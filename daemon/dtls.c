#include "dtls.h"

#include <stdio.h>
#include <string.h>
#include <glib.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <openssl/err.h>
#include <time.h>

#include "str.h"
#include "helpers.h"
#include "crypto.h"
#include "log.h"
#include "call.h"
#include "poller.h"
#include "ice.h"


#if OPENSSL_VERSION_NUMBER >= 0x10002000L
#define X509_getm_notBefore X509_get_notBefore
#define X509_getm_notAfter X509_get_notAfter
#endif


#define DTLS_DEBUG 0

#if DTLS_DEBUG
#define __DBG(x...) ilog(LOG_DEBUG, x)
#else
#define __DBG(x...) ilogs(internals, LOG_DEBUG, x)
#endif




#define CERT_EXPIRY_TIME (60*60*24*30) /* 30 days */

struct dtls_connection *dtls_ptr(stream_fd *sfd) {
	if (!sfd)
		return NULL;
	struct packet_stream *ps = sfd->stream;
	if (PS_ISSET(ps, ICE)) // ignore which sfd we were given
		return &ps->ice_dtls;
	return &sfd->dtls;
}





static char ciphers_str[1024];



static unsigned int sha_1_func(unsigned char *, X509 *);
static unsigned int sha_224_func(unsigned char *, X509 *);
static unsigned int sha_256_func(unsigned char *, X509 *);
static unsigned int sha_384_func(unsigned char *, X509 *);
static unsigned int sha_512_func(unsigned char *, X509 *);




static const struct dtls_hash_func hash_funcs[] = {
	{
		.name					= "sha-256",
		.num_bytes				= 256 / 8,
		.__func					= sha_256_func,
	},
	{
		.name					= "sha-1",
		.num_bytes				= 160 / 8,
		.__func					= sha_1_func,
	},
	{
		.name					= "sha-224",
		.num_bytes				= 224 / 8,
		.__func					= sha_224_func,
	},
	{
		.name					= "sha-384",
		.num_bytes				= 384 / 8,
		.__func					= sha_384_func,
	},
	{
		.name					= "sha-512",
		.num_bytes				= 512 / 8,
		.__func					= sha_512_func,
	},
};

const int num_hash_funcs = G_N_ELEMENTS(hash_funcs);



static struct dtls_cert *__dtls_cert;
static rwlock_t __dtls_cert_lock = RWLOCK_STATIC_INIT;



const struct dtls_hash_func *dtls_find_hash_func(const str *s) {
	int i;
	const struct dtls_hash_func *hf;

	for (i = 0; i < num_hash_funcs; i++) {
		hf = &hash_funcs[i];
		if (strlen(hf->name) != s->len)
			continue;
		if (!strncasecmp(s->s, hf->name, s->len))
			return hf;
	}

	return NULL;
}

static void cert_free(struct dtls_cert *cert) {
	if (cert->pkey)
		EVP_PKEY_free(cert->pkey);
	if (cert->x509)
		X509_free(cert->x509);
	g_queue_clear_full(&cert->fingerprints, free);
}

static void buf_dump_free(char *buf, size_t len) {
	char *p, *f;
	int llen;

	p = buf;
	while (len) {
		f = memchr(p, '\n', len);
		if (f)
			llen = f - p;
		else
			llen = len;

		ilogs(srtp, LOG_DEBUG, "--- %.*s", llen, p);

		if (!f)
			break;
		len -= llen + 1;
		p = f + 1;
	}

	free(buf);
}

static void dump_cert(struct dtls_cert *cert) {
	FILE *fp;
	char *buf;
	size_t len;

	if (get_log_level(core) < LOG_DEBUG)
		return;

	/* cert */
	fp = open_memstream(&buf, &len);
	if (!fp) {
		ilogs(crypto, LOG_ERROR, "Failed to allocate memory to dump DTLS certificate");
		return;
	}
	PEM_write_X509(fp, cert->x509);
	fclose(fp);

	ilogs(srtp, LOG_DEBUG, "Dump of DTLS certificate:");
	buf_dump_free(buf, len);

	/* key */
	fp = open_memstream(&buf, &len);
	if (!fp) {
		ilogs(crypto, LOG_ERROR, "Failed to allocate memory to dump DTLS private key");
		return;
	}
	PEM_write_PrivateKey(fp, cert->pkey, NULL, NULL, 0, 0, NULL);
	fclose(fp);

	ilogs(srtp, LOG_DEBUG, "Dump of DTLS private key:");
	buf_dump_free(buf, len);
}

static int cert_init(void) {
	X509 *x509 = NULL;
	EVP_PKEY *pkey = NULL;
	BIGNUM *serial_number = NULL;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	RSA *rsa = NULL;
	EC_KEY *ec_key = NULL;
	BIGNUM *exponent = NULL;
#endif
	ASN1_INTEGER *asn1_serial_number;
	X509_NAME *name;
	struct dtls_cert *new_cert;

	ilogs(crypto, LOG_INFO, "Generating new DTLS certificate");

	/* objects */

	serial_number = BN_new();
	name = X509_NAME_new();
	x509 = X509_new();
	if (!serial_number || !name || !x509)
		goto err;

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	pkey = EVP_PKEY_new();
	if (!pkey)
		goto err;
#endif

	/* key */

	if (rtpe_config.dtls_cert_cipher == DCC_RSA) {
		ilogs(crypto, LOG_DEBUG, "Using %i-bit RSA key for DTLS certificate",
				rtpe_config.dtls_rsa_key_size);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
		pkey = EVP_RSA_gen(rtpe_config.dtls_rsa_key_size);
#else // <3.0
		exponent = BN_new();
		rsa = RSA_new();
		if (!exponent || !rsa)
			goto err;

		if (!BN_set_word(exponent, 0x10001))
			goto err;

		if (!RSA_generate_key_ex(rsa, rtpe_config.dtls_rsa_key_size, exponent, NULL))
			goto err;

		if (!EVP_PKEY_assign_RSA(pkey, rsa))
			goto err;
		rsa = NULL;
#endif

	}
	else if (rtpe_config.dtls_cert_cipher == DCC_EC_PRIME256v1) {
		ilogs(crypto, LOG_DEBUG, "Using EC-prime256v1 key for DTLS certificate");

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
		pkey = EVP_EC_gen("prime256v1");
#else
		ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

		if (!ec_key)
			goto err;

		if (!EC_KEY_generate_key(ec_key))
			goto err;

		if (!EVP_PKEY_assign_EC_KEY(pkey, ec_key))
			goto err;
		ec_key = NULL;
#endif
	}
	else
		abort();

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	if (!pkey)
		goto err;
#endif
	/* x509 cert */

	if (!X509_set_pubkey(x509, pkey))
		goto err;

	/* serial */

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	if (!BN_pseudo_rand(serial_number, 64, 0, 0))
		goto err;
#else
	if (!BN_rand(serial_number, 64, 0, 0))
		goto err;
#endif

	asn1_serial_number = X509_get_serialNumber(x509);
	if (!asn1_serial_number)
		goto err;

	if (!BN_to_ASN1_INTEGER(serial_number, asn1_serial_number))
		goto err;

	/* version 1 */

	if (!X509_set_version(x509, 0L))
		goto err;

	/* common name */

	const char *cn = rtpe_config.software_id ?: "rtpengine";
	size_t cn_len = MIN(strlen(cn), 63);
	if (!X509_NAME_add_entry_by_NID(name, NID_commonName, MBSTRING_UTF8,
				(unsigned char *) cn, cn_len, -1, 0))
		goto err;

	if (!X509_set_subject_name(x509, name))
		goto err;

	if (!X509_set_issuer_name(x509, name))
		goto err;

	/* cert lifetime */

	if (!X509_gmtime_adj(X509_getm_notBefore(x509), -60*60*24))
		goto err;

	if (!X509_gmtime_adj(X509_getm_notAfter(x509), CERT_EXPIRY_TIME))
		goto err;

	/* sign it */

	if (!X509_sign(x509, pkey, rtpe_config.dtls_signature == DSIG_SHA1 ? EVP_sha1() : EVP_sha256()))
		goto err;

	/* digest */

	new_cert = obj_alloc0(struct dtls_cert, cert_free);

	for (int i = 0; i < num_hash_funcs; i++) {
		struct dtls_fingerprint *fp = malloc(sizeof(*fp));
		fp->hash_func = &hash_funcs[i];
		dtls_fingerprint_hash(fp, x509);
		g_queue_push_tail(&new_cert->fingerprints, fp);
	}

	new_cert->x509 = x509;
	new_cert->pkey = pkey;
	new_cert->expires = time(NULL) + CERT_EXPIRY_TIME;

	dump_cert(new_cert);

	/* swap out certs */

	rwlock_lock_w(&__dtls_cert_lock);

	if (__dtls_cert)
		obj_put(__dtls_cert);
	__dtls_cert = new_cert;

	rwlock_unlock_w(&__dtls_cert_lock);

	/* cleanup */

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	BN_free(exponent);
#endif
	BN_free(serial_number);
	X509_NAME_free(name);

	return 0;

err:
	ilogs(crypto, LOG_ERROR, "Failed to generate DTLS certificate");

	if (pkey)
		EVP_PKEY_free(pkey);
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	if (exponent)
		BN_free(exponent);
	if (rsa)
		RSA_free(rsa);
	if (ec_key)
		EC_KEY_free(ec_key);
#endif
	if (x509)
		X509_free(x509);
	if (serial_number)
		BN_free(serial_number);

	return -1;
}

int dtls_init(void) {
	int i;
	char *p;

	if (cert_init())
		return -1;

	p = ciphers_str;
	for (i = 0; i < num_crypto_suites; i++) {
		if (!crypto_suites[i].dtls_name)
			continue;

		p += sprintf(p, "%s:", crypto_suites[i].dtls_name);
	}

	assert(p != ciphers_str);
	assert(p - ciphers_str < sizeof(ciphers_str));

	p[-1] = '\0';

	return 0;
}

static enum thread_looper_action __dtls_timer(void) {
	struct dtls_cert *c;
	long int left;

	c = dtls_cert();
	if (!c)
		return TLA_BREAK;

	left = c->expires - rtpe_now.tv_sec;
	if (left > CERT_EXPIRY_TIME/2)
		goto out;

	cert_init();

out:
	obj_put(c);
	return TLA_CONTINUE;
}

void dtls_timer(void) {
	thread_create_looper(__dtls_timer, rtpe_config.idle_scheduling,
			rtpe_config.idle_priority, "DTLS refresh",
			((long long) CERT_EXPIRY_TIME / 7) * 1000000);
}

static unsigned int generic_func(unsigned char *o, X509 *x, const EVP_MD *md) {
	unsigned int n;
	assert(md != NULL);
	X509_digest(x, md, o, &n);
	return n;
}

static unsigned int sha_1_func(unsigned char *o, X509 *x) {
	const EVP_MD *md;
	md = EVP_sha1();
	return generic_func(o, x, md);
}
static unsigned int sha_224_func(unsigned char *o, X509 *x) {
	const EVP_MD *md;
	md = EVP_sha224();
	return generic_func(o, x, md);
}
static unsigned int sha_256_func(unsigned char *o, X509 *x) {
	const EVP_MD *md;
	md = EVP_sha256();
	return generic_func(o, x, md);
}
static unsigned int sha_384_func(unsigned char *o, X509 *x) {
	const EVP_MD *md;
	md = EVP_sha384();
	return generic_func(o, x, md);
}
static unsigned int sha_512_func(unsigned char *o, X509 *x) {
	const EVP_MD *md;
	md = EVP_sha512();
	return generic_func(o, x, md);
}


struct dtls_cert *dtls_cert(void) {
	struct dtls_cert *ret;

	rwlock_lock_r(&__dtls_cert_lock);
	ret = __dtls_cert ? obj_get(__dtls_cert) : NULL;
	rwlock_unlock_r(&__dtls_cert_lock);

	return ret;
}

void dtls_cert_free(void) {
	rwlock_lock_w(&__dtls_cert_lock);

	if (__dtls_cert)
		obj_put(__dtls_cert);

	__dtls_cert = NULL;

	rwlock_unlock_w(&__dtls_cert_lock);

	return ;
}

static int verify_callback(int ok, X509_STORE_CTX *store) {
	SSL *ssl;
	struct dtls_connection *d;
	struct packet_stream *ps;
	struct call_media *media;

	ssl = X509_STORE_CTX_get_ex_data(store, SSL_get_ex_data_X509_STORE_CTX_idx());
	d = SSL_get_app_data(ssl);
	if (d->ssl != ssl)
		return 0;
	ps = d->ptr;
	if (!ps)
		return 0;
	if (PS_ISSET(ps, FINGERPRINT_VERIFIED))
		return 1;
	media = ps->media;
	if (!media)
		return 0;

	if (ps->dtls_cert)
		X509_free(ps->dtls_cert);
	ps->dtls_cert = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x10100010L
	X509 *cert = X509_STORE_CTX_get0_cert(store);
	if (!cert)
		cert = X509_STORE_CTX_get_current_cert(store);
#else
	X509 *cert = X509_STORE_CTX_get_current_cert(store);
#endif
	if (!cert)
		return 0;
	ps->dtls_cert = X509_dup(cert);

	if (!media->fingerprint.hash_func || !media->fingerprint.digest_len)
		return 1; /* delay verification */

	if (dtls_verify_cert(ps))
		return 0;
	return 1;
}

int dtls_verify_cert(struct packet_stream *ps) {
	unsigned char fp[DTLS_MAX_DIGEST_LEN];
	struct call_media *media;

	media = ps->media;
	if (!media)
		return -1;
	if (!ps->dtls_cert)
		return -1;

	dtls_hash(media->fingerprint.hash_func, ps->dtls_cert, fp);

	if (memcmp(media->fingerprint.digest, fp, media->fingerprint.hash_func->num_bytes)) {
		ilogs(crypto, LOG_WARNING, "DTLS: Peer certificate rejected - fingerprint mismatch");
		__DBG("fingerprint expected: %02x%02x%02x%02x%02x%02x%02x%02x received: %02x%02x%02x%02x%02x%02x%02x%02x",
			media->fingerprint.digest[0], media->fingerprint.digest[1],
			media->fingerprint.digest[2], media->fingerprint.digest[3],
			media->fingerprint.digest[4], media->fingerprint.digest[5],
			media->fingerprint.digest[6], media->fingerprint.digest[7], 
			fp[0], fp[1], fp[2], fp[3],
			fp[4], fp[5], fp[6], fp[7]);
		return -1;
	}

	PS_SET(ps, FINGERPRINT_VERIFIED);
	ilogs(crypto, LOG_INFO, "DTLS: Peer certificate accepted");

	return 0;
}

static int try_connect(struct dtls_connection *d) {
	int ret, code;
	unsigned char buf[0x10000];

	__DBG("try_connect(%u)", d->active);

	if (d->connected)
		ret = SSL_read(d->ssl, buf, sizeof(buf)); /* retransmission after connected - handshake lost */
	else if (d->active)
		ret = SSL_connect(d->ssl);
	else
		ret = SSL_accept(d->ssl);

	code = SSL_get_error(d->ssl, ret);

	ret = 0;
	switch (code) {
		case SSL_ERROR_NONE:
			if (d->connected) {
				ilogs(crypto, LOG_INFO, "DTLS data received after handshake, code: %i", code);
			} else {
				ilogs(crypto, LOG_DEBUG, "DTLS handshake successful");
				d->connected = 1;
				ret = 1;
			}
			break;

		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
			if (d->connected) {
				ilogs(crypto, LOG_INFO, "DTLS data received after handshake, code: %i", code);
			}
			break;
                case SSL_ERROR_ZERO_RETURN:
			if (d->connected) {
				ilogs(crypto, LOG_INFO, "DTLS peer has closed the connection");
				ret = -2;
			}
			break;

		default:
			ret = ERR_peek_last_error();
			ilogs(crypto, LOG_ERROR, "DTLS error: %i (%s)", code, ERR_reason_error_string(ret));
			ret = -1;
			break;
	}

	return ret;
}

static long dtls_bio_callback(BIO *bio, int oper, const char *argp, size_t len, int argi, long argl,
		int ret, size_t *proc)
{
	if (oper == (BIO_CB_CTRL | BIO_CB_RETURN)) {
		if (argi == BIO_CTRL_DGRAM_QUERY_MTU)
			return rtpe_config.dtls_mtu; // this is with overhead already subtracted
		if (argi == BIO_CTRL_DGRAM_GET_MTU_OVERHEAD)
			return DTLS_MTU_OVERHEAD;
		return ret;
	}

	if (oper != BIO_CB_WRITE)
		return ret;
	if (!argp || len <= 0)
		return ret;

	struct packet_stream *ps = (struct packet_stream *) BIO_get_callback_arg(bio);
	if (!ps)
		return ret;
	struct stream_fd *sfd = ps->selected_sfd;
	if (!sfd)
		return ret;
	struct dtls_connection *d = dtls_ptr(sfd);
	if (!d)
		return ret;

	__DBG("dtls packet output: len %zu %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
		len,
		argp[0], argp[1], argp[2], argp[3],
		argp[4], argp[5], argp[6], argp[7],
		argp[8], argp[9], argp[10], argp[11],
		argp[12], argp[13], argp[14], argp[15]);

	const endpoint_t *fsin = &ps->endpoint;
	if (fsin->port == 9 || fsin->address.family == NULL)
		return ret;

	ilogs(srtp, LOG_DEBUG, "Sending DTLS packet");
	socket_sendto(&sfd->socket, argp, len, fsin);
	atomic64_inc_na(&ps->stats_out->packets);
	atomic64_add_na(&ps->stats_out->bytes, len);

	return ret;
}

int dtls_connection_init(struct dtls_connection *d, struct packet_stream *ps, int active,
		struct dtls_cert *cert)
{
	if (!cert) {
		ilogs(crypto, LOG_ERR, "Cannot establish DTLS: no certificate available");
		return -1;
	}

	unsigned long err;

	if (d->init) {
		if ((d->active && active) || (!d->active && !active))
			goto done;
		dtls_connection_cleanup(d);
	}

	d->ptr = ps;

	ilogs(crypto, LOG_DEBUG, "Creating %s DTLS connection context", active ? "active" : "passive");

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
	d->ssl_ctx = SSL_CTX_new(active ? DTLS_client_method() : DTLS_server_method());
#else
	d->ssl_ctx = SSL_CTX_new(active ? DTLSv1_client_method() : DTLSv1_server_method());
#endif
	if (!d->ssl_ctx)
		goto error;

	if (SSL_CTX_use_certificate(d->ssl_ctx, cert->x509) != 1)
		goto error;
	if (SSL_CTX_use_PrivateKey(d->ssl_ctx, cert->pkey) != 1)
		goto error;

	SSL_CTX_set_verify(d->ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
			verify_callback);
	SSL_CTX_set_verify_depth(d->ssl_ctx, 4);
	SSL_CTX_set_cipher_list(d->ssl_ctx, rtpe_config.dtls_ciphers);

	if (SSL_CTX_set_tlsext_use_srtp(d->ssl_ctx, ciphers_str))
		goto error;
	if (SSL_CTX_set_read_ahead(d->ssl_ctx, 1))
		goto error;

	d->ssl = SSL_new(d->ssl_ctx);
	if (!d->ssl)
		goto error;

	d->r_bio = BIO_new(BIO_s_mem());
	d->w_bio = BIO_new(BIO_s_mem());
	if (!d->r_bio || !d->w_bio)
		goto error;

	BIO_set_callback_ex(d->w_bio, dtls_bio_callback);
	BIO_set_callback_arg(d->w_bio, (char *) ps);

#if defined(BIO_CTRL_DGRAM_SET_MTU)
	BIO_ctrl(d->w_bio, BIO_CTRL_DGRAM_SET_MTU, rtpe_config.dtls_mtu, NULL);
	BIO_ctrl(d->r_bio, BIO_CTRL_DGRAM_SET_MTU, rtpe_config.dtls_mtu, NULL);
#endif

	SSL_set_app_data(d->ssl, d);
	SSL_set_bio(d->ssl, d->r_bio, d->w_bio);
	d->init = 1;
	SSL_set_mode(d->ssl, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);


        /* SSL_set1_groups_list et al. is not
         * necessary for OpenSSL >= 1.1.1 as it has sensible defaults
         * minimally P-521:P-384:P-256
         */
#if OPENSSL_VERSION_NUMBER < 0x10101000L
	EC_KEY* ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if (ecdh == NULL)
		goto error;
	SSL_set_options(d->ssl, SSL_OP_SINGLE_ECDH_USE);
	SSL_set_tmp_ecdh(d->ssl, ecdh);
	EC_KEY_free(ecdh);
#endif

#if defined(SSL_OP_NO_QUERY_MTU)
	SSL_CTX_set_options(d->ssl_ctx, SSL_OP_NO_QUERY_MTU);
	SSL_set_mtu(d->ssl, rtpe_config.dtls_mtu);
#if defined(DTLS_set_link_mtu) || defined(DTLS_CTRL_SET_LINK_MTU) || OPENSSL_VERSION_NUMBER >= 0x10100000L
	DTLS_set_link_mtu(d->ssl, rtpe_config.dtls_mtu);
#endif
#endif

	d->active = active ? 1 : 0;

	random_string(d->tls_id, sizeof(d->tls_id));

done:
	return 0;

error:
	err = ERR_peek_last_error();
	if (!d->init) {
		if (d->r_bio)
			BIO_free(d->r_bio);
		if (d->w_bio)
			BIO_free(d->w_bio);
	}
	if (d->ssl)
		SSL_free(d->ssl);
	if (d->ssl_ctx)
		SSL_CTX_free(d->ssl_ctx);
	ZERO(*d);
	ilogs(crypto, LOG_ERROR, "Failed to init DTLS connection: %s", ERR_reason_error_string(err));
	return -1;
}

static int dtls_setup_crypto(struct packet_stream *ps, struct dtls_connection *d) {
	const char *err;
	SRTP_PROTECTION_PROFILE *spp;
	int i;
	const struct crypto_suite *cs;
	unsigned char keys[2 * (SRTP_MAX_MASTER_KEY_LEN + SRTP_MAX_MASTER_SALT_LEN)];
	struct crypto_params client, server;

	err = "no SRTP protection profile negotiated";
	spp = SSL_get_selected_srtp_profile(d->ssl);
	if (!spp)
		goto error;

	for (i = 0; i < num_crypto_suites; i++) {
		cs = &crypto_suites[i];
		if (!cs->dtls_name)
			continue;
		if (!strcmp(cs->dtls_name, spp->name))
			goto found;
	}

	err = "unknown SRTP protection profile negotiated";
	goto error;

found:
	i = SSL_export_keying_material(d->ssl, keys, sizeof(keys), "EXTRACTOR-dtls_srtp",
			strlen("EXTRACTOR-dtls_srtp"), NULL, 0, 0);
	err = "failed to export keying material";
	if (i != 1)
		goto error;

	/* got everything XXX except MKI */
	ZERO(client);
	ZERO(server);
	i = 0;

	client.crypto_suite = server.crypto_suite = cs;

	memcpy(client.master_key, &keys[i], cs->master_key_len);
	i += cs->master_key_len;
	memcpy(server.master_key, &keys[i], cs->master_key_len);
	i += cs->master_key_len;
	memcpy(client.master_salt, &keys[i], cs->master_salt_len);
	i += cs->master_salt_len;
	memcpy(server.master_salt, &keys[i], cs->master_salt_len);

	ilogs(crypto, LOG_INFO, "DTLS-SRTP successfully negotiated using %s", cs->name);

	if (d->active) {
		/* we're the client */
		crypto_init(&ps->crypto, &client);
		if (ps->selected_sfd)
			crypto_init(&ps->selected_sfd->crypto, &server);
	}
	else {
		/* we're the server */
		crypto_init(&ps->crypto, &server);
		if (ps->selected_sfd)
			crypto_init(&ps->selected_sfd->crypto, &client);
	}
	// it's possible that ps->selected_sfd is not from ps->sfds list (?)
	for (__auto_type l = ps->sfds.head; l; l = l->next) {
		stream_fd *sfd = l->data;
		if (d->active) /* we're the client */
			crypto_init(&sfd->crypto, &server);
		else /* we're the server */
			crypto_init(&sfd->crypto, &client);
	}

	if (ps->selected_sfd)
		crypto_dump_keys(&ps->crypto, &ps->selected_sfd->crypto);

	return 0;

error:
	if (!spp)
		ilogs(crypto, LOG_ERROR, "Failed to set up SRTP after DTLS negotiation: %s", err);
	else
		ilogs(crypto, LOG_ERROR, "Failed to set up SRTP after DTLS negotiation: %s (profile \"%s\")",
				err, spp->name);
	return -1;
}

/* called with call locked in W or R with ps->in_lock held */
int dtls(stream_fd *sfd, const str *s, const endpoint_t *fsin) {
	struct packet_stream *ps = sfd->stream;
	int ret;

	if (!ps)
		return 0;
	if (!MEDIA_ISSET(ps->media, DTLS))
		return 0;
	struct dtls_connection *d = dtls_ptr(sfd);
	if (!d)
		return 0;

	if (s)
		__DBG("dtls packet input: len %zu %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
			s->len,
			(unsigned char) s->s[0], (unsigned char) s->s[1], (unsigned char) s->s[2], (unsigned char) s->s[3],
			(unsigned char) s->s[4], (unsigned char) s->s[5], (unsigned char) s->s[6], (unsigned char) s->s[7],
			(unsigned char) s->s[8], (unsigned char) s->s[9], (unsigned char) s->s[10], (unsigned char) s->s[11],
			(unsigned char) s->s[12], (unsigned char) s->s[13], (unsigned char) s->s[14], (unsigned char) s->s[15]);

	if (!d->init || !d->ssl)
		return -1;

	if (s) {
		ilogs(srtp, LOG_DEBUG, "Processing incoming DTLS packet");
		BIO_write(d->r_bio, s->s, s->len);
		/* we understand this as preference of DTLS over SDES */
		MEDIA_CLEAR(ps->media, SDES);
	}

	int dret = 0;

	ret = try_connect(d);
	if (ret == -1) {
		ilogs(srtp, LOG_ERROR, "DTLS error on local port %u", sfd->socket.local.port);
		/* fatal error */
		dtls_connection_cleanup(d);
		return 0;
	}
	if (ret == -2) {
		/* peer close connection */
		dtls_connection_cleanup(d);
		return 0;
	}
	else if (ret == 1) {
		/* connected! */
		dret = 1;
		mutex_lock(&ps->out_lock); // nested lock!
		if (dtls_setup_crypto(ps, d))
			{} /* XXX ?? */
		mutex_unlock(&ps->out_lock);

		if (PS_ISSET(ps, RTP) && PS_ISSET(ps, RTCP) && ps->rtcp_sibling
				&& MEDIA_ISSET(ps->media, RTCP_MUX)
				&& ps->rtcp_sibling != ps)
		{
			// nested locks!
			mutex_lock(&ps->rtcp_sibling->in_lock);
			mutex_lock(&ps->rtcp_sibling->out_lock);
			if (dtls_setup_crypto(ps->rtcp_sibling, d))
				{} /* XXX ?? */
			mutex_unlock(&ps->rtcp_sibling->out_lock);
			mutex_unlock(&ps->rtcp_sibling->in_lock);
		}
	}

	return dret;
}

/* call must be locked */
void dtls_shutdown(struct packet_stream *ps) {
	if (!ps)
		return;

	__DBG("dtls_shutdown");

	bool had_dtls = false;

	if (ps->ice_dtls.init) {
		if (ps->ice_dtls.connected && ps->ice_dtls.ssl) {
			had_dtls = true;
			SSL_shutdown(ps->ice_dtls.ssl);
		}
		dtls_connection_cleanup(&ps->ice_dtls);
	}
	for (__auto_type l = ps->sfds.head; l; l = l->next) {
		stream_fd *sfd = l->data;

		struct dtls_connection *d = &sfd->dtls;
		if (!d->init)
			continue;

		if (d->connected && d->ssl) {
			had_dtls = true;
			SSL_shutdown(d->ssl);
			dtls(sfd, NULL, &ps->endpoint);
		}

		dtls_connection_cleanup(d);
	}

	if (ps->dtls_cert) {
		X509_free(ps->dtls_cert);
		ps->dtls_cert = NULL;
	}

	if (had_dtls)
		ilogs(crypto, LOG_DEBUG, "Reuse SRTP crypto key");
}

void dtls_connection_cleanup(struct dtls_connection *c) {
	if (c->ssl_ctx || c->ssl)
		ilogs(crypto, LOG_DEBUG, "Resetting DTLS connection context");

	if (c->ssl_ctx)
		SSL_CTX_free(c->ssl_ctx);
	if (c->ssl)
		SSL_free(c->ssl);
	if (!c->init) {
		if (c->r_bio)
			BIO_free(c->r_bio);
		if (c->w_bio)
			BIO_free(c->w_bio);
	}
	ZERO(*c);
}
