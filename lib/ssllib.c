#include "ssllib.h"
#include <openssl/ssl.h>
#include <time.h>
#include "auxlib.h"
#include "log.h"



#if OPENSSL_VERSION_NUMBER >= 0x30000000L
EVP_MAC_CTX *rtpe_hmac_sha1_base;
#endif


#if OPENSSL_VERSION_NUMBER < 0x10100000L
static mutex_t *openssl_locks;

static void cb_openssl_threadid(CRYPTO_THREADID *tid) {
	pthread_t me;

	me = pthread_self();

	if (sizeof(me) == sizeof(void *))
		CRYPTO_THREADID_set_pointer(tid, (void *) me);
	else
		CRYPTO_THREADID_set_numeric(tid, (unsigned long) me);
}

static void cb_openssl_lock(int mode, int type, const char *file, int line) {
	if ((mode & CRYPTO_LOCK))
		mutex_lock(&openssl_locks[type]);
	else
		mutex_unlock(&openssl_locks[type]);
}

static void make_OpenSSL_thread_safe(void) {
	int i;

	openssl_locks = malloc(sizeof(*openssl_locks) * CRYPTO_num_locks());
	for (i = 0; i < CRYPTO_num_locks(); i++)
		mutex_init(&openssl_locks[i]);

	CRYPTO_THREADID_set_callback(cb_openssl_threadid);
	CRYPTO_set_locking_callback(cb_openssl_lock);
}
#endif


void rtpe_ssl_init(void) {
	ilog(LOG_INFO,"compile-time OpenSSL library: %s\n", OPENSSL_VERSION_TEXT);
	ilog(LOG_INFO,"run-time OpenSSL library: %s\n", OpenSSL_version(OPENSSL_VERSION));

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
	SSL_library_init();
	SSL_load_error_strings();
	make_OpenSSL_thread_safe();
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	if(EVP_default_properties_is_fips_enabled(NULL) == 1) {
		ilog(LOG_INFO,"FIPS mode enabled in OpenSSL library\n");
	} else  {
		ilog(LOG_DEBUG,"FIPS mode not enabled in OpenSSL library\n");
	}

	EVP_MAC *rtpe_evp_hmac = EVP_MAC_fetch(NULL, "hmac", NULL);
	assert(rtpe_evp_hmac != NULL);

	rtpe_hmac_sha1_base = EVP_MAC_CTX_new(rtpe_evp_hmac);
	assert(rtpe_hmac_sha1_base != NULL);
	static const OSSL_PARAM params[2] = {
		OSSL_PARAM_utf8_string("digest", "sha-1", 5),
		OSSL_PARAM_END,
	};
	EVP_MAC_CTX_set_params(rtpe_hmac_sha1_base, params);
#endif
}
