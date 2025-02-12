#include "ng_client.h"
#include "media_socket.h"

struct endpoint_sockets {
	endpoint_t dst;
	socket_slist *sockets;
};

static void socket_free(socket_t *s) {
	close_socket(s);
	g_free(s);
}

static void endpoint_socket_free(struct endpoint_sockets *es) {
	t_slist_free_full(es->sockets, socket_free);
	g_free(es);
}

TYPED_GHASHTABLE(endpoint_socket_ht, endpoint_t, struct endpoint_sockets,
		endpoint_hash, endpoint_eq,
		NULL, endpoint_socket_free)


static endpoint_socket_ht ng_client_endpoints;
static rwlock_t ng_client_endpoints_lock;


void ng_client_init(void) {
	ng_client_endpoints = endpoint_socket_ht_new();
}

void ng_client_cleanup(void) {
	t_hash_table_destroy(ng_client_endpoints);
}


static struct endpoint_sockets *ng_client_get_entry(const endpoint_t *dst) {
	struct endpoint_sockets *es;

	// quick check for existing entry
	{
		RWLOCK_R(&ng_client_endpoints_lock);
		es = t_hash_table_lookup(ng_client_endpoints, dst);
	}

	if (es)
		return es;

	// we have to create one
	es = g_new0(__typeof(*es), 1);
	es->dst = *dst;

	RWLOCK_W(&ng_client_endpoints_lock);
	// ... but someone may have beaten us to it
	__auto_type es2 = t_hash_table_lookup(ng_client_endpoints, dst);
	if (es2) {
		// lost the race
		g_free(es);
		es = es2;
	}
	else
		t_hash_table_insert(ng_client_endpoints, &es->dst, es);

	return es;
}

static socket_slist *ng_client_get_socket(struct endpoint_sockets *es) {
	// see if we can grab a socket
	socket_slist *link = __atomic_load_n(&es->sockets, __ATOMIC_SEQ_CST);
	bool success = false;
	while (link && !success)
		success = __atomic_compare_exchange_n(&es->sockets, &link, link->next,
				false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);

	if (link) {
		link->next = NULL;
		return link;
	}

	// no socket available, we need to create one
	link = g_new0(socket_slist, 1);
	__auto_type sock = link->data = g_new0(socket_t, 1);
	if (!connect_socket(sock, SOCK_DGRAM, &es->dst)) {
		// oops...
		ilog(LOG_ERR, "Failed to create or connect socket to remote NG peer (%s): %s",
				endpoint_print_buf(&es->dst),
				strerror(errno));
		g_free(link->data);
		g_free(link);
		return NULL;
	}
	socket_getsockname(sock);
	interfaces_exclude_port(&sock->local);
	socket_rcvtimeout(sock, rtpe_config.ng_client_timeout);

	return link;
}

static void ng_client_put_socket(struct endpoint_sockets *es, socket_slist *link) {
	link->next = __atomic_load_n(&es->sockets, __ATOMIC_SEQ_CST);
	bool success;
	do
		success = __atomic_compare_exchange_n(&es->sockets, &link->next, link,
				false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
	while (!success);
}

bencode_item_t *ng_client_request(const endpoint_t *dst, const str *req, bencode_buffer_t *rbuf) {
	__auto_type es = ng_client_get_entry(dst);
	__auto_type link = ng_client_get_socket(es);
	if (!link)
		return NULL;

	__auto_type sock = link->data;

	// construct message
	char cookie[17];
	rand_hex_str(cookie, 8);
	cookie[16] = ' ';

	struct iovec iov[2] = {
		{
			.iov_base = cookie,
			.iov_len = sizeof(cookie),
		},
		{
			.iov_base = req->s,
			.iov_len = req->len,
		},
	};

	ilog(LOG_DEBUG, "Sending NG request to %s: '" STR_FORMAT "'",
			endpoint_print_buf(dst),
			STR_FMT(req));

	static const size_t buflen = 4096;
	char *buf = bencode_buffer_alloc(rbuf, buflen);
	ssize_t len = 0;

	for (unsigned int try = 0; try < rtpe_config.ng_client_retries; try++) {
		ilog(LOG_DEBUG, "Attempt #%u sending NG request", try + 1);

		ssize_t ret = socket_sendiov(sock, iov, G_N_ELEMENTS(iov), NULL, NULL);
		if (ret <= 0)
			goto err;

		// receive the response
		len = socket_recvfrom(sock, buf, buflen, NULL);
		if (len > 0)
			ilog(LOG_DEBUG, "Received response from NG peer (%s): '%.*s'",
					endpoint_print_buf(dst),
					(int) len, buf);
		if (len == buflen)
			ilog(LOG_WARN, "Possibly truncated response from remote NG peer (%s)",
					endpoint_print_buf(dst));
		if (len > sizeof(cookie) && memcmp(buf, cookie, sizeof(cookie)) == 0)
			break;

		if (len < 0)
			ilog(LOG_WARN, "Error reading from socket from remote NG peer (%s): %s",
					endpoint_print_buf(dst),
					strerror(errno));
		else if (len == 0)
			ilog(LOG_WARN, "EOF while reading from socket from remote NG peer (%s)",
					endpoint_print_buf(dst));
		else
			ilog(LOG_WARN, "Short packet or mismatched cookie while reading from socket "
					"from remote NG peer (%s)",
					endpoint_print_buf(dst));
	}

	if (len <= 0)
		goto err;

	ilog(LOG_DEBUG, "Received valid NG response: '%.*s'", (int) len, buf);

	bencode_item_t *ret = bencode_decode_expect(rbuf, buf + sizeof(cookie), len - sizeof(cookie),
			BENCODE_DICTIONARY);
	if (!ret) {
		errno = EIO;
		goto err;
	}

	ng_client_put_socket(es, link);
	return ret;

err:
	ilog(LOG_ERR, "Error communicating with remote NG peer (%s): %s",
			endpoint_print_buf(&sock->remote),
			strerror(errno));

	ng_client_put_socket(es, link);
	return NULL;
}
