#ifndef _NETFILTER_API_H
#define _NETFILTER_API_H

#include <glib.h>
#include <stdint.h>
#include <stdbool.h>


typedef struct nfapi_socket nfapi_socket;
typedef struct nfapi_buf nfapi_buf;

typedef struct {
	const char *(*rule)(const int8_t *, size_t, void *userdata);
	const char *(*chain)(const int8_t *, size_t, void *userdata);
	const char *(*expression)(const char *, const int8_t *, size_t, void *userdata);
	void (*handle)(int64_t, void *userdata);
	void (*comment)(const char *, void *userdata);
} nfapi_callbacks;


nfapi_socket *nfapi_socket_open(void);
void nfapi_socket_close(nfapi_socket *);


nfapi_buf *nfapi_buf_new(void);
void nfapi_buf_free(nfapi_buf *);

void nfapi_add_msg(nfapi_buf *, uint16_t type, uint16_t family, uint16_t flags);

void nfapi_add_attr(nfapi_buf *b, uint16_t type, const void *data, size_t len);


static inline void nfapi_add_str_attr(nfapi_buf *b, uint16_t type, const char *s) {
	nfapi_add_attr(b, type, s, strlen(s) + 1);
}
static inline void nfapi_add_u32_attr(nfapi_buf *b, uint16_t type, uint32_t u) {
	nfapi_add_attr(b, type, &u, sizeof(u));
}
static inline void nfapi_add_u64_attr(nfapi_buf *b, uint16_t type, uint64_t u) {
	nfapi_add_attr(b, type, &u, sizeof(u));
}

#define nfapi_add_binary_str_attr(b, type, s) \
	nfapi_add_attr(b, type, &(struct { \
			uint16_t len; \
			char buf[sizeof(s)]; \
		}) { \
			.len = htons(sizeof(s)), \
			.buf = s, \
		}, 2 + sizeof(s))


void nfapi_nested_begin(nfapi_buf *, uint16_t type);
void nfapi_nested_end(nfapi_buf *);

void nfapi_batch_begin(nfapi_buf *);
void nfapi_batch_end(nfapi_buf *);


bool nfapi_send_buf(nfapi_socket *, nfapi_buf *);

const char *nfapi_recv_iter(nfapi_socket *, const nfapi_callbacks *, void *userdata);

const char *nfapi_rule_iter(const int8_t *, size_t, const nfapi_callbacks *, void *userdata);

const char *nfapi_get_immediate_chain(const int8_t *, size_t);
const char *nfapi_get_target(const int8_t *, size_t, void *info, size_t *info_len);


G_DEFINE_AUTOPTR_CLEANUP_FUNC(nfapi_socket, nfapi_socket_close);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(nfapi_buf, nfapi_buf_free);


#endif
