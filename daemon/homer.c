#include "homer.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <glib.h>
#include <sys/time.h>

#include "log.h"
#include "aux.h"
#include "str.h"




#define SEND_QUEUE_LIMIT 200




struct homer_sender {
	mutex_t		lock;

	endpoint_t	endpoint;
	int		protocol;
	int		capture_id;
	socket_t	socket;
	time_t		retry;

	GQueue		send_queue;
	GString		*partial;

	int		(*state)(struct homer_sender *);
};



static struct homer_sender *main_homer_sender;




static int send_hepv3 (GString *s, const str *id, int, const endpoint_t *src, const endpoint_t *dst,
		const struct timeval *);

// state handlers
static int __established(struct homer_sender *hs);
static int __in_progress(struct homer_sender *hs);
static int __no_socket(struct homer_sender *hs);




static void __reset(struct homer_sender *hs) {
	close_socket(&hs->socket);
	hs->state = __no_socket;
	hs->retry = time(NULL) + 30;

	// discard partially written packet
	if (hs->partial)
		g_string_free(hs->partial, TRUE);
	hs->partial = NULL;
}

static int __attempt_send(struct homer_sender *hs, GString *gs) {
	int ret;

	ret = write(hs->socket.fd, gs->str, gs->len);
	if (ret == gs->len) {
		// full write
		g_string_free(gs, TRUE);
		return 0;
	}
	if (ret < 0) {
		if (errno != EWOULDBLOCK && errno != EAGAIN) {
			ilog(LOG_ERR, "Write error to Homer at %s: %s",
					endpoint_print_buf(&hs->endpoint), strerror(errno));
			__reset(hs);
			return 1;
		}
		ilog(LOG_DEBUG, "Home write blocked");
		// XXX use poller for blocked writes?
		return 2;
	}
	// partial write
	ilog(LOG_DEBUG, "Home write blocked (partial write)");
	g_string_erase(gs, 0, ret);
	return 3;
}

static int __established(struct homer_sender *hs) {
	char buf[16];
	int ret;
	GString *gs;

	// test connection with a dummy read
	ret = read(hs->socket.fd, buf, sizeof(buf));
	if (ret < 0) {
		if (errno != EWOULDBLOCK && errno != EAGAIN) {
			ilog(LOG_ERR, "Connection error from Homer at %s: %s",
					endpoint_print_buf(&hs->endpoint), strerror(errno));
			__reset(hs);
			return -1;
		}
	}
	// XXX handle return data from Homer?

	if (hs->partial) {
		ilog(LOG_DEBUG, "dequeue partial packet to Homer");
		ret = __attempt_send(hs, hs->partial);
		if (ret == 3 || ret == 2) // partial write or not sent at all
			return 0;
		if (ret == 1) // write error, takes care of deleting hs->partial
			return -1;
		// ret == 0 -> sent OK, drop through to unqueue
		g_string_free(hs->partial, TRUE);
		hs->partial = NULL;
	}

	// unqueue as much as we can
	while ((gs = g_queue_pop_head(&hs->send_queue))) {
		ilog(LOG_DEBUG, "dequeue send queue to Homer");
		ret = __attempt_send(hs, gs);
		if (ret == 0) // everything sent OK
			continue;
		if (ret == 3) { // partial write
			hs->partial = gs;
			return 0;
		}
		g_queue_push_head(&hs->send_queue, gs);
		if (ret == 1) // write error
			return -1;
		// ret == 2 -> blocked
		return 0;
	}

	// everything unqueued
	return 0;
}

static int __check_conn(struct homer_sender *hs, int ret) {
	if (ret == 0) {
		ilog(LOG_INFO, "Connection to Homer at %s has been established",
				endpoint_print_buf(&hs->endpoint));
		hs->state = __established;
		return hs->state(hs);
	}
	if (ret == 1) {
		ilog(LOG_DEBUG, "connection to Homer is in progress");
		hs->state = __in_progress;
		return 0;
	}

	ilog(LOG_ERR, "Failed to connect to Homer at %s: %s",
			endpoint_print_buf(&hs->endpoint), strerror(errno));

	__reset(hs);
	return -1;
}

static int __in_progress(struct homer_sender *hs) {
	int ret;

	ilog(LOG_DEBUG, "connection to Homer is in progress - checking");

	ret = connect_socket_retry(&hs->socket);
	return __check_conn(hs, ret);
}

static int __no_socket(struct homer_sender *hs) {
	int ret;

	if (hs->retry > time(NULL))
		return 0;

	ilog(LOG_INFO, "Connecting to Homer at %s", endpoint_print_buf(&hs->endpoint));

	ret = connect_socket_nb(&hs->socket, hs->protocol, &hs->endpoint);
	return __check_conn(hs, ret);
}

void homer_sender_init(const endpoint_t *ep, int protocol, int capture_id) {
	struct homer_sender *ret;

	if (is_addr_unspecified(&ep->address))
		return;
	if (main_homer_sender)
		return;

	ret = malloc(sizeof(*ret));
	ZERO(*ret);
	mutex_init(&ret->lock);
	ret->endpoint = *ep;
	ret->protocol = protocol;
	ret->capture_id = capture_id;
	ret->retry = time(NULL);

	ret->state = __no_socket;

	main_homer_sender = ret;

	return;
}

// takes over the GString
int homer_send(GString *s, const str *id, const endpoint_t *src,
		const endpoint_t *dst, const struct timeval *tv)
{
	if (!main_homer_sender)
		goto out;
	if (!s)
		goto out;
	if (!s->len) // empty write, shouldn't happen
		goto out;

	ilog(LOG_DEBUG, "JSON to send to Homer: '"STR_FORMAT"'", G_STR_FMT(s));

	if (send_hepv3(s, id, main_homer_sender->capture_id, src, dst, tv))
		goto out;

	mutex_lock(&main_homer_sender->lock);
	if (main_homer_sender->send_queue.length < SEND_QUEUE_LIMIT) {
		g_queue_push_tail(&main_homer_sender->send_queue, s);
		s = NULL;
	}
	else
		ilog(LOG_ERR, "Send queue length limit (%i) reached, dropping Homer message", SEND_QUEUE_LIMIT);
	main_homer_sender->state(main_homer_sender);
	mutex_unlock(&main_homer_sender->lock);

out:
	if (s)
		g_string_free(s, TRUE);
	return 0;
}




// from captagent transport_hep.[ch]

struct hep_chunk {
       u_int16_t vendor_id;
       u_int16_t type_id;
       u_int16_t length;
} __attribute__((packed));

typedef struct hep_chunk hep_chunk_t;

struct hep_chunk_uint8 {
       hep_chunk_t chunk;
       u_int8_t data;
} __attribute__((packed));

typedef struct hep_chunk_uint8 hep_chunk_uint8_t;

struct hep_chunk_uint16 {
       hep_chunk_t chunk;
       u_int16_t data;
} __attribute__((packed));

typedef struct hep_chunk_uint16 hep_chunk_uint16_t;

struct hep_chunk_uint32 {
       hep_chunk_t chunk;
       u_int32_t data;
} __attribute__((packed));

typedef struct hep_chunk_uint32 hep_chunk_uint32_t;

struct hep_chunk_str {
       hep_chunk_t chunk;
       char *data;
} __attribute__((packed));

typedef struct hep_chunk_str hep_chunk_str_t;

struct hep_chunk_ip4 {
       hep_chunk_t chunk;
       struct in_addr data;
} __attribute__((packed));

typedef struct hep_chunk_ip4 hep_chunk_ip4_t;

struct hep_chunk_ip6 {
       hep_chunk_t chunk;
       struct in6_addr data;
} __attribute__((packed));

typedef struct hep_chunk_ip6 hep_chunk_ip6_t;

struct hep_ctrl {
    char id[4];
    u_int16_t length;
} __attribute__((packed));

typedef struct hep_ctrl hep_ctrl_t;

struct hep_chunk_payload {
    hep_chunk_t chunk;
    char *data;
} __attribute__((packed));

typedef struct hep_chunk_payload hep_chunk_payload_t;

/* Structure of HEP */

struct hep_generic {
        hep_ctrl_t         header;
        hep_chunk_uint8_t  ip_family;
        hep_chunk_uint8_t  ip_proto;
        hep_chunk_uint16_t src_port;
        hep_chunk_uint16_t dst_port;
        hep_chunk_uint32_t time_sec;
        hep_chunk_uint32_t time_usec;
        hep_chunk_uint8_t  proto_t;
        hep_chunk_uint32_t capt_id;
} __attribute__((packed));

typedef struct hep_generic hep_generic_t;

#define PROTO_RTCP_JSON   0x05

// modifies the GString in place
static int send_hepv3 (GString *s, const str *id, int capt_id, const endpoint_t *src, const endpoint_t *dst,
		const struct timeval *tv)
{

    struct hep_generic *hg=NULL;
    void* buffer;
    unsigned int buflen=0, iplen=0,tlen=0;
    hep_chunk_ip4_t src_ip4, dst_ip4;
    hep_chunk_ip6_t src_ip6, dst_ip6;
    hep_chunk_t payload_chunk;
    //hep_chunk_t authkey_chunk;
    hep_chunk_t correlation_chunk;
    //static int errors = 0;

    hg = malloc(sizeof(struct hep_generic));
    memset(hg, 0, sizeof(struct hep_generic));


    /* header set */
    memcpy(hg->header.id, "\x48\x45\x50\x33", 4);

    /* IP proto */
    hg->ip_family.chunk.vendor_id = htons(0x0000);
    hg->ip_family.chunk.type_id   = htons(0x0001);
    hg->ip_family.data = src->address.family->af;
    hg->ip_family.chunk.length = htons(sizeof(hg->ip_family));

    /* Proto ID */
    hg->ip_proto.chunk.vendor_id = htons(0x0000);
    hg->ip_proto.chunk.type_id   = htons(0x0002);
    hg->ip_proto.data = IPPROTO_UDP;
    hg->ip_proto.chunk.length = htons(sizeof(hg->ip_proto));


    /* IPv4 */
    if(hg->ip_family.data == AF_INET) {
        /* SRC IP */
        src_ip4.chunk.vendor_id = htons(0x0000);
        src_ip4.chunk.type_id   = htons(0x0003);
	src_ip4.data = src->address.u.ipv4;
        src_ip4.chunk.length = htons(sizeof(src_ip4));

        /* DST IP */
        dst_ip4.chunk.vendor_id = htons(0x0000);
        dst_ip4.chunk.type_id   = htons(0x0004);
	dst_ip4.data = dst->address.u.ipv4;
        dst_ip4.chunk.length = htons(sizeof(dst_ip4));

        iplen = sizeof(dst_ip4) + sizeof(src_ip4);
    }
      /* IPv6 */
    else if(hg->ip_family.data == AF_INET6) {
        /* SRC IPv6 */
        src_ip6.chunk.vendor_id = htons(0x0000);
        src_ip6.chunk.type_id   = htons(0x0005);
	src_ip6.data = src->address.u.ipv6;
        src_ip6.chunk.length = htons(sizeof(src_ip6));

        /* DST IPv6 */
        dst_ip6.chunk.vendor_id = htons(0x0000);
        dst_ip6.chunk.type_id   = htons(0x0006);
	dst_ip6.data = dst->address.u.ipv6;
        dst_ip6.chunk.length = htons(sizeof(dst_ip6));

        iplen = sizeof(dst_ip6) + sizeof(src_ip6);
    }

    /* SRC PORT */
    hg->src_port.chunk.vendor_id = htons(0x0000);
    hg->src_port.chunk.type_id   = htons(0x0007);
    hg->src_port.data = htons(src->port);
    hg->src_port.chunk.length = htons(sizeof(hg->src_port));

    /* DST PORT */
    hg->dst_port.chunk.vendor_id = htons(0x0000);
    hg->dst_port.chunk.type_id   = htons(0x0008);
    hg->dst_port.data = htons(dst->port);
    hg->dst_port.chunk.length = htons(sizeof(hg->dst_port));


    /* TIMESTAMP SEC */
    hg->time_sec.chunk.vendor_id = htons(0x0000);
    hg->time_sec.chunk.type_id   = htons(0x0009);
    hg->time_sec.data = htonl(tv->tv_sec);
    hg->time_sec.chunk.length = htons(sizeof(hg->time_sec));


    /* TIMESTAMP USEC */
    hg->time_usec.chunk.vendor_id = htons(0x0000);
    hg->time_usec.chunk.type_id   = htons(0x000a);
    hg->time_usec.data = htonl(tv->tv_usec);
    hg->time_usec.chunk.length = htons(sizeof(hg->time_usec));

    /* Protocol TYPE */
    hg->proto_t.chunk.vendor_id = htons(0x0000);
    hg->proto_t.chunk.type_id   = htons(0x000b);
    hg->proto_t.data = PROTO_RTCP_JSON;
    hg->proto_t.chunk.length = htons(sizeof(hg->proto_t));

    /* Capture ID */
    hg->capt_id.chunk.vendor_id = htons(0x0000);
    hg->capt_id.chunk.type_id   = htons(0x000c);
    hg->capt_id.data = htonl(capt_id);
    hg->capt_id.chunk.length = htons(sizeof(hg->capt_id));

    /* Payload */
    payload_chunk.vendor_id = htons(0x0000);
    payload_chunk.type_id   = 0 ? htons(0x0010) : htons(0x000f);
    payload_chunk.length    = htons(sizeof(payload_chunk) + s->len);

    tlen = sizeof(struct hep_generic) + s->len + iplen + sizeof(hep_chunk_t);

#if 0
    /* auth key */
    if(profile_transport[idx].capt_password != NULL) {

          tlen += sizeof(hep_chunk_t);
          /* Auth key */
          authkey_chunk.vendor_id = htons(0x0000);
          authkey_chunk.type_id   = htons(0x000e);
          authkey_chunk.length    = htons(sizeof(authkey_chunk) + strlen(profile_transport[idx].capt_password));
          tlen += strlen(profile_transport[idx].capt_password);
    }
#endif

    /* correlation key */
    //if(rcinfo->correlation_id.s && rcinfo->correlation_id.len > 0) {

             tlen += sizeof(hep_chunk_t);
             /* Correlation key */
             correlation_chunk.vendor_id = htons(0x0000);
             correlation_chunk.type_id   = htons(0x0011);
             correlation_chunk.length    = htons(sizeof(correlation_chunk) + id->len);
             tlen += id->len;
    //}

    /* total */
    hg->header.length = htons(tlen);

    buffer = (void*)malloc(tlen);
    if (buffer==0){
        ilog(LOG_ERR, "ERROR: out of memory");
        free(hg);
        return -1;
    }

    memcpy((void*) buffer, hg, sizeof(struct hep_generic));
    buflen = sizeof(struct hep_generic);

    /* IPv4 */
    if(hg->ip_family.data == AF_INET) {
        /* SRC IP */
        memcpy((void*) buffer+buflen, &src_ip4, sizeof(struct hep_chunk_ip4));
        buflen += sizeof(struct hep_chunk_ip4);

        memcpy((void*) buffer+buflen, &dst_ip4, sizeof(struct hep_chunk_ip4));
        buflen += sizeof(struct hep_chunk_ip4);
    }
      /* IPv6 */
    else if(hg->ip_family.data == AF_INET6) {
        /* SRC IPv6 */
        memcpy((void*) buffer+buflen, &src_ip6, sizeof(struct hep_chunk_ip6));
        buflen += sizeof(struct hep_chunk_ip6);

        memcpy((void*) buffer+buflen, &dst_ip6, sizeof(struct hep_chunk_ip6));
        buflen += sizeof(struct hep_chunk_ip6);
    }

#if 0
    /* AUTH KEY CHUNK */
    if(profile_transport[idx].capt_password != NULL) {

        memcpy((void*) buffer+buflen, &authkey_chunk,  sizeof(struct hep_chunk));
        buflen += sizeof(struct hep_chunk);

        /* Now copying payload self */
        memcpy((void*) buffer+buflen, profile_transport[idx].capt_password, strlen(profile_transport[idx].capt_password));
        buflen+=strlen(profile_transport[idx].capt_password);
    }
#endif

    /* Correlation KEY CHUNK */
    //if(rcinfo->correlation_id.s && rcinfo->correlation_id.len > 0) {

           memcpy((void*) buffer+buflen, &correlation_chunk,  sizeof(struct hep_chunk));
           buflen += sizeof(struct hep_chunk);

           /* Now copying payload self */
           memcpy((void*) buffer+buflen, id->s, id->len);
           buflen+= id->len;
    //}

    /* PAYLOAD CHUNK */
    memcpy((void*) buffer+buflen, &payload_chunk,  sizeof(struct hep_chunk));
    buflen +=  sizeof(struct hep_chunk);

    /* Now copying payload self */
    memcpy((void*) buffer+buflen, s->str, s->len);
    buflen+=s->len;

#if 0
    /* make sleep after 100 errors */
     if(errors > 50) {
        LERR( "HEP server is down... retrying after sleep...");
        if(!profile_transport[idx].usessl) {
             sleep(2);
             if(init_hepsocket_blocking(idx)) {
            	 profile_transport[idx].initfails++;
             }

             errors=0;
        }
#ifdef USE_SSL
        else {
                sleep(2);

                if(initSSL(idx)) profile_transport[idx].initfails++;

                errors=0;
         }
#endif /* USE SSL */

     }

    /* send this packet out of our socket */
    if(send_data(buffer, buflen, idx)) {
        errors++;
        stats.errors_total++;
    }
#endif

    g_string_truncate(s, 0);
    g_string_append_len(s, buffer, buflen);

    /* FREE */
    free(buffer);
    free(hg);

    return 0;
}

int has_homer() {
	return main_homer_sender ? 1 : 0;
}
