#include "control_udp.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <pcre.h>
#include <glib.h>
#include <time.h>
#include <netinet/in.h>
#include <errno.h>

#include "poller.h"
#include "aux.h"
#include "log.h"
#include "call.h"
#include "udp_listener.h"
#include "call_interfaces.h"
#include "socket.h"
#include "log_funcs.h"


static void control_udp_incoming(struct obj *obj, struct udp_buffer *udp_buf) {
	struct control_udp *u = (void *) obj;
	int ret;
	int ovec[100];
	char **out;
	struct iovec iov[10];
	unsigned int iovlen;
	str cookie, *reply;

	ret = pcre_exec(u->parse_re, u->parse_ree, udp_buf->str.s, udp_buf->str.len, 0, 0, ovec, G_N_ELEMENTS(ovec));
	if (ret <= 0) {
		ret = pcre_exec(u->fallback_re, NULL, udp_buf->str.s, udp_buf->str.len, 0, 0, ovec, G_N_ELEMENTS(ovec));
		if (ret <= 0) {
			ilogs(control, LOG_WARNING, "Unable to parse command line from udp:%s: %.*s", udp_buf->addr, STR_FMT(&udp_buf->str));
			return;
		}

		ilogs(control, LOG_WARNING, "Failed to properly parse UDP command line '%.*s' from %s, using fallback RE", STR_FMT(&udp_buf->str), udp_buf->addr);

		pcre_get_substring_list(udp_buf->str.s, ovec, ret, (const char ***) &out);

		iov[0].iov_base = (void *) out[RE_UDP_COOKIE];
		iov[0].iov_len = strlen(out[RE_UDP_COOKIE]);
		if (out[RE_UDP_UL_CMD] && (chrtoupper(out[RE_UDP_UL_CMD][0]) == 'U' || chrtoupper(out[RE_UDP_UL_CMD][0]) == 'L')) {
			iov[1].iov_base = (void *) out[4];
			iov[1].iov_len = strlen(out[4]);
			iov[2].iov_base = (void *) out[3];
			iov[2].iov_len = strlen(out[3]);
			iov[3].iov_base = "\n";
			iov[3].iov_len = 1;
			iovlen = 4;
		}
		else {
			iov[1].iov_base = " E8\n";
			iov[1].iov_len = 4;
			iovlen = 2;
		}

		socket_sendiov(udp_buf->listener, iov, iovlen, &udp_buf->sin);

		pcre_free(out);

		return;
	}

	ilogs(control, LOG_INFO, "Got valid command from udp:%s: %.*s", udp_buf->addr, STR_FMT(&udp_buf->str));

	pcre_get_substring_list(udp_buf->str.s, ovec, ret, (const char ***) &out);

	str_init(&cookie, (void *) out[RE_UDP_COOKIE]);
	reply = cookie_cache_lookup(&u->cookie_cache, &cookie);
	if (reply) {
		ilogs(control, LOG_INFO, "Detected command from udp:%s as a duplicate", udp_buf->addr);
		socket_sendto(udp_buf->listener, reply->s, reply->len, &udp_buf->sin);
		free(reply);
		goto out;
	}

	if (out[RE_UDP_UL_CALLID])
		log_info_c_string(out[RE_UDP_UL_CALLID]);
	else if (out[RE_UDP_DQ_CALLID])
		log_info_c_string(out[RE_UDP_DQ_CALLID]);

	if (chrtoupper(out[RE_UDP_UL_CMD][0]) == 'U')
		reply = call_update_udp(out, udp_buf->addr, &udp_buf->sin);
	else if (chrtoupper(out[RE_UDP_UL_CMD][0]) == 'L')
		reply = call_lookup_udp(out);
	else if (chrtoupper(out[RE_UDP_DQ_CMD][0]) == 'D')
		reply = call_delete_udp(out);
	else if (chrtoupper(out[RE_UDP_DQ_CMD][0]) == 'Q')
		reply = call_query_udp(out);
	else if (chrtoupper(out[RE_UDP_V_CMD][0]) == 'V') {
		iovlen = 2;

		iov[0].iov_base = (void *) out[RE_UDP_COOKIE];
		iov[0].iov_len = strlen(out[RE_UDP_COOKIE]);
		iov[1].iov_base = " ";
		iov[1].iov_len = 1;

		if (chrtoupper(out[RE_UDP_V_FLAGS][0]) == 'F') {
			ret = 0;
			if (!strcmp(out[RE_UDP_V_PARMS], "20040107"))
				ret = 1;
			else if (!strcmp(out[RE_UDP_V_PARMS], "20050322"))
				ret = 1;
			else if (!strcmp(out[RE_UDP_V_PARMS], "20060704"))
				ret = 1;
			iov[2].iov_base = ret ? "1\n" : "0\n";
			iov[2].iov_len = 2;
			iovlen++;
		}
		else {
			iov[2].iov_base = "20040107\n";
			iov[2].iov_len = 9;
			iovlen++;
		}
		socket_sendiov(udp_buf->listener, iov, iovlen, &udp_buf->sin);
	}

	if (reply) {
		socket_sendto(udp_buf->listener, reply->s, reply->len, &udp_buf->sin);
		cookie_cache_insert(&u->cookie_cache, &cookie, reply);
		free(reply);
	}
	else
		cookie_cache_remove(&u->cookie_cache, &cookie);

out:
	pcre_free(out);
	log_info_pop();
}

void control_udp_free(void *p) {
	struct control_udp *u = p;
	pcre_free_study(u->parse_ree);
	pcre_free(u->parse_re);
	pcre_free(u->fallback_re);
	close_socket(&u->udp_listener);
	cookie_cache_cleanup(&u->cookie_cache);
}

struct control_udp *control_udp_new(struct poller *p, endpoint_t *ep) {
	struct control_udp *c;
	const char *errptr;
	int erroff;

	if (!p)
		return NULL;

	c = obj_alloc0("control_udp", sizeof(*c), control_udp_free);

	c->parse_re = pcre_compile(
			/* cookie cmd flags callid viabranch:5 */
			"^(\\S+)\\s+(?:([ul])(\\S*)\\s+([^;]+)(?:;(\\S+))?\\s+" \
			/* addr4 addr6:7 */
			"(?:([\\d.]+)|([\\da-f:]+(?::ffff:[\\d.]+)?))" \
			/* port fromtag num totag:11 */
			"\\s+(\\d+)\\s+(\\S+?);(\\d+)(?:\\s+(\\S+?);\\d+(?:\\s+.*)?)?\r?\n?$" \
			/* "d/q" flags callid viabranch fromtag totag:17 */
			"|([dq])(\\S*)\\s+([^;\\s]+)(?:;(\\S+))?\\s+(\\S+?)(?:;\\d+)?(?:\\s+(\\S+?)(?:;\\d+)?)?\r?\n?$" \
			/* v flags params:20 */
			"|(v)(\\S*)(?:\\s+(\\S+))?)",
			PCRE_DOLLAR_ENDONLY | PCRE_DOTALL | PCRE_CASELESS, &errptr, &erroff, NULL);
	c->parse_ree = pcre_study(c->parse_re, 0, &errptr);
			              /* cookie       cmd flags callid   addr      port */
	c->fallback_re = pcre_compile("^(\\S+)(?:\\s+(\\S)\\S*\\s+\\S+(\\s+\\S+)(\\s+\\S+))?", PCRE_DOLLAR_ENDONLY | PCRE_DOTALL | PCRE_CASELESS, &errptr, &erroff, NULL);

	if (!c->parse_re || !c->fallback_re)
		goto fail2;

	cookie_cache_init(&c->cookie_cache);

	if (udp_listener_init(&c->udp_listener, p, ep, control_udp_incoming, &c->obj))
		goto fail2;

	return c;

fail2:
	obj_put(c);
	return NULL;

}
