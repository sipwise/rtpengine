#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <pcre.h>
#include <glib.h>
#include <time.h>
#include <netinet/in.h>

#include "control_udp.h"
#include "poller.h"
#include "aux.h"
#include "log.h"
#include "call.h"


static void control_udp_closed(int fd, void *p) {
	abort();
}

static void control_udp_incoming(int fd, void *p) {
	struct control_udp *u = p;
	int ret, len;
	char buf[8192];
	struct sockaddr_in6 sin;
	socklen_t sin_len;
	int ovec[60];
	const char **out;
	char *reply;
	struct msghdr mh;
	struct iovec iov[10];
	char addr[64];

	sin_len = sizeof(sin);
	len = recvfrom(fd, buf, sizeof(buf) - 1, 0, (struct sockaddr *) &sin, &sin_len);
	if (len <= 0) {
		mylog(LOG_WARNING, "Error reading from UDP socket");
		return;
	}

	buf[len] = '\0';
	smart_ntop_p(addr, &sin.sin6_addr, sizeof(addr));

	ret = pcre_exec(u->parse_re, u->parse_ree, buf, len, 0, 0, ovec, G_N_ELEMENTS(ovec));
	if (ret <= 0) {
		ret = pcre_exec(u->fallback_re, NULL, buf, len, 0, 0, ovec, G_N_ELEMENTS(ovec));
		if (ret <= 0) {
			mylog(LOG_WARNING, "Unable to parse command line from udp:%s:%u: %s", addr, ntohs(sin.sin6_port), buf);
			return;
		}

		mylog(LOG_WARNING, "Failed to properly parse UDP command line '%s' from %s:%u, using fallback RE", buf, addr, ntohs(sin.sin6_port));

		pcre_get_substring_list(buf, ovec, ret, &out);

		ZERO(mh);
		mh.msg_name = &sin;
		mh.msg_namelen = sizeof(sin);
		mh.msg_iov = iov;

		iov[0].iov_base = (void *) out[RE_UDP_COOKIE];
		iov[0].iov_len = strlen(out[RE_UDP_COOKIE]);
		if (out[RE_UDP_UL_CMD] && (chrtoupper(out[RE_UDP_UL_CMD][0]) == 'U' || chrtoupper(out[RE_UDP_UL_CMD][0]) == 'L')) {
			iov[1].iov_base = (void *) out[RE_UDP_UL_CALLID];
			iov[1].iov_len = strlen(out[RE_UDP_UL_CALLID]);
			iov[2].iov_base = (void *) out[RE_UDP_UL_FLAGS];
			iov[2].iov_len = strlen(out[RE_UDP_UL_FLAGS]);
			iov[3].iov_base = "\n";
			iov[3].iov_len = 1;
			mh.msg_iovlen = 4;
		}
		else {
			iov[1].iov_base = " E8\n";
			iov[1].iov_len = 4;
			mh.msg_iovlen = 2;
		}

		sendmsg(fd, &mh, 0);

		pcre_free(out);

		return;
	}

	mylog(LOG_INFO, "Got valid command from udp:%s:%u: %s", addr, ntohs(sin.sin6_port), buf);

	pcre_get_substring_list(buf, ovec, ret, &out);

	if (u->poller->now - u->oven_time >= 30) {
		g_hash_table_remove_all(u->stale_cookies);
#if GLIB_CHECK_VERSION(2,14,0)
		g_string_chunk_clear(u->stale_chunks);
		swap_ptrs(&u->stale_chunks, &u->fresh_chunks);
#else
		g_string_chunk_free(u->stale_chunks);
		u->stale_chunks = u->fresh_chunks;
		u->fresh_chunks = g_string_chunk_new(4 * 1024);
#endif
		swap_ptrs(&u->stale_cookies, &u->fresh_cookies);
		u->oven_time = u->poller->now;	/* baked new cookies! */
	}

	/* XXX better hashing */
	reply = g_hash_table_lookup(u->fresh_cookies, out[RE_UDP_COOKIE]);
	if (!reply)
		reply = g_hash_table_lookup(u->stale_cookies, out[RE_UDP_COOKIE]);
	if (reply) {
		mylog(LOG_INFO, "Detected command from udp:%s:%u as a duplicate", addr, ntohs(sin.sin6_port));
		sendto(fd, reply, strlen(reply), 0, (struct sockaddr *) &sin, sin_len);
		goto out;
	}

	if (chrtoupper(out[RE_UDP_UL_CMD][0]) == 'U')
		reply = call_update_udp(out, u->callmaster);
	else if (chrtoupper(out[RE_UDP_UL_CMD][0]) == 'L')
		reply = call_lookup_udp(out, u->callmaster);
	else if (chrtoupper(out[RE_UDP_D_CMD][0]) == 'D')
		reply = call_delete_udp(out, u->callmaster);
	else if (chrtoupper(out[RE_UDP_V_CMD][0]) == 'V') {
		ZERO(mh);
		mh.msg_name = &sin;
		mh.msg_namelen = sizeof(sin);
		mh.msg_iov = iov;
		mh.msg_iovlen = 2;

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
			mh.msg_iovlen++;
		}
		else {
			iov[2].iov_base = "20040107\n";
			iov[2].iov_len = 9;
			mh.msg_iovlen++;
		}
		sendmsg(fd, &mh, 0);
	}

	if (reply) {
		sendto(fd, reply, strlen(reply), 0, (struct sockaddr *) &sin, sin_len);
		g_hash_table_insert(u->fresh_cookies, g_string_chunk_insert(u->fresh_chunks, out[RE_UDP_COOKIE]),
			g_string_chunk_insert(u->fresh_chunks, reply));
		free(reply);
	}

out:
	pcre_free(out);
}

struct control_udp *control_udp_new(struct poller *p, struct in6_addr ip, u_int16_t port, struct callmaster *m) {
	int fd;
	struct control_udp *c;
	struct poller_item i;
	struct sockaddr_in6 sin;
	const char *errptr;
	int erroff;

	if (!p || !m)
		return NULL;

	fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (fd == -1)
		return NULL;

	nonblock(fd);
	reuseaddr(fd);
	ipv6only(fd, 0);

	ZERO(sin);
	sin.sin6_family = AF_INET6;
	sin.sin6_addr = ip;
	sin.sin6_port = htons(port);
	if (bind(fd, (struct sockaddr *) &sin, sizeof(sin)))
		goto fail;


	c = malloc(sizeof(*c));
	ZERO(*c);

	c->fd = fd;
	c->poller = p;
	c->callmaster = m;
	c->fresh_cookies = g_hash_table_new(g_str_hash, g_str_equal);
	c->stale_cookies = g_hash_table_new(g_str_hash, g_str_equal);
	c->fresh_chunks = g_string_chunk_new(4 * 1024);
	c->stale_chunks = g_string_chunk_new(4 * 1024);
	c->oven_time = p->now;
	c->parse_re = pcre_compile(
			/* cookie:1     cmd:2 flags:3  callid:4  viabranch:5      addr4:6           addr6:7                  port:8  from_tag:9 num:10      to_tag:11                      d:12 flags:13 callid:14 viabranch:15 v:16 flags:17 parms:18 */
			"^(\\S+)\\s+(?:([ul])(\\S*)\\s+([^;]+)(?:;(\\S+))?\\s+" \
			"(?:([\\d.]+)|([\\da-f:]+(?::ffff:[\\d.]+)?))" \
			"\\s+(\\d+)\\s+(\\S+?);(\\d+)(?:\\s+(\\S+?);\\d+(?:\\s+.*)?)?\r?\n?$" \
			"|(d)(\\S*)\\s+([^;\\s]+)(?:;(\\S+))?\\s+" \
			"|(v)(\\S*)(?:\\s+(\\S+))?)",
			PCRE_DOLLAR_ENDONLY | PCRE_DOTALL | PCRE_CASELESS, &errptr, &erroff, NULL);
	c->parse_ree = pcre_study(c->parse_re, 0, &errptr);
			              /* cookie       cmd flags callid   addr      port */
	c->fallback_re = pcre_compile("^(\\S+)(?:\\s+(\\S)\\S*\\s+\\S+(\\s+\\S+)(\\s+\\S+))?", PCRE_DOLLAR_ENDONLY | PCRE_DOTALL | PCRE_CASELESS, &errptr, &erroff, NULL);

	if (!c->parse_re || !c->fallback_re)
		goto fail2;

	ZERO(i);
	i.fd = fd;
	i.closed = control_udp_closed;
	i.readable = control_udp_incoming;
	i.ptr = c;
	if (poller_add_item(p, &i))
		goto fail2;

	return c;

fail2:
	free(c);
fail:
	close(fd);
	return NULL;

}
