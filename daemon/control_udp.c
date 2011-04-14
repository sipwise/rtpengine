#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <pcre.h>
#include <glib.h>

#include "control_udp.h"
#include "poller.h"
#include "aux.h"
#include "log.h"
#include "call.h"





static pcre		*parse_re;
static pcre_extra	*parse_ree;
static GHashTable	*cookies;




static void control_udp_closed(int fd, void *p) {
	abort();
}

static void control_udp_incoming(int fd, void *p) {
	struct control_udp *u = p;
	int ret;
	char buf[8192];
	struct sockaddr_in sin;
	socklen_t sin_len;
	int ovec[60];
	const char *errptr;
	int erroff;
	const char **out;
	char *reply;

	sin_len = sizeof(sin);
	ret = recvfrom(fd, buf, sizeof(buf) - 1, 0, (struct sockaddr *) &sin, &sin_len);
	if (ret <= 0) {
		mylog(LOG_WARNING, "Error reading from UDP socket");
		return;
	}

	buf[ret] = '\0';

	if (!parse_re) {
		parse_re = pcre_compile(
				/* cookie       cmd   flags    callid      addr        port   from_tag                 to_tag              cmd flags    callid */
				"^(\\S+)\\s+(?:([ul])(\\S*)\\s+(\\S+)\\s+([\\d.]+)\\s+(\\d+)\\s+(\\S+?)(?:;\\S+)?(?:\\s+(\\S+?)(?:;\\S+)?)?|(d)(\\S*)\\s+(\\S+))",
				PCRE_DOLLAR_ENDONLY | PCRE_DOTALL | PCRE_CASELESS, &errptr, &erroff, NULL);
		parse_ree = pcre_study(parse_re, 0, &errptr);
	}

	ret = pcre_exec(parse_re, parse_ree, buf, ret, 0, 0, ovec, ARRAY_SIZE(ovec));
	if (ret <= 0) {
		mylog(LOG_WARNING, "Unable to parse command line from udp:" DF ": %s", DP(sin), buf);
		return;
	}

	mylog(LOG_INFO, "Got valid command from udp:" DF ": %s", DP(sin), buf);

	pcre_get_substring_list(buf, ovec, ret, &out);

	if (!cookies)
		cookies = g_hash_table_new_full(g_str_hash, g_str_equal, free, free);

	/* XXX better hashing */
	reply = g_hash_table_lookup(cookies, out[1]);
	if (reply) {
		sendto(fd, reply, strlen(reply), 0, (struct sockaddr *) &sin, sin_len);
		goto out;
	}

	if (out[2][0] == 'u' || out[2][0] == 'U')
		reply = call_update_udp(out, u->callmaster);
	else if (out[2][0] == 'l' || out[2][0] == 'L')
		reply = call_lookup_udp(out, u->callmaster);
	else if (out[9][0] == 'd' || out[9][0] == 'D')
		reply = call_delete_udp(out, u->callmaster);

	if (reply) {
		sendto(fd, reply, strlen(reply), 0, (struct sockaddr *) &sin, sin_len);
		g_hash_table_insert(cookies, strdup(out[1]), reply);	/* XXX timeout entries */
	}

out:
	pcre_free(out);
}

struct control_udp *control_udp_new(struct poller *p, u_int32_t ip, u_int16_t port, struct callmaster *m) {
	int fd;
	struct control_udp *c;
	struct poller_item i;
	struct sockaddr_in sin;

	if (!p || !m)
		return NULL;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd == -1)
		return NULL;

	NONBLOCK(fd);
	REUSEADDR(fd);

	ZERO(sin);
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = ip;
	sin.sin_port = htons(port);
	if (bind(fd, (struct sockaddr *) &sin, sizeof(sin)))
		goto fail;


	c = malloc(sizeof(*c));
	ZERO(*c);

	c->fd = fd;
	c->poller = p;
	c->callmaster = m;

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
