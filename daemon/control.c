#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <pcre.h>

#include "control.h"
#include "poller.h"
#include "aux.h"
#include "streambuf.h"
#include "log.h"
#include "call.h"




static pcre		*parse_re;
static pcre_extra	*parse_ree;

static void control_stream_closed(int fd, void *p, uintptr_t u) {
	struct control_stream *s = p;
	struct control *c;

	mylog(LOG_INFO, "Control connection from " DF " closed", DP(s->inaddr));

	c = s->control;

	c->streams = g_list_remove(c->streams, s);
	obj_put(&s->obj);

	if (poller_del_item(s->poller, fd))
		abort();
}


static void control_list(struct control *c, struct control_stream *s) {
	struct control_stream *i;
	GList *l;

	for (l = c->streams; l; l = l->next) {
		i = l->data;
		streambuf_printf(s->outbuf, DF "\n", DP(i->inaddr));
	}

	streambuf_printf(s->outbuf, "End.\n");
}


static int control_stream_parse(struct control_stream *s, char *line) {
	const char *errptr;
	int erroff;
	int ovec[60];
	int ret;
	const char **out;
	struct control *c = s->control;
	char *output = NULL;

	if (!parse_re) {
		parse_re = pcre_compile(
				/*      reqtype          callid   streams     ip      fromdom   fromtype   todom     totype    agent          info  |reqtype     callid         info  | reqtype */
				"^(?:(request|lookup)\\s+(\\S+)\\s+(\\S+)\\s+(\\S+)\\s+(\\S+)\\s+(\\S+)\\s+(\\S+)\\s+(\\S+)\\s+(\\S+)\\s+info=(\\S*)|(delete)\\s+(\\S+)\\s+info=(\\S*)|(build|version|controls|quit|exit|status))$",
				PCRE_DOLLAR_ENDONLY | PCRE_DOTALL, &errptr, &erroff, NULL);
		parse_ree = pcre_study(parse_re, 0, &errptr);
	}

	ret = pcre_exec(parse_re, parse_ree, line, strlen(line), 0, 0, ovec, G_N_ELEMENTS(ovec));
	if (ret <= 0) {
		mylog(LOG_WARNING, "Unable to parse command line from " DF ": %s", DP(s->inaddr), line);
		return -1;
	}

	mylog(LOG_INFO, "Got valid command from " DF ": %s", DP(s->inaddr), line);

	pcre_get_substring_list(line, ovec, ret, &out);


	if (!strcmp(out[RE_TCP_RL_CMD], "request"))
		output = call_request(out, c->callmaster);
	else if (!strcmp(out[RE_TCP_RL_CMD], "lookup"))
		output = call_lookup(out, c->callmaster);
	else if (!strcmp(out[RE_TCP_D_CMD], "delete"))
		call_delete(out, c->callmaster);
	else if (!strcmp(out[RE_TCP_DIV_CMD], "status"))
		calls_status(c->callmaster, s);
	else if (!strcmp(out[RE_TCP_DIV_CMD], "build") | !strcmp(out[RE_TCP_DIV_CMD], "version"))
		streambuf_printf(s->outbuf, "Version: %s\n", MEDIAPROXY_VERSION);
	else if (!strcmp(out[RE_TCP_DIV_CMD], "controls"))
		control_list(c, s);
	else if (!strcmp(out[RE_TCP_DIV_CMD], "quit") || !strcmp(out[RE_TCP_DIV_CMD], "exit"))
		;

	if (output) {
		streambuf_write(s->outbuf, output, strlen(output));
		free(output);
	}

	pcre_free(out);
	return -1;
}


static void control_stream_timer(int fd, void *p, uintptr_t u) {
	struct control_stream *s = p;
	struct poller *o = s->poller;

	if ((poller_now(o) - s->inbuf->active) >= 60 || (poller_now(o) - s->outbuf->active) >= 60)
		control_stream_closed(s->fd, s, 0);
}


static void control_stream_readable(int fd, void *p, uintptr_t u) {
	struct control_stream *s = p;
	char *line;
	int ret;

	if (streambuf_readable(s->inbuf))
		goto close;

	while ((line = streambuf_getline(s->inbuf))) {
		mylog(LOG_DEBUG, "Got control line from " DF ": %s", DP(s->inaddr), line);
		ret = control_stream_parse(s, line);
		free(line);
		if (ret)
			goto close;
	}

	if (streambuf_bufsize(s->inbuf) > 1024) {
		mylog(LOG_WARNING, "Buffer length exceeded in control connection from " DF, DP(s->inaddr));
		goto close;
	}

	return;

close:
	control_stream_closed(fd, s, 0);
}

static void control_stream_writeable(int fd, void *p, uintptr_t u) {
	struct control_stream *s = p;

	if (streambuf_writeable(s->outbuf))
		control_stream_closed(fd, s, 0);
}

static void control_closed(int fd, void *p, uintptr_t u) {
	abort();
}

static void control_stream_free(void *p) {
	struct control_stream *s = p;

	close(s->fd);
	streambuf_destroy(s->inbuf);
	streambuf_destroy(s->outbuf);
}

static void control_incoming(int fd, void *p, uintptr_t u) {
	int nfd;
	struct control *c = p;
	struct control_stream *s;
	struct poller_item i;
	struct sockaddr_in sin;
	socklen_t sinl;

	sinl = sizeof(sin);
	nfd = accept(fd, (struct sockaddr *) &sin, &sinl);
	if (nfd == -1)
		return;
	nonblock(nfd);

	mylog(LOG_INFO, "New control connection from " DF, DP(sin));

	s = obj_alloc0("control_stream", sizeof(*s), control_stream_free);

	s->fd = nfd;
	s->control = c;
	s->poller = c->poller;
	s->inbuf = streambuf_new(c->poller, nfd);
	s->outbuf = streambuf_new(c->poller, nfd);
	memcpy(&s->inaddr, &sin, sizeof(s->inaddr));

	ZERO(i);
	i.fd = nfd;
	i.closed = control_stream_closed;
	i.readable = control_stream_readable;
	i.writeable = control_stream_writeable;
	i.timer = control_stream_timer;
	i.obj = &s->obj;

	if (poller_add_item(c->poller, &i))
		goto fail;

	/* let the list steal our own ref */
	c->streams = g_list_prepend(c->streams, s);

	return;

fail:
	obj_put(&s->obj);
}


struct control *control_new(struct poller *p, u_int32_t ip, u_int16_t port, struct callmaster *m) {
	int fd;
	struct control *c;
	struct poller_item i;
	struct sockaddr_in sin;

	if (!p)
		return NULL;
	if (!m)
		return NULL;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1)
		return NULL;

	nonblock(fd);
	reuseaddr(fd);

	ZERO(sin);
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = ip;
	sin.sin_port = htons(port);
	if (bind(fd, (struct sockaddr *) &sin, sizeof(sin)))
		goto fail;

	if (listen(fd, 5))
		goto fail;


	c = obj_alloc0("control", sizeof(*c), NULL);

	c->fd = fd;
	c->poller = p;
	c->callmaster = m;

	ZERO(i);
	i.fd = fd;
	i.closed = control_closed;
	i.readable = control_incoming;
	i.obj = &c->obj;
	if (poller_add_item(p, &i))
		goto fail2;

	obj_put(&c->obj);
	return c;

fail2:
	obj_put(&c->obj);
fail:
	close(fd);
	return NULL;
}
