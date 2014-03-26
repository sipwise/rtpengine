#include "control_tcp.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <pcre.h>
#include <glib.h>
#include <stdarg.h>
#include <errno.h>

#include "poller.h"
#include "aux.h"
#include "streambuf.h"
#include "log.h"
#include "call.h"




struct control_stream {
	struct obj		obj;

	int			fd;
	mutex_t			lock;
	struct streambuf	*inbuf;
	struct streambuf	*outbuf;
	struct sockaddr_in	inaddr;

	struct control_tcp	*control;
	struct poller		*poller;
	int			linked:1;
};


struct control_tcp {
	struct obj		obj;

	int			fd;
	pcre			*parse_re;
	pcre_extra		*parse_ree;

	mutex_t			lock;
	GList			*streams;

	struct poller		*poller;
	struct callmaster	*callmaster;
};




static void control_stream_closed(int fd, void *p, uintptr_t u) {
	struct control_stream *s = p;
	struct control_tcp *c;
	GList *l = NULL;

	ilog(LOG_INFO, "Control connection from " DF " closed", DP(s->inaddr));

	c = s->control;

restart:
	mutex_lock(&c->lock);
	if (s->linked) {
		/* we might get called when it's not quite linked yet */
		l = g_list_find(c->streams, s);
		if (!l) {
			mutex_unlock(&c->lock);
			goto restart;
		}
		c->streams = g_list_delete_link(c->streams, l);
		s->linked = 0;
	}
	mutex_unlock(&c->lock);
	if (l)
		obj_put(s);
	poller_del_item(s->poller, fd);
}


static void control_list(struct control_tcp *c, struct control_stream *s) {
	struct control_stream *i;
	GList *l;

	mutex_lock(&c->lock);
	for (l = c->streams; l; l = l->next) {
		i = l->data;
		mutex_lock(&s->lock);
		streambuf_printf(s->outbuf, DF "\n", DP(i->inaddr));
		mutex_unlock(&s->lock);
	}
	mutex_unlock(&c->lock);

	streambuf_printf(s->outbuf, "End.\n");
}


static int control_stream_parse(struct control_stream *s, char *line) {
	int ovec[60];
	int ret;
	char **out;
	struct control_tcp *c = s->control;
	str *output = NULL;

	ret = pcre_exec(c->parse_re, c->parse_ree, line, strlen(line), 0, 0, ovec, G_N_ELEMENTS(ovec));
	if (ret <= 0) {
		ilog(LOG_WARNING, "Unable to parse command line from " DF ": %s", DP(s->inaddr), line);
		return -1;
	}

	ilog(LOG_INFO, "Got valid command from " DF ": %s", DP(s->inaddr), line);

	pcre_get_substring_list(line, ovec, ret, (const char ***) &out);


	if (!strcmp(out[RE_TCP_RL_CMD], "request"))
		output = call_request_tcp(out, c->callmaster);
	else if (!strcmp(out[RE_TCP_RL_CMD], "lookup"))
		output = call_lookup_tcp(out, c->callmaster);
	else if (!strcmp(out[RE_TCP_D_CMD], "delete"))
		call_delete_tcp(out, c->callmaster);
	else if (!strcmp(out[RE_TCP_DIV_CMD], "status"))
		calls_status_tcp(c->callmaster, s);
	else if (!strcmp(out[RE_TCP_DIV_CMD], "build") | !strcmp(out[RE_TCP_DIV_CMD], "version"))
		control_stream_printf(s, "Version: %s\n", MEDIAPROXY_VERSION);
	else if (!strcmp(out[RE_TCP_DIV_CMD], "controls"))
		control_list(c, s);
	else if (!strcmp(out[RE_TCP_DIV_CMD], "quit") || !strcmp(out[RE_TCP_DIV_CMD], "exit"))
		;

	if (output) {
		mutex_lock(&s->lock);
		streambuf_write_str(s->outbuf, output);
		mutex_unlock(&s->lock);
		free(output);
	}

	pcre_free(out);
	log_info_clear();
	return -1;
}


static void control_stream_timer(int fd, void *p, uintptr_t u) {
	struct control_stream *s = p;
	int i;

	mutex_lock(&s->lock);
	i = (poller_now - s->inbuf->active) >= 60 || (poller_now - s->outbuf->active) >= 60;
	mutex_unlock(&s->lock);

	if (i)
		control_stream_closed(s->fd, s, 0);
}


static void control_stream_readable(int fd, void *p, uintptr_t u) {
	struct control_stream *s = p;
	char *line;
	int ret;

	mutex_lock(&s->lock);

	if (streambuf_readable(s->inbuf))
		goto close;

	while ((line = streambuf_getline(s->inbuf))) {
		mutex_unlock(&s->lock);
		ilog(LOG_DEBUG, "Got control line from " DF ": %s", DP(s->inaddr), line);
		ret = control_stream_parse(s, line);
		free(line);
		if (ret)
			goto close_nolock;
		mutex_lock(&s->lock);
	}

	if (streambuf_bufsize(s->inbuf) > 1024) {
		ilog(LOG_WARNING, "Buffer length exceeded in control connection from " DF, DP(s->inaddr));
		goto close;
	}

	mutex_unlock(&s->lock);
	return;

close:
	mutex_unlock(&s->lock);
close_nolock:
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
	mutex_destroy(&s->lock);
}

static void control_incoming(int fd, void *p, uintptr_t u) {
	int nfd;
	struct control_tcp *c = p;
	struct control_stream *s;
	struct poller_item i;
	struct sockaddr_in sin;
	socklen_t sinl;

next:
	sinl = sizeof(sin);
	nfd = accept(fd, (struct sockaddr *) &sin, &sinl);
	if (nfd == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return;
		goto next;
	}
	nonblock(nfd);

	ilog(LOG_INFO, "New control connection from " DF, DP(sin));

	s = obj_alloc0("control_stream", sizeof(*s), control_stream_free);

	s->fd = nfd;
	s->control = c;
	s->poller = c->poller;
	s->inbuf = streambuf_new(c->poller, nfd);
	s->outbuf = streambuf_new(c->poller, nfd);
	memcpy(&s->inaddr, &sin, sizeof(s->inaddr));
	mutex_init(&s->lock);
	s->linked = 1;

	ZERO(i);
	i.fd = nfd;
	i.closed = control_stream_closed;
	i.readable = control_stream_readable;
	i.writeable = control_stream_writeable;
	i.timer = control_stream_timer;
	i.obj = &s->obj;

	if (poller_add_item(c->poller, &i))
		goto fail;

	mutex_lock(&c->lock);
	/* let the list steal our own ref */
	c->streams = g_list_prepend(c->streams, s);
	mutex_unlock(&c->lock);

	goto next;

fail:
	obj_put(s);
	goto next;
}


struct control_tcp *control_tcp_new(struct poller *p, u_int32_t ip, u_int16_t port, struct callmaster *m) {
	int fd;
	struct control_tcp *c;
	struct poller_item i;
	struct sockaddr_in sin;
	const char *errptr;
	int erroff;

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

	c->parse_re = pcre_compile(
			/*      reqtype          callid   streams     ip      fromdom   fromtype   todom     totype    agent          info  |reqtype     callid         info  | reqtype */
			"^(?:(request|lookup)\\s+(\\S+)\\s+(\\S+)\\s+(\\S+)\\s+(\\S+)\\s+(\\S+)\\s+(\\S+)\\s+(\\S+)\\s+(\\S+)\\s+info=(\\S*)|(delete)\\s+(\\S+)\\s+info=(\\S*)|(build|version|controls|quit|exit|status))$",
			PCRE_DOLLAR_ENDONLY | PCRE_DOTALL, &errptr, &erroff, NULL);
	c->parse_ree = pcre_study(c->parse_re, 0, &errptr);

	c->fd = fd;
	c->poller = p;
	c->callmaster = m;
	mutex_init(&c->lock);

	ZERO(i);
	i.fd = fd;
	i.closed = control_closed;
	i.readable = control_incoming;
	i.obj = &c->obj;
	if (poller_add_item(p, &i))
		goto fail2;

	obj_put(c);
	return c;

fail2:
	obj_put(c);
fail:
	close(fd);
	return NULL;
}


void control_stream_printf(struct control_stream *s, const char *f, ...) {
	va_list va;

	va_start(va, f);
	mutex_lock(&s->lock);
	streambuf_vprintf(s->outbuf, f, va);
	mutex_unlock(&s->lock);
	va_end(va);
}
