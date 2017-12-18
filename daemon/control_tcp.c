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
#include "call_interfaces.h"
#include "socket.h"
#include "log_funcs.h"
#include "tcp_listener.h"




struct control_tcp {
	struct obj		obj;

	struct streambuf_listener listeners[2];

	pcre			*parse_re;
	pcre_extra		*parse_ree;

	struct poller		*poller;
	struct callmaster	*callmaster;
};




//static void control_stream_closed(int fd, void *p, uintptr_t u) {
static void control_stream_closed(struct streambuf_stream *s) {
	ilog(LOG_INFO, "Control connection from %s closed", s->addr);
}


static void control_list(struct control_tcp *c, struct streambuf_stream *s) {
	for (int i = 0; i < G_N_ELEMENTS(c->listeners); i++) {
		if (!c->listeners[i].listener.family || !c->listeners[i].poller)
			continue; // not used

		mutex_lock(&c->listeners[i].lock);

		GList *streams = g_hash_table_get_values(c->listeners[i].streams);
		for (GList *l = streams; l; l = l->next) {
			struct streambuf_stream *cl = l->data;
			streambuf_printf(s->outbuf, "%s\n", cl->addr);
		}

		mutex_unlock(&c->listeners[i].lock);

		g_list_free(streams);
	}

	streambuf_printf(s->outbuf, "End.\n");
}


static int control_stream_parse(struct streambuf_stream *s, char *line) {
	int ovec[60];
	int ret;
	char **out;
	struct control_tcp *c = (void *) s->parent;
	str *output = NULL;

	ret = pcre_exec(c->parse_re, c->parse_ree, line, strlen(line), 0, 0, ovec, G_N_ELEMENTS(ovec));
	if (ret <= 0) {
		ilog(LOG_WARNING, "Unable to parse command line from %s: %s", s->addr, line);
		return -1;
	}

	ilog(LOG_INFO, "Got valid command from %s: %s", s->addr, line);

	pcre_get_substring_list(line, ovec, ret, (const char ***) &out);


	if (out[RE_TCP_RL_CALLID])
		log_info_c_string(out[RE_TCP_RL_CALLID]);
	else if (out[RE_TCP_D_CALLID])
		log_info_c_string(out[RE_TCP_D_CALLID]);


	if (!strcmp(out[RE_TCP_RL_CMD], "request"))
		output = call_request_tcp(out, c->callmaster);
	else if (!strcmp(out[RE_TCP_RL_CMD], "lookup"))
		output = call_lookup_tcp(out, c->callmaster);
	else if (!strcmp(out[RE_TCP_D_CMD], "delete"))
		call_delete_tcp(out, c->callmaster);
	else if (!strcmp(out[RE_TCP_DIV_CMD], "status"))
		calls_status_tcp(c->callmaster, s);
	else if (!strcmp(out[RE_TCP_DIV_CMD], "build") || !strcmp(out[RE_TCP_DIV_CMD], "version"))
		streambuf_printf(s->outbuf, "Version: %s\n", RTPENGINE_VERSION);
	else if (!strcmp(out[RE_TCP_DIV_CMD], "controls"))
		control_list(c, s);
	else if (!strcmp(out[RE_TCP_DIV_CMD], "quit") || !strcmp(out[RE_TCP_DIV_CMD], "exit"))
		;

	if (output) {
		streambuf_write_str(s->outbuf, output);
		free(output);
	}

	pcre_free(out);
	log_info_clear();
	return 1;
}


static void control_stream_timer(struct streambuf_stream *s) {
	if ((poller_now - s->inbuf->active) >= 60 || (poller_now - s->outbuf->active) >= 60)
		control_stream_closed(s);
}


//static void control_stream_readable(int fd, void *p, uintptr_t u) {
static void control_stream_readable(struct streambuf_stream *s) {
	char *line;
	int ret;

	while ((line = streambuf_getline(s->inbuf))) {
		ilog(LOG_DEBUG, "Got control line from %s: %s", s->addr, line);
		ret = control_stream_parse(s, line);
		free(line);
		if (ret == 1) {
			streambuf_stream_shutdown(s);
			break;
		}
		if (ret)
			goto close;
	}

	if (streambuf_bufsize(s->inbuf) > 1024) {
		ilog(LOG_WARNING, "Buffer length exceeded in control connection from %s", s->addr);
		goto close;
	}

	return;

close:
	streambuf_stream_close(s);
}

static void control_incoming(struct streambuf_stream *s) {
	ilog(LOG_INFO, "New TCP control connection from %s", s->addr);
}


struct control_tcp *control_tcp_new(struct poller *p, endpoint_t *ep, struct callmaster *m) {
	struct control_tcp *c;
	const char *errptr;
	int erroff;

	if (!p)
		return NULL;
	if (!m)
		return NULL;

	c = obj_alloc0("control", sizeof(*c), NULL);

	if (streambuf_listener_init(&c->listeners[0], p, ep,
				control_incoming, control_stream_readable,
				control_stream_closed,
				control_stream_timer,
				&c->obj))
	{
		ilog(LOG_ERR, "Failed to open TCP control port: %s", strerror(errno));
		goto fail;
	}
	if (ipv46_any_convert(ep)) {
		if (streambuf_listener_init(&c->listeners[1], p, ep,
					control_incoming, control_stream_readable,
					control_stream_closed,
					control_stream_timer,
					&c->obj))
		{
			ilog(LOG_ERR, "Failed to open TCP control port: %s", strerror(errno));
			goto fail;
		}
	}

	c->parse_re = pcre_compile(
			/*      reqtype          callid   streams     ip      fromdom   fromtype   todom     totype    agent          info  |reqtype     callid         info  | reqtype */
			"^(?:(request|lookup)\\s+(\\S+)\\s+(\\S+)\\s+(\\S+)\\s+(\\S+)\\s+(\\S+)\\s+(\\S+)\\s+(\\S+)\\s+(\\S+)\\s+info=(\\S*)|(delete)\\s+(\\S+)\\s+info=(\\S*)|(build|version|controls|quit|exit|status))$",
			PCRE_DOLLAR_ENDONLY | PCRE_DOTALL, &errptr, &erroff, NULL);
	c->parse_ree = pcre_study(c->parse_re, 0, &errptr);

	c->poller = p;
	c->callmaster = m;

	obj_put(c);
	return c;

fail:
	// XXX streambuf_listener_close ...
	obj_put(c);
	return NULL;
}
