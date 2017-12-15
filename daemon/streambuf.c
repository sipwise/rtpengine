#include "streambuf.h"

#include <stdio.h>
#include <glib.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <time.h>

#include "poller.h"
#include "aux.h"





struct streambuf *streambuf_new(struct poller *p, int fd) {
	struct streambuf *b;

	b = malloc(sizeof(*b));
	ZERO(*b);

	mutex_init(&b->lock);
	b->buf = g_string_new("");
	b->fd = fd;
	b->poller = p;
	b->active = poller_now;

	return b;
}


void streambuf_destroy(struct streambuf *b) {
	g_string_free(b->buf, TRUE);
	free(b);
}


int streambuf_writeable(struct streambuf *b) {
	int ret;
	unsigned int out;

	mutex_lock(&b->lock);

	for (;;) {
		if (!b->buf->len)
			break;

		out = (b->buf->len > 1024) ? 1024 : b->buf->len;
		ret = write(b->fd, b->buf->str, out);

		if (ret < 0) {
			if (errno == EINTR)
				continue;
			if (errno != EAGAIN && errno != EWOULDBLOCK) {
				mutex_unlock(&b->lock);
				return -1;
			}
			ret = 0;
		}

		if (ret > 0) {
			g_string_erase(b->buf, 0, ret);
			b->active = poller_now;
		}

		if (ret != out) {
			poller_blocked(b->poller, b->fd);
			break;
		}
	}

	mutex_unlock(&b->lock);
	return 0;
}

int streambuf_readable(struct streambuf *b) {
	int ret;
	char buf[1024];

	mutex_lock(&b->lock);

	for (;;) {
		ret = read(b->fd, buf, 1024);

		if (ret == 0) {
			// don't discard already read data in the buffer
			b->eof = 1;
			ret = b->buf->len ? -2 : -1;
			mutex_unlock(&b->lock);
			return ret;
		}
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			mutex_unlock(&b->lock);
			return -1;
		}

		g_string_append_len(b->buf, buf, ret);
		b->active = poller_now;
	}

	mutex_unlock(&b->lock);
	return 0;
}


char *streambuf_getline(struct streambuf *b) {
	char *p;
	int len, to_del;
	char *s = NULL;

	mutex_lock(&b->lock);

	for (;;) {
		if (s) {
			free(s);
			s = NULL;
		}

		p = memchr(b->buf->str, '\n', b->buf->len);
		if (!p) {
			if (b->eof) {
				// use entire string
				len = b->buf->len;
				to_del = len;
			}
			else
				break;
		}
		else {
			len = p - b->buf->str;
			to_del = len + 1;
			if (len == 0) {
				// blank line, skip it
				g_string_erase(b->buf, 0, 1);
				continue;
			}
		}

		s = malloc(len + 1);
		memcpy(s, b->buf->str, len);
		s[len] = '\0';
		g_string_erase(b->buf, 0, to_del);

		if (s[--len] == '\r') {
			if (len == 0)
				continue;
			s[len] = '\0';
		}

		break;
	}

	mutex_unlock(&b->lock);
	return s;
}

unsigned int streambuf_bufsize(struct streambuf *b) {
	return b->buf->len;
}


void streambuf_vprintf(struct streambuf *b, const char *f, va_list va) {
	GString *gs;

	gs = g_string_new("");
	g_string_vprintf(gs, f, va);

	streambuf_write(b, gs->str, gs->len);
	g_string_free(gs, TRUE);
}

void streambuf_printf(struct streambuf *b, const char *f, ...) {
	va_list va;

	va_start(va, f);
	streambuf_vprintf(b, f, va);
	va_end(va);
}

void streambuf_write(struct streambuf *b, const char *s, unsigned int len) {
	unsigned int out;
	int ret;

	mutex_lock(&b->lock);

	while (len && !poller_isblocked(b->poller, b->fd)) {
		out = (len > 1024) ? 1024 : len;
		ret = write(b->fd, s, out);

		if (ret < 0) {
			if (errno == EINTR)
				continue;
			if (errno != EAGAIN && errno != EWOULDBLOCK) {
				poller_error(b->poller, b->fd);
				break;
			}
			poller_blocked(b->poller, b->fd);
			break;
		}
		if (ret == 0)
			break;

		s += ret;
		len -= ret;
		b->active = poller_now;
	}

	if (b->buf->len > 5242880)
		poller_error(b->poller, b->fd);
	else if (len)
		g_string_append_len(b->buf, s, len);

	mutex_unlock(&b->lock);
}
