#include "streambuf.h"

#include <stdio.h>
#include <glib.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <time.h>

#include "poller.h"
#include "auxlib.h"




static ssize_t __fd_write(void *, const void *, size_t);
static ssize_t __fd_read(void *, void *, size_t);

static const struct streambuf_funcs __fd_funcs = {
	.write = __fd_write,
	.read = __fd_read,
};

static ssize_t __fd_write(void *fd, const void *b, size_t s) {
	return write(GPOINTER_TO_INT(fd), b, s);
}
static ssize_t __fd_read(void *fd, void *b, size_t s) {
	return read(GPOINTER_TO_INT(fd), b, s);
}

struct streambuf *streambuf_new_ptr(struct poller *p, void *fd_ptr, const struct streambuf_funcs *funcs) {
	struct streambuf *b;

	b = g_slice_alloc0(sizeof(*b));

	mutex_init(&b->lock);
	b->buf = g_string_new("");
	b->fd_ptr = fd_ptr;
	b->poller = p;
	b->active = rtpe_now.tv_sec;
	b->funcs = funcs;

	return b;
}
struct streambuf *streambuf_new(struct poller *p, int fd) {
	return streambuf_new_ptr(p, GINT_TO_POINTER(fd), &__fd_funcs);
}


void streambuf_destroy(struct streambuf *b) {
	g_string_free(b->buf, TRUE);
	g_slice_free1(sizeof(*b), b);
}


int streambuf_writeable(struct streambuf *b) {
	int ret;
	unsigned int out;

	mutex_lock(&b->lock);

	for (;;) {
		if (!b->buf->len)
			break;

		out = (b->buf->len > 1024) ? 1024 : b->buf->len;
		ret = b->funcs->write(b->fd_ptr, b->buf->str, out);

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
			b->active = rtpe_now.tv_sec;
		}

		if (ret != out) {
			rtpe_poller_blocked(b->poller, b->fd_ptr);
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
		ret = b->funcs->read(b->fd_ptr, buf, 1024);

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
		b->active = rtpe_now.tv_sec;
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

size_t streambuf_bufsize(struct streambuf *b) {
	return b->buf->len;
}


size_t streambuf_vprintf(struct streambuf *b, const char *f, va_list va) {
	GString *gs;

	gs = g_string_new("");
	g_string_vprintf(gs, f, va);

	size_t ret = gs->len;
	streambuf_write(b, gs->str, gs->len);
	g_string_free(gs, TRUE);

	return ret;
}

size_t streambuf_printf(struct streambuf *b, const char *f, ...) {
	va_list va;

	va_start(va, f);
	size_t ret = streambuf_vprintf(b, f, va);
	va_end(va);

	return ret;
}

void streambuf_write(struct streambuf *b, const char *s, unsigned int len) {
	unsigned int out;
	int ret;

	if (!b)
		return;

	mutex_lock(&b->lock);

	while (len && !rtpe_poller_isblocked(b->poller, b->fd_ptr)) {
		out = (len > 1024) ? 1024 : len;
		ret = b->funcs->write(b->fd_ptr, s, out);

		if (ret < 0) {
			if (errno == EINTR)
				continue;
			if (errno != EAGAIN && errno != EWOULDBLOCK) {
				rtpe_poller_error(b->poller, b->fd_ptr);
				break;
			}
			rtpe_poller_blocked(b->poller, b->fd_ptr);
			break;
		}
		if (ret == 0)
			break;

		s += ret;
		len -= ret;
		b->active = rtpe_now.tv_sec;
	}

	if (b->buf->len > 5242880)
		rtpe_poller_error(b->poller, b->fd_ptr);
	else if (len)
		g_string_append_len(b->buf, s, len);

	mutex_unlock(&b->lock);
}
