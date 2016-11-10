#include "stream.h"
#include <glib.h>
#include <pthread.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <assert.h>
#include "metafile.h"
#include "epoll.h"
#include "log.h"
#include "main.h"


// stream is locked
void stream_close(stream_t *stream) {
	if (stream->fd == -1)
		return;
	epoll_del(stream->fd);
	close(stream->fd);
	stream->fd = -1;
}

void stream_free(stream_t *stream) {
	g_slice_free1(sizeof(*stream), stream);
}


static void stream_handler(handler_t *handler) {
	stream_t *stream = handler->ptr;

	//dbg("poll event for %s", stream->name);

	pthread_mutex_lock(&stream->lock);

	if (stream->fd == -1)
		goto out;

	char buf[65535];
	int ret = read(stream->fd, buf, sizeof(buf));
	if (ret == 0) {
		ilog(LOG_INFO, "EOF on stream %s", stream->name);
		stream_close(stream);
		goto out;
	}
	else if (ret < 0) {
		ilog(LOG_INFO, "Read error on stream %s: %s", stream->name, strerror(errno));
		stream_close(stream);
		goto out;
	}

out:
	pthread_mutex_unlock(&stream->lock);
}


// mf is locked
void stream_open(metafile_t *mf, unsigned long id, char *name) {
	dbg("opening stream %lu/%s", id, name);

	if (mf->streams->len <= id)
		g_ptr_array_set_size(mf->streams, id + 1);
	assert(g_ptr_array_index(mf->streams, id) == NULL);
	stream_t *stream = g_slice_alloc0(sizeof(*stream));
	g_ptr_array_index(mf->streams, id) = stream;

	pthread_mutex_init(&stream->lock, NULL);
	stream->name = g_string_chunk_insert(mf->gsc, name);
	stream->id = id;

	char fnbuf[PATH_MAX];
	snprintf(fnbuf, sizeof(fnbuf), "%s/%s/%s", PROC_DIR, mf->parent, name);

	stream->fd = open(fnbuf, O_RDONLY | O_NONBLOCK);
	if (stream->fd == -1) {
		ilog(LOG_ERR, "Failed to open kernel stream %s: %s", fnbuf, strerror(errno));
		return;
	}

	// add to epoll
	stream->handler.ptr = stream;
	stream->handler.func = stream_handler;
	epoll_add(stream->fd, EPOLLIN, &stream->handler);
}
