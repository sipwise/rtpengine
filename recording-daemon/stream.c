#include "stream.h"
#include <glib.h>
#include <pthread.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <libavformat/avformat.h>
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
static stream_t *stream_get(metafile_t *mf, unsigned long id) {
	if (mf->streams->len <= id)
		g_ptr_array_set_size(mf->streams, id + 1);
	stream_t *ret = g_ptr_array_index(mf->streams, id);
	if (ret)
		goto out;

	ret = g_slice_alloc0(sizeof(*ret));
	g_ptr_array_index(mf->streams, id) = ret;
	pthread_mutex_init(&ret->lock, NULL);
	ret->fd = -1;
	ret->id = id;

out:
	return ret;
}


// mf is locked
void stream_open(metafile_t *mf, unsigned long id, char *name) {
	dbg("opening stream %lu/%s", id, name);

	stream_t *stream = stream_get(mf, id);

	stream->name = g_string_chunk_insert(mf->gsc, name);

	char fnbuf[PATH_MAX];
	snprintf(fnbuf, sizeof(fnbuf), "%s/%s/%s", PROC_DIR, mf->parent, name);

	stream->fd = open(fnbuf, O_RDONLY | O_NONBLOCK);
	if (stream->fd == -1) {
		ilog(LOG_ERR, "Failed to open kernel stream %s: %s", fnbuf, strerror(errno));
		return;
	}

	stream->avinf = av_find_input_format("rtp");
	ilog(LOG_DEBUG, "avinf %p", stream->avinf);

	stream->avfctx = avformat_alloc_context();
	unsigned char *buf = av_malloc(1024); // ?
	stream->avfctx->pb = avio_alloc_context(buf, 1024, 1, NULL, NULL, NULL, NULL);
	int ret = avformat_open_input(&stream->avfctx, "", stream->avinf, NULL);
	ilog(LOG_DEBUG, "ret %i avfctx %p", ret, stream->avfctx);

	// add to epoll
	stream->handler.ptr = stream;
	stream->handler.func = stream_handler;
	epoll_add(stream->fd, EPOLLIN, &stream->handler);
}
