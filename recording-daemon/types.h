#ifndef _TYPES_H_
#define _TYPES_H_


#include <pthread.h>
#include <sys/types.h>
#include <glib.h>


typedef struct handler_s handler_t;
typedef void handler_func(handler_t *);

struct handler_s {
	handler_func *func;
	void *ptr;
};

struct stream_s {
	pthread_mutex_t lock;
	char *name;
	unsigned long id;
	int fd;
	handler_t handler;
};
typedef struct stream_s stream_t;

struct metafile_s {
	pthread_mutex_t lock;
	char *name;
	char *parent;
	char *call_id;
	off_t pos;
	GStringChunk *gsc; // XXX limit max size
	GPtrArray *streams;
};
typedef struct metafile_s metafile_t;


#endif
