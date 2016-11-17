#ifndef _TYPES_H_
#define _TYPES_H_


#include <pthread.h>
#include <sys/types.h>
#include <glib.h>
#include <pcre.h>
#include <libavformat/avformat.h>
#include "str.h"


struct iphdr;
struct ip6_hdr;
struct udphdr;
struct rtp_header;


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
	//AVInputFormat *avinf;
	//AVFormatContext *avfctx;
};
typedef struct stream_s stream_t;


struct packet_s {
	void *buffer;
	// pointers into buffer
	struct iphdr *ip;
	struct ip6_hdr *ip6;
	struct udphdr *udp;
	struct rtp_header *rtp;
	str payload;

};
typedef struct packet_s packet_t;


struct ssrc_s {
	unsigned long ssrc;
	GTree *packets; // contains packet_t objects
};
typedef struct ssrc_s ssrc_t;


struct metafile_s {
	pthread_mutex_t lock;
	char *name;
	char *parent;
	char *call_id;
	off_t pos;

	GStringChunk *gsc; // XXX limit max size

	GPtrArray *streams;
	char *payload_types[128];
	GHashTable *ssrc_hash; // contains ssrc_t objects
};
typedef struct metafile_s metafile_t;


// struct pcre_s {
// 	pcre *re;
// 	pcre_extra *extra;
// };
// typedef struct pcre_s pcre_t;


#endif
