#ifndef _TYPES_H_
#define _TYPES_H_


#include <pthread.h>
#include <sys/types.h>
#include <glib.h>
#include "str.h"


struct iphdr;
struct ip6_hdr;
struct udphdr;
struct rtp_header;


struct handler_s;
typedef struct handler_s handler_t;
struct metafile_s;
typedef struct metafile_s metafile_t;
struct decoder_s;
typedef struct decoder_s decoder_t;
struct output_s;
typedef struct output_s output_t;
struct mix_s;
typedef struct mix_s mix_t;


typedef void handler_func(handler_t *);


struct handler_s {
	handler_func *func;
	void *ptr;
};


struct stream_s {
	pthread_mutex_t lock;
	char *name;
	metafile_t *metafile;
	unsigned long id;
	int fd;
	handler_t handler;
};
typedef struct stream_s stream_t;


struct packet_s {
	void *buffer;
	// pointers into buffer
	struct iphdr *ip;
	struct ip6_hdr *ip6;
	struct udphdr *udp;
	int seq;
	struct rtp_header *rtp;
	str payload;

};
typedef struct packet_s packet_t;


struct ssrc_s {
	pthread_mutex_t lock;
	metafile_t *metafile;
	unsigned long ssrc;
	GTree *packets; // contains packet_t objects
	int seq; // next expected seq
	decoder_t *decoders[128];
	output_t *output;
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
	GHashTable *ssrc_hash; // contains ssrc_t objects

	pthread_mutex_t mix_lock;
	mix_t *mix;
	output_t *mix_out;

	pthread_mutex_t payloads_lock;
	char *payload_types[128];
};


#endif
