#ifndef _TYPES_H_
#define _TYPES_H_


#include <pthread.h>
#include <sys/types.h>
#include <glib.h>
#include <libavutil/frame.h>
#include <libavformat/avformat.h>
#include <libavutil/channel_layout.h>
#include <libavutil/samplefmt.h>
#include <libavutil/audio_fifo.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include "str.h"
#include "codeclib.h"
#include "poller.h"
#include "socket.h"


struct iphdr;
struct ip6_hdr;
struct udphdr;
struct rtp_header;
struct streambuf;


struct handler_s;
typedef struct handler_s handler_t;
struct metafile_s;
typedef struct metafile_s metafile_t;
struct output_s;
typedef struct output_s output_t;
struct mix_s;
typedef struct mix_s mix_t;
struct decode_s;
typedef struct decode_s decode_t;


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
	unsigned long tag;
	int fd;
	handler_t handler;
	int forwarding_on:1;
};
typedef struct stream_s stream_t;


struct packet_s {
	seq_packet_t p; // must be first
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
	pthread_mutex_t lock;
	stream_t *stream;
	metafile_t *metafile;
	unsigned long ssrc;
	packet_sequencer_t sequencer;
	decode_t *decoders[128];
	output_t *output;

	// TLS output
	format_t tls_fwd_format;
	resample_t tls_fwd_resampler;
	socket_t tls_fwd_sock;
	//BIO *bio;
	SSL_CTX *ssl_ctx;
	SSL *ssl;
	struct streambuf *tls_fwd_stream;
	struct poller tls_fwd_poller;
	int sent_intro:1;
};
typedef struct ssrc_s ssrc_t;


struct tag_s {
	unsigned long id;
	char *name;
	char *label;
};
typedef struct tag_s tag_t;


struct metafile_s {
	pthread_mutex_t lock;
	char *name;
	char *parent;
	char *call_id;
	char *metadata;
	char *metadata_db;
	off_t pos;
	unsigned long long db_id;

	GStringChunk *gsc; // XXX limit max size

	GPtrArray *streams;
	GPtrArray *tags;
	GHashTable *ssrc_hash; // contains ssrc_t objects

	pthread_mutex_t mix_lock;
	mix_t *mix;
	output_t *mix_out;

	int forward_fd;
	volatile gint forward_count;
	volatile gint forward_failed;

	pthread_mutex_t payloads_lock;
	char *payload_types[128];
	int payload_ptimes[128];
	int media_ptimes[4];

	int recording_on:1;
	int forwarding_on:1;
};


struct output_s {
	char full_filename[PATH_MAX], // path + filename
		file_path[PATH_MAX],
		file_name[PATH_MAX];
	const char *file_format;
	unsigned long long db_id;

//	format_t requested_format,
//		 actual_format;

//	AVCodecContext *avcctx;
	AVFormatContext *fmtctx;
	AVStream *avst;
//	AVPacket avpkt;
//	AVAudioFifo *fifo;
//	int64_t fifo_pts; // pts of first data in fifo
//	int64_t mux_dts; // last dts passed to muxer
//	AVFrame *frame;
	encoder_t *encoder;
};


struct decode_s {
	decoder_t *dec;
	resample_t mix_resampler;
	unsigned int mixer_idx;
};



#endif
