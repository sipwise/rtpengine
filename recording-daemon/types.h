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
#include "containers.h"


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
	unsigned int forwarding_on:1;
	double start_time;
	unsigned int media_sdp_id;
	unsigned int channel_slot;
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
	uint64_t tls_in_pts;
	AVFrame *tls_silence_frame;
	//BIO *bio;
	SSL_CTX *ssl_ctx;
	SSL *ssl;
	struct streambuf *tls_fwd_stream;
	struct poller tls_fwd_poller;
	unsigned int sent_intro:1;
};
typedef struct ssrc_s ssrc_t;


struct tag_s {
	unsigned long id;
	char *name;
	char *label;
	char *metadata;
};
typedef struct tag_s tag_t;


INLINE void str_q_free(str_q *q) {
	t_queue_clear_full(q, str_free);
	t_queue_free(q);
}
TYPED_GHASHTABLE(metadata_ht, str, str_q, str_hash, str_equal, str_free, str_q_free)


struct metafile_s {
	pthread_mutex_t lock;
	char *name;
	char *parent;
	char *call_id;
	char *random_tag;
	char *metadata;
	metadata_ht metadata_parsed;
	char *output_dest;
	char *output_path;
	char *output_pattern;
	off_t pos;
	unsigned long long db_id;
	unsigned int db_streams;
	double start_time;

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
	char *payload_formats[128];
	int payload_ptimes[128];
	int media_ptimes[4];

	unsigned int recording_on:1;
	unsigned int forwarding_on:1;
	unsigned int discard:1;
	unsigned int db_metadata_done:1;
	unsigned int skip_db:1;
};


struct output_s {
	char *full_filename, // path + filename
		*file_path,
		*file_name,
		*filename; // path + filename + suffix
	const char *file_format;
	const char *kind; // "mixed" or "single"
	unsigned long long db_id;
	gboolean skip_filename_extension;
	unsigned int channel_mult;
	double start_time;

	AVFormatContext *fmtctx;
	AVStream *avst;
	encoder_t *encoder;
	format_t requested_format,
		 actual_format;
};


struct decode_s {
	decoder_t *dec;
	resample_t mix_resampler;
	unsigned int mixer_idx;
};



#endif
