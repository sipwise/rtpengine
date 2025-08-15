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
#include "str.h"
#include "codeclib.h"
#include "custom_poller.h"
#include "socket.h"
#include "containers.h"


struct iphdr;
struct ip6_hdr;
struct udphdr;
struct rtp_header;
struct streambuf;


typedef struct handler_s handler_t;
typedef struct metafile_s metafile_t;
typedef struct output_s output_t;
typedef struct mix_s mix_t;
typedef struct decode_s decode_t;
typedef struct packet_s packet_t;
typedef struct stream_s stream_t;
typedef struct ssrc_s ssrc_t;
typedef struct sink_s sink_t;
typedef struct tls_fwd_s tls_fwd_t;


typedef void handler_func(handler_t *);


struct handler_s {
	handler_func *func;
	void *ptr;
};


struct sink_s {
	bool (*add)(sink_t *, AVFrame *);
	bool (*config)(sink_t *, const format_t *requested_format, format_t *actual_format);

	union {
		output_t *output;
		ssrc_t *ssrc;
		tls_fwd_t **tls_fwd;
	};
	union {
		mix_t **mix;
	};

	resample_t resampler;
	format_t format;

	union {
		unsigned int mixer_idx;
	};
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
	int64_t start_time_us;
	unsigned int media_sdp_id;
	unsigned int channel_slot;
};


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


struct tls_fwd_s {
	sink_t sink;
	format_t format;
	socket_t sock;
	uint64_t in_pts;
	AVFrame *silence_frame;
	SSL_CTX *ssl_ctx;
	SSL *ssl;
	struct streambuf *stream;
	struct poller poller;
	ssrc_t *ssrc;
	metafile_t *metafile;
	unsigned int sent_intro:1;
};


struct ssrc_s {
	pthread_mutex_t lock;
	stream_t *stream;
	metafile_t *metafile;
	unsigned long ssrc;
	packet_sequencer_t sequencer;
	decode_t *decoders[128];
	output_t *output;
	tls_fwd_t *tls_fwd;
};


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
	int64_t start_time_us;
	unsigned int media_rec_slots;

	GStringChunk *gsc; // XXX limit max size

	GPtrArray *streams;
	GPtrArray *tags;
	GHashTable *ssrc_hash; // contains ssrc_t objects

	pthread_mutex_t mix_lock;
	mix_t *mix;
	output_t *mix_out;

	mix_t *tls_mix;
	tls_fwd_t *mix_tls_fwd;

	int forward_fd;
	int forward_count;
	int forward_failed;

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
	sink_t sink;

	char *full_filename, // path + filename
		*file_path,
		*file_name,
		*filename; // path + filename + suffix
	const char *file_format;
	const char *kind; // "mixed" or "single"
	unsigned long long db_id;
	gboolean skip_filename_extension;
	int64_t start_time_us;

	FILE *fp;
	char *iobuf;
	GString *membuf;
	size_t mempos;
	AVIOContext *avioctx;
	AVFormatContext *fmtctx;
	AVStream *avst;
	encoder_t *encoder;
	format_t requested_format,
		 actual_format;

	GString *content;
};


struct decode_s {
	decoder_t *dec;
	sink_t mix_sink;
	sink_t tls_mix_sink;
};



#endif
