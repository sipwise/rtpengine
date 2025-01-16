#ifndef _MEDIA_PLAYER_H_
#define _MEDIA_PLAYER_H_

#include <stdbool.h>

#include "auxlib.h"
#include "timerthread.h"
#include "str.h"
#include "types.h"
#include "control_ng.h"

struct call_media;
struct call_monologue;
struct codec_handler;
struct ssrc_ctx;
struct packet_stream;
struct codec_packet;
struct media_player;


typedef struct {
	long long start_pos;
	int repeat;
	long long duration_spent; /* in milliseconds */
	str_case_value_ht codec_set;
	unsigned int block_egress:1;
	str file, blob;
	long long db_id;
} media_player_opts_t;


#ifdef WITH_TRANSCODING

#include <libavformat/avformat.h>
#include <libavcodec/avcodec.h>

struct media_player_cache_entry;
struct media_player_media_file;

struct media_player_content_index {
	enum { MP_OTHER = 0, MP_FILE = 1, MP_DB, MP_BLOB } type;
	long long db_id;
	str file; // file name or binary blob
};


// returns true to indicate that playback is finished and codec handlers should be reset
typedef bool (*media_player_run_func)(struct media_player *);


struct media_player_coder {
	AVFormatContext *fmtctx;
	AVStream *avstream;
	unsigned long duration; // in milliseconds
	AVPacket *pkt;
	AVIOContext *avioctx;
	str blob;
	str read_pos;
	struct codec_handler *handler;
};

struct media_player {
	struct timerthread_obj tt_obj;
	mutex_t lock;
	media_player_run_func run_func;
	call_t *call;
	struct call_monologue *ml;
	struct call_media *media;
	struct packet_stream *sink;
	const struct streamhandler *crypt_handler;

	struct timeval next_run;

	media_player_opts_t opts;

	struct media_player_coder coder;
	struct media_player_content_index cache_index;
	struct media_player_cache_entry *cache_entry;
	unsigned int cache_read_idx;
	unsigned int kernel_idx;
	struct media_player_media_file *media_file;

	struct ssrc_ctx *ssrc_out;
	unsigned long seq;
	unsigned long buffer_ts;
	unsigned long sync_ts;
	struct timeval sync_ts_tv;
	long long last_frame_ts;
	bool moh;
};

INLINE void media_player_put(struct media_player **mp) {
	if (!*mp)
		return;
	obj_put(&(*mp)->tt_obj);
	*mp = NULL;
}
INLINE struct media_player *media_player_get(struct media_player *mp) {
	if (!mp)
		return NULL;
	obj_hold(&mp->tt_obj);
	return mp;
}

#else

INLINE void media_player_put(struct media_player **mp) {
}
INLINE struct media_player *media_player_get(struct media_player *mp) {
	return NULL;
}

#endif

struct send_timer {
	struct timerthread_queue ttq;
	call_t *call; // main reference that keeps this alive
	struct packet_stream *sink;
};


#define MPO(...) (media_player_opts_t){__VA_ARGS__}

void media_player_new(struct media_player **, struct call_monologue *);
bool media_player_add(struct media_player *mp, media_player_opts_t opts);
bool media_player_start(struct media_player *);
long long media_player_stop(struct media_player *);
bool media_player_is_active(struct call_monologue *);

int media_player_setup(struct media_player *mp, const rtp_payload_type *src_pt,
		const rtp_payload_type *dst_pt, str_case_value_ht codec_set);
void media_player_set_media(struct media_player *mp, struct call_media *media);
bool media_player_pt_match(const struct media_player *mp, const rtp_payload_type *src_pt,
		const rtp_payload_type *dst_pt);

void media_player_add_packet(struct media_player *mp, char *buf, size_t len,
		long long us_dur, unsigned long long pts);

const char * call_play_media_for_ml(struct call_monologue *ml,
		media_player_opts_t opts, sdp_ng_flags *flags);
long long call_stop_media_for_ml(struct call_monologue *ml);
bool call_ml_wants_moh(struct call_monologue *ml, enum ng_opmode opmode);
bool call_ml_stops_moh(struct call_monologue *from_ml, struct call_monologue *to_ml,
		enum ng_opmode opmode);
void call_ml_moh_handle_flags(struct call_monologue *from_ml, struct call_monologue *to_ml);
const char * call_check_moh(struct call_monologue *from_ml, struct call_monologue *to_ml,
	sdp_ng_flags *flags);

void media_player_init(void);
void media_player_free(void);
void media_player_launch(void);
bool media_player_preload_files(char **);
bool media_player_add_cached_file(str *name);
bool media_player_reload_file(str *name);
unsigned int media_player_reload_files(void);
bool media_player_add_db_media(unsigned long long);
bool media_player_reload_db_media(unsigned long long);
unsigned int media_player_reload_db_medias(void);
enum thread_looper_action media_player_refresh_timer(void);
bool media_player_preload_db(char **);
enum thread_looper_action media_player_refresh_db(void);
bool media_player_evict_file(str *name);
unsigned int media_player_evict_files(void);
bool media_player_evict_db_media(unsigned long long);
unsigned int media_player_evict_db_medias(void);
str_q media_player_list_files(void);
GQueue media_player_list_dbs(void);
GQueue media_player_list_caches(void);
bool media_player_get_file_times(const str *, time_t *mtime, time_t *atime);
bool media_player_get_db_times(unsigned long long, time_t *mtime, time_t *atime);
bool media_player_get_cache_times(unsigned long long, time_t *mtime, time_t *atime);
bool media_player_evict_cache(unsigned long long);
unsigned int media_player_evict_caches(void);
bool media_player_preload_cache(char **);
bool media_player_add_cache(unsigned long long);
bool media_player_reload_cache(unsigned long long);
unsigned int media_player_reload_caches(void);
enum thread_looper_action media_player_refresh_cache(void);
charp_q media_player_list_player_cache(void);
unsigned int media_player_evict_player_caches(void);
enum thread_looper_action media_player_expire(void);

struct send_timer *send_timer_new(struct packet_stream *);
void send_timer_push(struct send_timer *, struct codec_packet *);
void send_timer_launch(void);



INLINE void send_timer_put(struct send_timer **st) {
	if (!*st)
		return;
	obj_put(&(*st)->ttq.tt_obj);
	*st = NULL;
}


#endif
