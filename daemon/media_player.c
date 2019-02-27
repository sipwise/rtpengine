#include "media_player.h"
#include <glib.h>
#include <libavformat/avformat.h>
#include <libavcodec/avcodec.h>
#include "obj.h"
#include "log.h"
#include "timerthread.h"
#include "call.h"
#include "str.h"



static struct timerthread media_player_thread;



// appropriate lock must be held
static void media_player_shutdown(struct media_player *mp) {
	ilog(LOG_DEBUG, "shutting down media_player");
	timerthread_obj_deschedule(&mp->tt_obj);
	avformat_free_context(mp->fmtctx);
	mp->fmtctx = NULL;
}


static void __media_player_free(void *p) {
	struct media_player *mp = p;

	ilog(LOG_DEBUG, "freeing media_player");

	media_player_shutdown(mp);
	mutex_destroy(&mp->lock);
}


// call->master_lock held in W
struct media_player *media_player_new(struct call_monologue *ml) {
	ilog(LOG_DEBUG, "creating media_player");

	struct media_player *mp = obj_alloc0("media_player", sizeof(*mp), __media_player_free);

	mp->tt_obj.tt = &media_player_thread;
	mutex_init(&mp->lock);
	mp->call = obj_get(ml->call);
	mp->ml = ml;

	av_init_packet(&mp->pkt);
	mp->pkt.data = NULL;
	mp->pkt.size = 0;

	return mp;
}


// appropriate lock must be held
static void media_player_read_packet(struct media_player *mp) {
	int ret = av_read_frame(mp->fmtctx, &mp->pkt);
	if (ret < 0) {
		if (ret == AVERROR_EOF) {
			ilog(LOG_DEBUG, "EOF reading from media stream");
			return;
		}
		ilog(LOG_ERR, "Error while reading from media stream");
		return;
	}

	ilog(LOG_DEBUG, "read media packet: duration %llu", (unsigned long long) mp->pkt.duration);
	abort();

	av_packet_unref(&mp->pkt);
}


// call->master_lock held in W
int media_player_play_file(struct media_player *mp, const str *file) {
	media_player_shutdown(mp);

	char file_s[PATH_MAX];
	snprintf(file_s, sizeof(file_s), STR_FORMAT, STR_FMT(file));

	int ret = avformat_open_input(&mp->fmtctx, file_s, NULL, NULL);
	if (ret < 0)
		return -1;

	media_player_read_packet(mp);

	return 0;
}


static void media_player_run(void *ptr) {
	struct media_player *mp = ptr;
	struct call *call = mp->call;

	ilog(LOG_DEBUG, "running scheduled media_player");

	rwlock_lock_r(&call->master_lock);

	//..

	rwlock_unlock_r(&call->master_lock);
}


void media_player_init(void) {
	timerthread_init(&media_player_thread, media_player_run);
}


void media_player_loop(void *p) {
	timerthread_run(&media_player_thread);
}
