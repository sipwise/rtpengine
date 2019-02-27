#ifndef _MEDIA_PLAYER_H_
#define _MEDIA_PLAYER_H_


#include <libavformat/avformat.h>
#include <libavcodec/avcodec.h>
#include "auxlib.h"
#include "timerthread.h"
#include "str.h"



struct call;
struct call_monologue;


struct media_player {
	struct timerthread_obj tt_obj;
	mutex_t lock;
	struct call *call;
	struct call_monologue *ml;

	struct timeval next_run;

	AVFormatContext *fmtctx;
	AVPacket pkt;
};


struct media_player *media_player_new(struct call_monologue *);
int media_player_play_file(struct media_player *, const str *);
void media_player_stop(struct media_player *);

void media_player_init(void);
void media_player_loop(void *);



INLINE void media_player_put(struct media_player **mp) {
	if (!*mp)
		return;
	obj_put(&(*mp)->tt_obj);
	*mp = NULL;
}


#endif
