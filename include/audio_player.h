#ifndef _AUDIO_PLAYER_H_
#define _AUDIO_PLAYER_H_

#ifdef WITH_TRANSCODING

#include <stdbool.h>
#include <libavutil/frame.h>
#include <stdint.h>


/*
 * Similar to the existing media_player, but instead of simply producing
 * its own standalone output media stream, the audio_player takes over the
 * entire media stream flowing to the receiver, including media forwarded
 * from the opposite side of the call, as well as media produced by the
 * media_player.
 */

struct audio_player;
struct call_media;
struct rtp_payload_type;

bool audio_player_setup(struct call_media *, const struct rtp_payload_type *,
		unsigned int size_ms, unsigned int delay_ms);
void audio_player_activate(struct call_media *);
void audio_player_free(struct call_media *);

void audio_player_start(struct call_media *);
void audio_player_stop(struct call_media *);
bool audio_player_is_active(struct call_media *);
bool audio_player_pt_match(struct call_media *, const struct rtp_payload_type *);

void audio_player_add_frame(struct audio_player *, uint32_t ssrc, AVFrame *);

#else

INLINE void audio_player_start(struct call_media *m) { }
INLINE void audio_player_free(struct call_media *m) { }
INLINE void audio_player_stop(struct call_media *m) { }
INLINE void audio_player_activate(struct call_media *m) { }

#endif

#endif
