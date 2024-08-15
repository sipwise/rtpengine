#ifdef WITH_TRANSCODING

#include "audio_player.h"
#include "call.h"
#include "media_player.h"
#include "mix_buffer.h"
#include "codec.h"


struct audio_player {
	struct media_player *mp;
	struct mix_buffer mb;
	struct timeval last_run;

	unsigned int ptime_us;
	unsigned int ptime; // in samples

	unsigned long long pts;
};


// call is locked in R and mp is locked
static bool audio_player_run(struct media_player *mp) {
	if (!mp || !mp->media)
		return false;

	struct audio_player *ap = mp->media->audio_player;
	if (!ap || !ap->ptime_us)
		return false;

	ap->last_run = rtpe_now; // equals mp->next_run

	unsigned int size;
	void *buf = mix_buffer_read_fast(&ap->mb, ap->ptime, &size);
	if (!buf) {
		if (!size) {
			// error or not active: just reschedule
			timeval_add_usec(&mp->next_run, ap->ptime_us);
			timerthread_obj_schedule_abs(&mp->tt_obj, &mp->next_run);
			return false;
		}
		buf = g_alloca(size);
		mix_buffer_read_slow(&ap->mb, buf, ap->ptime);
	}

	media_player_add_packet(mp, buf, size, ap->ptime_us, ap->pts);
	ap->pts += ap->ptime;

	return false;
}

// call locked in W
bool audio_player_setup(struct call_media *m, const rtp_payload_type *dst_pt,
		unsigned int size_ms, unsigned int delay_ms, str_case_value_ht codec_set)
{
	if (!dst_pt)
		return false;
	unsigned int bufsize_ms = size_ms;
	if (!bufsize_ms)
		bufsize_ms = rtpe_config.audio_buffer_length;
	if (!bufsize_ms)
		return false;

	unsigned int clockrate = fraction_mult(dst_pt->clock_rate, &dst_pt->codec_def->default_clockrate_fact);

	unsigned int ptime_ms = m->ptime;
	if (!ptime_ms)
		ptime_ms = 20;
	unsigned int ptime_us = ptime_ms * 1000;
	unsigned int ptime_smp = ptime_ms * clockrate / 1000; // in samples

	// TODO: shortcut this to avoid the detour of avframe -> avpacket -> avframe (all in s16)
	rtp_payload_type src_pt = {
		.payload_type = -1,
		.encoding = STR_CONST("PCM-S16LE"), // XXX support flp
		.channels = dst_pt->channels,
		.clock_rate = clockrate,
		.ptime = ptime_ms,
	};

	struct audio_player *ap;
	struct media_player *mp = NULL;

	// check if objects exists and parameters are still the same

	if ((ap = m->audio_player) && (mp = ap->mp)) {
		if (!media_player_pt_match(mp, &src_pt, dst_pt))
			{ /* do reset below */ }
		if (ap->ptime != ptime_smp || ap->ptime_us != ptime_us)
			{ /* do reset below */ }
		else // everything matched
			return true;

		ilogs(transcoding, LOG_DEBUG, "Resetting audio player for new parameters");
	}
	else
		ilogs(transcoding, LOG_DEBUG, "Creating new audio player");

	// create ap and mp objects, or reset them if needed

	if (ap) {
		mix_buffer_destroy(&ap->mb);
		ZERO(ap->mb);
	}
	else
		ap = m->audio_player = g_slice_alloc0(sizeof(*m->audio_player));

	if (mp)
		media_player_stop(mp);
	else {
		media_player_new(&mp, m->monologue);
		ap->mp = mp;
	}
	if (!mp)
		goto error;

	// set everything up

	src_pt.codec_def = codec_find_by_av(AV_CODEC_ID_PCM_S16LE), // XXX shortcut this?

	mp->run_func = audio_player_run;

	ap->ptime_us = ptime_us;
	ap->ptime = ptime_smp;

	if (media_player_setup(mp, &src_pt, dst_pt, codec_set))
		goto error;

	bufsize_ms = MAX(bufsize_ms, ptime_ms * 2); // make sure the buf size is at least 2 frames

	mix_buffer_init_active(&ap->mb, AV_SAMPLE_FMT_S16, clockrate, dst_pt->channels, bufsize_ms, delay_ms,
			false);

	return true;

error:
	audio_player_free(m);
	return false;
}


void audio_player_activate(struct call_media *m) {
	if (!m)
		return;
	struct audio_player *ap = m->audio_player;
	if (!ap)
		return;
	mix_buffer_activate(&ap->mb);
}


// call locked in W
void audio_player_start(struct call_media *m) {
	struct audio_player *ap;

	if (!m || !(ap = m->audio_player))
		return;

	struct media_player *mp = ap->mp;
	if (!mp)
		return;

	media_player_set_media(mp, m);

	if (mp->next_run.tv_sec) // already running?
		return;

	ilogs(transcoding, LOG_DEBUG, "Starting audio player");

	ap->last_run = rtpe_now;

	mp->next_run = rtpe_now;
	timeval_add_usec(&mp->next_run, ap->ptime_us);
	timerthread_obj_schedule_abs(&mp->tt_obj, &mp->next_run);

}


void audio_player_add_frame(struct audio_player *ap, uint32_t ssrc, AVFrame *frame) {
	bool ret = mix_buffer_write(&ap->mb, ssrc, frame->extended_data[0], frame->nb_samples);
	if (!ret)
		ilogs(transcoding, LOG_WARN | LOG_FLAG_LIMIT, "Failed to add samples to mix buffer");
	av_frame_free(&frame);
}


void audio_player_stop(struct call_media *m) {
	struct audio_player *ap = m->audio_player;
	if (!ap)
		return;
	ilogs(transcoding, LOG_DEBUG, "Stopping audio player");
	media_player_stop(ap->mp);
	media_player_put(&ap->mp);
}


bool audio_player_is_active(struct call_media *m) {
	if (!m->audio_player)
		return false;
	if (!m->audio_player->mp)
		return false;
	if (!m->audio_player->mp->next_run.tv_sec)
		return false;
	return true;
}


bool audio_player_pt_match(struct call_media *m, const rtp_payload_type *pt) {
	return rtp_payload_type_eq_exact(&m->audio_player->mp->coder.handler->dest_pt, pt);
}


void audio_player_free(struct call_media *m) {
	struct audio_player *ap = m->audio_player;
	if (!ap)
		return;
	mix_buffer_destroy(&ap->mb);
	media_player_put(&ap->mp);
	g_slice_free1(sizeof(*ap), ap);
	m->audio_player = NULL;
}

#endif
