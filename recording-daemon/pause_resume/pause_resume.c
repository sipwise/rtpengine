#include "../types.h"
#include "../metafile.h"
#include "../decoder.h"
#include "../epoll.h"
#include "../log.h"
#include "../timer.h"
#include "maskbeep.h"

static long get_current_milliseconds(void) {
    struct timeval tp;
    gettimeofday(&tp, NULL);
    return tp.tv_sec * 1000 + tp.tv_usec / 1000;
}

static const unsigned char* fill_mask_data(unsigned char* mask_data, int len, const unsigned char * pMask) {
    if (pMaskBeepEnd - pMask >= len)
    {
        memcpy(mask_data, pMask, len);
        pMask += len;
        if (pMask == pMaskBeepEnd)
            pMask = maskbeep;
    }
    else{
        int firstPartLen = pMaskBeepEnd - pMask;
        memcpy(mask_data, pMask, firstPartLen);
        int secondPartLen = len - firstPartLen;
        pMask = maskbeep;
        memcpy(mask_data + firstPartLen, pMask, secondPartLen);
        pMask += secondPartLen;
    }
    return pMask;
}

static void insert_mask_beep(pause_ctrl_t *pr_ctrl, long timediff) {
    int nb_samples = 160;
    int clockrate = 8000; // clockrate for maskbeep data is 8000
    uint64_t target_pts = timediff * (clockrate / 1000);
    int offset_mask_beep = pr_ctrl->last_mask_pts % MASK_BEEP_LENGTH;
    int shift_ts = target_pts - pr_ctrl->last_mask_pts;
    //int pkt_num = (target_pts - dec->pts) / nb_samples;

    dbg("====> metafile_insert_mask_beep: timediff=%lu,  target_pts=%llu, start_pos=%llu, shift_ts=%d",
      timediff,
      (long long unsigned int)target_pts,
      (long long unsigned int)offset_mask_beep,
      shift_ts);
    unsigned char mask_data[nb_samples];
    int len = nb_samples;
    const unsigned char* pMask = maskbeep + offset_mask_beep;
    while (shift_ts > 0){
        if (shift_ts<len)
            len = shift_ts;
        dbg("====> insert maskbeep[%d:%d]", (int)(pMask - maskbeep), len);
        pMask = fill_mask_data(mask_data, len, pMask);
        str pMaskData;
        pMaskData.s = (char*)mask_data;
        pMaskData.len = len;
        metafile_traverse_decoders(pr_ctrl->mf, decoder_append_data, &pMaskData);
        shift_ts -= len;
    }
    pr_ctrl->last_mask_pts = target_pts;
}

static void pause_timer_handler(handler_t *handler) {
    uint64_t exp = 0;
    pause_ctrl_t *pr_ctrl = handler->ptr;
    if (pr_ctrl == NULL)
        return;
    read(pr_ctrl->timer_fd, &exp, sizeof(uint64_t));
    if (pr_ctrl->mf == NULL)
        return;
    long now = get_current_milliseconds();
    pthread_mutex_lock(&pr_ctrl->mf->lock);
    insert_mask_beep(pr_ctrl, now - pr_ctrl->pause_start_time);
    pthread_mutex_unlock(&pr_ctrl->mf->lock);
}

#define CHECK_MASK_BEEP_INTERVAL 200  // miliseconds
static int pause_ctrl_timer_init(pause_ctrl_t *pr_ctrl) {
    if (pr_ctrl->timer_fd != -1){
        ilog(LOG_WARN, "recording has been already paused");
        return 0;
    }

    pr_ctrl->timer_handler.ptr = pr_ctrl;
    pr_ctrl->timer_handler.func = pause_timer_handler;
    pr_ctrl->timer_fd = timerfd_init(&pr_ctrl->timer_handler, CHECK_MASK_BEEP_INTERVAL);
    return pr_ctrl->timer_fd > 0 ? 0 : -1;
}

static int pause_ctrl_timer_destroy(pause_ctrl_t *pr_ctrl)
{
    if (pr_ctrl->timer_fd != -1) {
        timerfd_destroy(pr_ctrl->timer_fd);
        pr_ctrl->timer_fd = -1;
    }
    return 0;
}

pause_ctrl_t * pause_ctrl_new(metafile_t* mf){
    pause_ctrl_t * pr_ctrl = g_slice_alloc0(sizeof(pause_ctrl_t));
    pr_ctrl->mf = mf;
    pr_ctrl->timer_fd = -1;
    pr_ctrl->pause_start_time = 0;
    pr_ctrl->last_mask_pts = -1;
    return pr_ctrl;
}

void pause_ctrl_destroy(pause_ctrl_t *pr_ctrl){
    pause_ctrl_timer_destroy(pr_ctrl);
    g_slice_free1(sizeof(pause_ctrl_t), pr_ctrl);
}

void pause_ctrl_unlock_mf(pause_ctrl_t *pr_ctrl){
    pthread_mutex_unlock(&pr_ctrl->mf->lock);
}


static pause_ctrl_t * pause_ctrl_get(const char* call_id){
    metafile_t *mf = metafile_get_by_call_id(call_id);
    if (mf == NULL){
        ilog(LOG_WARN, "Call %s does not exist", call_id);
        return NULL;
    }
    if (mf->pause_controller == NULL)
        mf->pause_controller = pause_ctrl_new(mf);
    pause_ctrl_t *result = mf->pause_controller;
    return result;
}

void pause_ctrl_stop_recording(char *call_id){
    pause_ctrl_t * pr_ctrl = pause_ctrl_get(call_id);
    pause_ctrl_timer_init(pr_ctrl);
    pr_ctrl->pause_start_time = get_current_milliseconds();
    pr_ctrl->last_mask_pts = 0;
    pause_ctrl_unlock_mf(pr_ctrl);
}

void pause_ctrl_start_recording(char *call_id){
    pause_ctrl_t * pr_ctrl = pause_ctrl_get(call_id);
    pause_ctrl_timer_destroy(pr_ctrl);
    pr_ctrl->pause_start_time = -1;
    pause_ctrl_unlock_mf(pr_ctrl);
}




