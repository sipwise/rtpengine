#include "common.h"


#if RTP_LOOP_PROTECT

bool loop_detect(struct loop_protector *lp, const char *buf, size_t len, int64_t tv) {
	for (unsigned int i = 0; i < RTP_LOOP_PACKETS; i++) {
		if (lp->lp_buf[i].len != len)
			continue;
		if (memcmp(lp->lp_buf[i].buf, buf, MIN(len, RTP_LOOP_PROTECT)))
			continue;

		dbg_int("packet dupe");

		/* not a loop if duplicates arrive more than 1s apart */
		if (tv - lp->lp_buf[i].recv_us > 1000000LL) {
			dbg_int("duplicate packet too old to indicate a loop, resetting count");
			lp->lp_count = 0;
			lp->lp_buf[i].recv_us = tv;
			return true;
		}

		lp->lp_buf[i].recv_us = tv;

		if (lp->lp_count >= RTP_LOOP_MAX_COUNT)
			return false;

		lp->lp_count++;
		return true;
	}

	/* not a dupe */
	lp->lp_count = 0;
	lp->lp_buf[lp->lp_idx].len = len;
	memcpy(lp->lp_buf[lp->lp_idx].buf, buf, MIN(len, RTP_LOOP_PROTECT));
	lp->lp_buf[lp->lp_idx].recv_us = tv;
	lp->lp_idx = (lp->lp_idx + 1) % RTP_LOOP_PACKETS;

	return true;
}

#endif
