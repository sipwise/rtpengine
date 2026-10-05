#ifndef _RTPE_COMMON_H_
#define _RTPE_COMMON_H_


#ifndef RTP_LOOP_PROTECT
#define RTP_LOOP_PROTECT	28 /* number of bytes */
#define RTP_LOOP_PACKETS	2  /* number of packets */
#define RTP_LOOP_MAX_COUNT	30 /* number of consecutively detected dupes to trigger protection */
#endif


#if RTP_LOOP_PROTECT

struct loop_entry {
	unsigned int		len;
	unsigned char		buf[RTP_LOOP_PROTECT];
	int64_t			recv_us;
};

struct loop_protector {
	unsigned int		lp_idx;
	struct loop_entry	lp_buf[RTP_LOOP_PACKETS];
	unsigned int		lp_count;
};

bool loop_detect(struct loop_protector *lp, const char *buf, size_t len, int64_t tv);

#endif


#endif
