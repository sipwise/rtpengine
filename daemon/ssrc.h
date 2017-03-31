#ifndef _SSRC_H_
#define _SSRC_H_


#include <sys/types.h>
#include <glib.h>
#include "compat.h"
#include "aux.h"




struct call;
struct timeval;



struct ssrc_hash {
	GHashTable *ht;
	rwlock_t lock;
};
struct ssrc_ctx {
	// XXX lock this?
	u_int64_t srtp_index;
	// XXX move entire crypto context in here?
};
struct ssrc_entry {
	mutex_t lock;
	u_int32_t ssrc;
	struct ssrc_ctx input_ctx,
			output_ctx;
	GQueue sender_reports;
};
enum ssrc_dir {
	SSRC_DIR_INPUT  = G_STRUCT_OFFSET(struct ssrc_entry, input_ctx),
	SSRC_DIR_OUTPUT = G_STRUCT_OFFSET(struct ssrc_entry, output_ctx),
};

struct ssrc_sender_report {
	u_int32_t ssrc;
	u_int32_t ntp_msw;
	u_int32_t ntp_lsw;
	u_int32_t timestamp;
	u_int32_t packet_count;
	u_int32_t octet_count;
	double ntp_ts;
};
struct ssrc_sender_report_item {
	struct timeval received;
	u_int32_t ntp_middle_bits; // to match up with rr->lsr
	struct ssrc_sender_report report;
};

struct ssrc_receiver_report {
	u_int32_t from;
	u_int32_t ssrc;
	unsigned char fraction_lost;
	u_int32_t packets_lost;
	u_int32_t high_seq_received;
	u_int32_t jitter;
	u_int32_t lsr;
	u_int32_t dlsr;
};
struct ssrc_receiver_report_item {
	struct timeval received;
	struct ssrc_receiver_report report;
};




void free_ssrc_hash(struct ssrc_hash **);
struct ssrc_hash *create_ssrc_hash(void);

struct ssrc_entry *find_ssrc(u_int32_t, struct ssrc_hash *); // returns NULL if not found
struct ssrc_entry *get_ssrc(u_int32_t, struct ssrc_hash * /* , int *created */); // creates new entry if not found
//void add_ssrc_entry(struct ssrc_entry *, struct ssrc_hash *); // XXX static
//struct ssrc_entry *create_ssrc_entry(u_int32_t);
struct ssrc_ctx *get_ssrc_ctx(u_int32_t, struct ssrc_hash *, enum ssrc_dir); // creates new entry if not found


void ssrc_sender_report(struct call *, const struct ssrc_sender_report *, const struct timeval *);
void ssrc_receiver_report(struct call *, const struct ssrc_receiver_report *,
		const struct timeval *);



#endif
