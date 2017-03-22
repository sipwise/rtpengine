#ifndef _SSRC_H_
#define _SSRC_H_


#include <sys/types.h>
#include <glib.h>
#include "compat.h"
#include "aux.h"




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
	// XXX lock this?
	u_int32_t ssrc;
	struct ssrc_ctx input_ctx,
			output_ctx;
};
enum ssrc_dir {
	SSRC_DIR_INPUT  = G_STRUCT_OFFSET(struct ssrc_entry, input_ctx),
	SSRC_DIR_OUTPUT = G_STRUCT_OFFSET(struct ssrc_entry, output_ctx),
};




void free_ssrc_hash(struct ssrc_hash **);
struct ssrc_hash *create_ssrc_hash(void);

struct ssrc_entry *find_ssrc(u_int32_t, struct ssrc_hash *); // returns NULL if not found
struct ssrc_entry *get_ssrc(u_int32_t, struct ssrc_hash * /* , int *created */); // creates new entry if not found
//void add_ssrc_entry(struct ssrc_entry *, struct ssrc_hash *); // XXX static
//struct ssrc_entry *create_ssrc_entry(u_int32_t);
struct ssrc_ctx *get_ssrc_ctx(u_int32_t, struct ssrc_hash *, enum ssrc_dir); // creates new entry if not found



#endif
