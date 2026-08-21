#ifndef __CALL_CHECKPOINT_H__
#define __CALL_CHECKPOINT_H__

#include <stdbool.h>
#include <stdint.h>
#include "str.h"

struct call;
struct call_monologue;
struct call_checkpoint;

uint64_t call_checkpoint_offer(struct call *, struct call_monologue *, struct call_monologue *, bool);
uint64_t call_checkpoint_answer(struct call *, struct call_monologue *, struct call_monologue *, bool *);
int call_checkpoint_rollback(struct call *, struct call_monologue *, struct call_monologue *,
		uint64_t, bool, uint64_t *);
void call_checkpoint_free_all(struct call *);
str call_checkpoint_serialize(struct call *, void **);
int call_checkpoint_deserialize(struct call *, const str *);

#endif
