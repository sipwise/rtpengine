#ifndef __POLLER_H__
#define __POLLER_H__



#include <sys/types.h>
#include <stdint.h>
#include <time.h>
#include <glib.h>
#include <stdbool.h>
#include "compat.h"
#include "auxlib.h"


#define MAX_RTP_PACKET_SIZE	8192
#define RTP_BUFFER_HEAD_ROOM	128
#define RTP_BUFFER_TAIL_ROOM	512
#define RTP_BUFFER_SIZE		(MAX_RTP_PACKET_SIZE + RTP_BUFFER_HEAD_ROOM + RTP_BUFFER_TAIL_ROOM)


struct obj;
struct sockaddr;


typedef void (*poller_func_t)(int, void *);

union poller_item_u64 {
	struct {
		int fd;
		int32_t gen;
	} __attribute__((packed));
	uint64_t u64;
};

struct poller_item {
	union poller_item_u64		u;
	struct obj			*obj;

	poller_func_t			readable;
	void				(*recv)(struct obj *, char *b, size_t len, const struct sockaddr *, int64_t);
	poller_func_t			writeable;
	poller_func_t			closed;
};

static_assert(sizeof(union poller_item_u64) == sizeof(uint64_t), "wrong packing of union poller_item_u64");

struct poller;

struct poller_thread {
	pid_t pid;

	struct poller *poller;

	// stats
	atomic64 wakeups;
	atomic64 items; // per wakeup
};

struct poller *poller_new(void);
void poller_free(struct poller **);
bool poller_add_item(struct poller *, struct poller_item *);
bool poller_del_item(struct poller *, int);
bool poller_del_item_callback(struct poller *, int, void (*)(void *), void *);

void poller_blocked(struct poller *, void *);
bool poller_isblocked(struct poller *, void *);
void poller_error(struct poller *, void *);

void poller_loop(struct poller_thread *);

extern bool (*rtpe_poller_add_item)(struct poller *, struct poller_item *);
extern bool (*rtpe_poller_del_item)(struct poller *, int);
extern bool (*rtpe_poller_del_item_callback)(struct poller *, int, void (*)(void *), void *);
extern void (*rtpe_poller_blocked)(struct poller *, void *);
extern bool (*rtpe_poller_isblocked)(struct poller *, void *);
extern void (*rtpe_poller_error)(struct poller *, void *);


#endif
