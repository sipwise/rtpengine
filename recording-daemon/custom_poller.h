#ifndef __POLLER_H__
#define __POLLER_H__

#include <stdbool.h>

// dummy poller
struct poller {
	enum {
		PS_CLOSED = 0,
		PS_CONNECTING,
		PS_HANDSHAKE,
		PS_OPEN,
		PS_WRITE_BLOCKED,
		PS_ERROR,
	} state;
};

void poller_blocked(struct poller *, void *);
void poller_error(struct poller *, void *);
bool poller_isblocked(struct poller *, void *);

#define rtpe_poller_isblocked poller_isblocked
#define rtpe_poller_blocked poller_blocked
#define rtpe_poller_error poller_error

#endif
