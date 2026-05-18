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

#endif
