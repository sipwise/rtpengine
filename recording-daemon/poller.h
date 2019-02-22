#ifndef __POLLER_H__
#define __POLLER_H__


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
int poller_isblocked(struct poller *, void *);
void poller_error(struct poller *, void *);


#endif
