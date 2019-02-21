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

void poller_blocked(struct poller *, int);
int poller_isblocked(struct poller *, int);
void poller_error(struct poller *, int);


#endif
