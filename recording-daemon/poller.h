#ifndef __POLLER_H__
#define __POLLER_H__


// dummy poller
struct poller {
	int blocked:1;
	int connected:1;
	int error:1;
	int intro:1;
};

void poller_blocked(struct poller *, void *);
int poller_isblocked(struct poller *, void *);
void poller_error(struct poller *, void *);


#endif
