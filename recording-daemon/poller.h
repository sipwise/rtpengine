#ifndef __POLLER_H__
#define __POLLER_H__


struct poller;

void poller_blocked(struct poller *, int);
int poller_isblocked(struct poller *, int);
void poller_error(struct poller *, int);


#endif
