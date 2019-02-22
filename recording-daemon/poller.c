#include "poller.h"

void poller_blocked(struct poller *p, void *fdp) {
	p->blocked = 1;
}
int poller_isblocked(struct poller *p, void *fdp) {
	return p->blocked ? 1 : 0;
}
void poller_error(struct poller *p, void *fdp) {
}
