#include "poller.h"

void poller_blocked(struct poller *p, void *fdp) {
	p->state = PS_WRITE_BLOCKED;
}
bool poller_isblocked(struct poller *p, void *fdp) {
	return p->state != PS_OPEN;
}
void poller_error(struct poller *p, void *fdp) {
	p->state = PS_ERROR;
}
