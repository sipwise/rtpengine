#include "poller.h"

void poller_blocked(struct poller *p, int fd) {
	p->state = PS_WRITE_BLOCKED;
}
int poller_isblocked(struct poller *p, int fd) {
	return p->state == PS_WRITE_BLOCKED;
}
void poller_error(struct poller *p, int fd) {
	p->state = PS_ERROR;
}
