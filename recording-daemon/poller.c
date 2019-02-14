#include "poller.h"

void poller_blocked(struct poller *p, int fd) {
	p->blocked = 1;
}
int poller_isblocked(struct poller *p, int fd) {
	return p->blocked ? 1 : 0;
}
void poller_error(struct poller *p, int fd) {
}
