#include "poller.h"

void poller_blocked(struct poller *p, int fd) {
}
int poller_isblocked(struct poller *p, int fd) {
	return 0;
}
void poller_error(struct poller *p, int fd) {
}
