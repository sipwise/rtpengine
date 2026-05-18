#include "custom_poller.h"

static void poller_blocked(struct poller *p, void *fdp) {
	p->state = PS_WRITE_BLOCKED;
}
static bool poller_isblocked(struct poller *p, void *fdp) {
	return p->state != PS_OPEN;
}
static void poller_error(struct poller *p, void *fdp) {
	p->state = PS_ERROR;
}

void (*rtpe_poller_blocked)(struct poller *, void *) = poller_blocked;
bool (*rtpe_poller_isblocked)(struct poller *, void *) = poller_isblocked;
void (*rtpe_poller_error)(struct poller *, void *) = poller_error;
