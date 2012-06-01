#include <stdio.h>
#include <assert.h>
#include "poller.h"


void dummy(int a, void *b) {
}


int main() {
	struct poller *p;
	struct poller_item i;

	p = poller_new();
	if (!p) {
		fprintf(stderr, "poller creation failed\n");
		return -1;
	}

	assert(p->items_size == 0);
	assert(p->pollfds_size == 0);

	i.readable = dummy;
	i.writeable = dummy;
	i.closed = dummy;


	i.fd = 3;
	assert(poller_add_item(p, &i) == 0);
	i.fd = 4;
	assert(poller_add_item(p, &i) == 0);
	i.fd = 2;
	assert(poller_add_item(p, &i) == 0);
	i.fd = 6;
	assert(poller_add_item(p, &i) == 0);
	i.fd = 0;
	assert(poller_add_item(p, &i) == 0);
	i.fd = 1;
	assert(poller_add_item(p, &i) == 0);
	i.fd = 5;
	assert(poller_add_item(p, &i) == 0);
	i.fd = 7;
	assert(poller_add_item(p, &i) == 0);
	i.fd = 9;
	assert(poller_add_item(p, &i) == 0);


	assert(poller_del_item(p, 10) == -1);
	assert(poller_del_item(p, 6) == 0);
	assert(poller_del_item(p, 8) == -1);
	assert(poller_del_item(p, 0) == 0);
	assert(poller_del_item(p, 3) == 0);
	assert(poller_del_item(p, 11) == -1);
	assert(poller_del_item(p, 9) == 0);
	assert(poller_del_item(p, 11) == -1);
	assert(poller_del_item(p, 4) == 0);


	return 0;
}
