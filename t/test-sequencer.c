#include "codeclib.h"
#include <assert.h>

static unsigned int num_freed;

static void ffunc(seq_packet_t *a) {
	num_freed++;
}

int main(void) {
	packet_sequencer_t ps = {0};
	packet_sequencer_init(&ps, ffunc);

	void *p;
	int i;

	p = packet_sequencer_next_packet(&ps);
	assert(p == NULL);

	p = packet_sequencer_force_next_packet(&ps);
	assert(p == NULL);

	i = packet_sequencer_next_ok(&ps);
	assert(!i);

	assert(num_freed == 0);

	seq_packet_t pks[256];

	pks[0].seq = 100;
	i = packet_sequencer_insert(&ps, &pks[0]);
	assert(i == 0);
	assert(num_freed == 0);

	i = packet_sequencer_next_ok(&ps);
	assert(i);

	p = packet_sequencer_next_packet(&ps);
	assert(p == &pks[0]);
	assert(num_freed == 0);


	pks[0].seq = 101;
	pks[1].seq = 102;

	i = packet_sequencer_insert(&ps, &pks[0]);
	assert(i == 0);
	assert(num_freed == 0);

	i = packet_sequencer_next_ok(&ps);
	assert(i);

	i = packet_sequencer_insert(&ps, &pks[1]);
	assert(i == 2);
	assert(num_freed == 0);

	i = packet_sequencer_next_ok(&ps);
	assert(i);

	p = packet_sequencer_next_packet(&ps);
	assert(p == &pks[0]);
	assert(num_freed == 0);

	p = packet_sequencer_next_packet(&ps);
	assert(p == &pks[1]);
	assert(num_freed == 0);

	p = packet_sequencer_next_packet(&ps);
	assert(p == NULL);


	pks[0].seq = 103;
	pks[1].seq = 104;

	i = packet_sequencer_insert(&ps, &pks[1]);
	assert(i == 2);
	assert(num_freed == 0);

	i = packet_sequencer_next_ok(&ps);
	assert(!i);

	p = packet_sequencer_next_packet(&ps);
	assert(p == NULL);

	i = packet_sequencer_insert(&ps, &pks[0]);
	assert(i == 0);
	assert(num_freed == 0);

	i = packet_sequencer_next_ok(&ps);
	assert(i);

	p = packet_sequencer_next_packet(&ps);
	assert(p == &pks[0]);
	assert(num_freed == 0);

	p = packet_sequencer_next_packet(&ps);
	assert(p == &pks[1]);
	assert(num_freed == 0);

	p = packet_sequencer_next_packet(&ps);
	assert(p == NULL);

	i = packet_sequencer_insert(&ps, &pks[0]);
	assert(i == -1);
	assert(num_freed == 0);

	i = packet_sequencer_next_ok(&ps);
	assert(!i);

	i = packet_sequencer_insert(&ps, &pks[1]);
	assert(i == -1);
	assert(num_freed == 0);

	i = packet_sequencer_next_ok(&ps);
	assert(!i);

	p = packet_sequencer_next_packet(&ps);
	assert(p == NULL);


	pks[0].seq = 106;
	pks[1].seq = 107;

	i = packet_sequencer_insert(&ps, &pks[1]);
	assert(i == 2);
	assert(num_freed == 0);

	i = packet_sequencer_next_ok(&ps);
	assert(!i);

	p = packet_sequencer_next_packet(&ps);
	assert(p == NULL);

	i = packet_sequencer_insert(&ps, &pks[0]);
	assert(i == 2);
	assert(num_freed == 0);

	i = packet_sequencer_next_ok(&ps);
	assert(!i);

	p = packet_sequencer_next_packet(&ps);
	assert(p == NULL);
	assert(num_freed == 0);

	p = packet_sequencer_force_next_packet(&ps);
	assert(p == &pks[0]);
	assert(num_freed == 0);

	p = packet_sequencer_next_packet(&ps);
	assert(p == &pks[1]);
	assert(num_freed == 0);



	pks[0].seq = 110;
	pks[1].seq = 111;

	i = packet_sequencer_insert(&ps, &pks[1]);
	assert(i == 2);
	assert(num_freed == 0);

	i = packet_sequencer_next_ok(&ps);
	assert(!i);

	p = packet_sequencer_next_packet(&ps);
	assert(p == NULL);

	i = packet_sequencer_insert(&ps, &pks[0]);
	assert(i == 2);
	assert(num_freed == 0);

	i = packet_sequencer_next_ok(&ps);
	assert(!i);

	p = packet_sequencer_next_packet(&ps);
	assert(p == NULL);
	assert(num_freed == 0);

	pks[2].seq = 112;
	pks[3].seq = 113;
	pks[4].seq = 114;
	pks[5].seq = 115;
	pks[6].seq = 116;
	pks[7].seq = 117;
	pks[8].seq = 118;
	pks[9].seq = 119;

	i = packet_sequencer_insert(&ps, &pks[2]);
	assert(i == 2);
	assert(num_freed == 0);
	i = packet_sequencer_insert(&ps, &pks[3]);
	assert(i == 2);
	assert(num_freed == 0);
	i = packet_sequencer_insert(&ps, &pks[7]);
	assert(i == 2);
	assert(num_freed == 0);
	i = packet_sequencer_insert(&ps, &pks[8]);
	assert(i == 2);
	assert(num_freed == 0);
	i = packet_sequencer_insert(&ps, &pks[9]);
	assert(i == 2);
	assert(num_freed == 0);
	i = packet_sequencer_insert(&ps, &pks[4]);
	assert(i == 2);
	assert(num_freed == 0);

	i = packet_sequencer_next_ok(&ps);
	assert(!i);

	p = packet_sequencer_next_packet(&ps);
	assert(p == NULL);
	assert(num_freed == 0);

	i = packet_sequencer_insert(&ps, &pks[6]);
	assert(i == 2);
	assert(num_freed == 0);

	i = packet_sequencer_next_ok(&ps);
	assert(!i);

	p = packet_sequencer_next_packet(&ps);
	assert(p == NULL);
	assert(num_freed == 0);

	i = packet_sequencer_insert(&ps, &pks[5]);
	assert(i == 2);
	assert(num_freed == 0);

	i = packet_sequencer_next_ok(&ps);
	assert(!i);

	p = packet_sequencer_next_packet(&ps);
	assert(p == &pks[0]);
	assert(num_freed == 0);

	i = packet_sequencer_next_ok(&ps);
	assert(i);
	assert(num_freed == 0);

	p = packet_sequencer_next_packet(&ps);
	assert(p == &pks[1]);
	assert(num_freed == 0);


	pks[0].seq = 10000;
	pks[1].seq = 10001;

	i = packet_sequencer_insert(&ps, &pks[1]);
	assert(i == 1);
	assert(num_freed == 8);
	num_freed = 0;

	p = packet_sequencer_next_packet(&ps);
	assert(p == &pks[1]);
	assert(num_freed == 0);

	i = packet_sequencer_insert(&ps, &pks[0]);
	assert(i == -1);
	assert(num_freed == 0);

	p = packet_sequencer_next_packet(&ps);
	assert(p == NULL);
	assert(num_freed == 0);


	pks[0].seq = 10;
	pks[1].seq = 11;

	i = packet_sequencer_insert(&ps, &pks[1]);
	assert(i == 1);
	assert(num_freed == 0);

	i = packet_sequencer_insert(&ps, &pks[0]);
	assert(i == -1);
	assert(num_freed == 0);

	p = packet_sequencer_next_packet(&ps);
	assert(p == &pks[1]);
	assert(num_freed == 0);

	p = packet_sequencer_next_packet(&ps);
	assert(p == NULL);
	assert(num_freed == 0);


	packet_sequencer_destroy(&ps);

	return 0;
}
