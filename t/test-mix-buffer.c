#include "mix_buffer.h"
#include <assert.h>
#include <libavutil/samplefmt.h>
#include <string.h>
#include "statistics.h"


struct rtpengine_config rtpe_config;
struct global_stats_gauge rtpe_stats_gauge;
struct global_gauge_min_max rtpe_gauge_min_max;
struct global_stats_counter *rtpe_stats;
struct global_stats_counter rtpe_stats_rate;
struct global_stats_counter rtpe_stats_intv;
struct global_stats_sampled rtpe_stats_sampled;
struct global_sampled_min_max rtpe_sampled_min_max;
struct global_sampled_min_max rtpe_sampled_graphite_min_max;
struct global_sampled_min_max rtpe_sampled_graphite_min_max_sampled;
__thread struct bufferpool *media_bufferpool;
void append_thread_lpr_to_glob_lpr(void) {}
struct bufferpool *shm_bufferpool;

int get_local_log_level(unsigned int u) {
	return -1;
}


int main(void) {
	struct mix_buffer mb;

	memset(&mb, 0, sizeof(mb));
	bool ret = mix_buffer_init(&mb, AV_SAMPLE_FMT_S16, 500, 1, 100, 0);
	assert(ret == true);

	// pre-fill with zeroes

	unsigned int size = 0;
	void *p = mix_buffer_read_fast(&mb, 20, &size);
	assert(p != NULL);
	assert(size == 40);
	assert(memcmp(p, (int16_t[]){0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, size) == 0);

	p = mix_buffer_read_fast(&mb, 25, &size);
	assert(p != NULL);
	assert(size == 50);
	assert(memcmp(p, (int16_t[]){0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, size) == 0);

	// slow-path read around boundary

	p = mix_buffer_read_fast(&mb, 20, &size);
	assert(p == NULL);
	assert(size == 40);
	char buf[size];
	mix_buffer_read_slow(&mb, buf, 20);
	assert(memcmp(buf, (int16_t[]){0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, size) == 0);

	// write-in and read-out

	ret = mix_buffer_write(&mb, 0x1234, (int16_t[]){11,22,33,44,55}, 5);
	assert(ret == true);

	p = mix_buffer_read_fast(&mb, 5, &size);
	assert(p != NULL);
	assert(size == 10);
	assert(memcmp(p, (int16_t[]){11,22,33,44,55}, size) == 0);

	// subsequent read with pre-fill

	p = mix_buffer_read_fast(&mb, 25, &size);
	assert(p != NULL);
	assert(size == 50);
	assert(memcmp(p, (int16_t[]){0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, size) == 0);

	// write-in around boundary

	ret = mix_buffer_write(&mb, 0x1234, (int16_t[]){50,51,52,53,54,55,56,57,58,59,60,61,62,63,64}, 15);
	assert(ret == true);

	// read-out around boundary past end with pre-fill

	p = mix_buffer_read_fast(&mb, 20, &size);
	assert(p == NULL);
	assert(size == 40);
	mix_buffer_read_slow(&mb, buf, 20);
	assert(memcmp(buf, (int16_t[]){50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,0,0,0,0,0}, size) == 0);

	// write-in and partial read-out

	ret = mix_buffer_write(&mb, 0x1234, (int16_t[]){50,51,52,53,54,55,56,57,58,59,60,61,62,63,64}, 15);
	assert(ret == true);

	p = mix_buffer_read_fast(&mb, 5, &size);
	assert(p != NULL);
	assert(size == 10);
	assert(memcmp(p, (int16_t[]){50,51,52,53,54}, size) == 0);
	// read-pos = 20, write-pos = 30

	// another write-in and partial read-out

	ret = mix_buffer_write(&mb, 0x1234, (int16_t[]){65,66,67,68,69,70,71,72,73,74,75,76,77,78,79}, 15);
	assert(ret == true);

	p = mix_buffer_read_fast(&mb, 5, &size);
	assert(p != NULL);
	assert(size == 10);
	assert(memcmp(p, (int16_t[]){55,56,57,58,59}, size) == 0);
	// read-pos = 25, write-pos = 45

	// write-in around boundary

	ret = mix_buffer_write(&mb, 0x1234, (int16_t[]){80,81,82,83,84,85,86,87,88,89}, 10);
	assert(ret == true);
	// read-pos = 25, write-pos = 5

	// partial read-out

	p = mix_buffer_read_fast(&mb, 20, &size);
	assert(p != NULL);
	assert(size == 40);
	assert(memcmp(p, (int16_t[]){60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79}, size) == 0);
	// read-pos = 45, write-pos = 5

	// read-out across boundary plus pre-fill
	p = mix_buffer_read_fast(&mb, 15, &size);
	assert(p == NULL);
	assert(size == 30);
	mix_buffer_read_slow(&mb, buf, 15);
	assert(memcmp(buf, (int16_t[]){80,81,82,83,84,85,86,87,88,89,0,0,0,0,0}, size) == 0);
	// read-pos = 10, write-pos = 10

	// write and read to end of buffer

	ret = mix_buffer_write(&mb, 0x1234, (int16_t[]){30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69}, 40);
	assert(ret == true);

	p = mix_buffer_read_fast(&mb, 40, &size);
	assert(p != NULL);
	assert(size == 80);
	assert(memcmp(p, (int16_t[]){30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69}, size) == 0);
	// read-pos = 0, write-pos = 0

	// mix-in

	// write from source 1
	ret = mix_buffer_write(&mb, 0x1234, (int16_t[]){31,31,31,31,31,31,31,31,31,31}, 10);
	assert(ret == true);
	// write from source 2
	ret = mix_buffer_write(&mb, 0x6543, (int16_t[]){11,11,11,11,11,11,11,11,11,11}, 10);
	assert(ret == true);

	// read mixed output
	p = mix_buffer_read_fast(&mb, 10, &size);
	assert(p != NULL);
	assert(size == 20);
	assert(memcmp(p, (int16_t[]){42,42,42,42,42,42,42,42,42,42}, size) == 0);
	// read-pos = 10, write-pos = 10

	// write with only partial mix-in
	ret = mix_buffer_write(&mb, 0x1234, (int16_t[]){30,31,32,33,34,35,36,37,38,39,40,41,42,43,44}, 15);
	assert(ret == true);
	ret = mix_buffer_write(&mb, 0x6543, (int16_t[]){50,51,52,53,54,55,56,57,58,59}, 10);
	assert(ret == true);

	// read partially mixed output
	p = mix_buffer_read_fast(&mb, 15, &size);
	assert(p != NULL);
	assert(size == 30);
	assert(memcmp(p, (int16_t[]){80,82,84,86,88,90,92,94,96,98,40,41,42,43,44}, size) == 0);
	// read-pos = 25, write-pos = 25

	// partial write followed by larger mix-in
	ret = mix_buffer_write(&mb, 0x6543, (int16_t[]){50,51,52,53,54,55,56,57,58,59}, 10);
	assert(ret == true);
	ret = mix_buffer_write(&mb, 0x1234, (int16_t[]){30,31,32,33,34,35,36,37,38,39,40,41,42,43,44}, 15);
	assert(ret == true);

	// read partially mixed output plus fill-in
	p = mix_buffer_read_fast(&mb, 20, &size);
	assert(p != NULL);
	assert(size == 40);
	assert(memcmp(p, (int16_t[]){80,82,84,86,88,90,92,94,96,98,40,41,42,43,44,0,0,0,0,0}, size) == 0);
	// read-pos = 45, write-pos = 45

	// mix-in across boundary with overflows
	ret = mix_buffer_write(&mb, 0x6543, (int16_t[]){32100,32101,32102,32103,32104,32105,32106,32107,32108,32109,32110,32111,32112,32113,32114}, 15);
	assert(ret == true);
	ret = mix_buffer_write(&mb, 0x1234, (int16_t[]){660,661,662,663,664,665,666,667,668,669,670,671,672,673,674}, 15);
	assert(ret == true);
	// read-pos = 45, write-pos = 10

	// continue mix-in with overflows before reading
	ret = mix_buffer_write(&mb, 0x1234, (int16_t[]){-32035,-32036,-32037,-32038,-32039,-32040,-32041,-32042,-32043,-32044,-32045,-32046,-32047,-32048,-32049}, 15);
	assert(ret == true);
	ret = mix_buffer_write(&mb, 0x6543, (int16_t[]){-720,-721,-722,-723,-724,-725,-726,-727,-728,-729,-730,-731,-732,-733,-734}, 15);
	assert(ret == true);
	// read-pos = 45, write-pos = 25

	// read some mixed data, slow path across boundary
	p = mix_buffer_read_fast(&mb, 10, &size);
	assert(p == NULL);
	assert(size == 20);
	mix_buffer_read_slow(&mb, buf, 10);
	assert(memcmp(buf, (int16_t[]){32760,32762,32764,32766,32767,32767,32767,32767,32767,32767}, size) == 0);
	// read-pos = 5, write-pos = 25

	// read some more, fast path
	p = mix_buffer_read_fast(&mb, 10, &size);
	assert(p != NULL);
	assert(size == 20);
	assert(memcmp(p, (int16_t[]){32767,32767,32767,32767,32767,-32755,-32757,-32759,-32761,-32763}, size) == 0);
	// read-pos = 15, write-pos = 25

	// read remainder
	p = mix_buffer_read_fast(&mb, 10, &size);
	assert(p != NULL);
	assert(size == 20);
	assert(memcmp(p, (int16_t[]){-32765,-32767,-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768}, size) == 0);
	// read-pos = 25, write-pos = 25

	// write across boundary
	ret = mix_buffer_write(&mb, 0x1234, (int16_t[]){20,20,20,20,20,20,20,20,20,20,20,20,20,20,20,20,20,20,20,20,20,20,20,20,20,20,20,20,20,20}, 30);
	assert(ret == true);
	// read-pos = 25, write-pos = 5

	// mix-in small piece
	ret = mix_buffer_write(&mb, 0x6543, (int16_t[]){30,30,30,30,30,30,30,30,30,30}, 10);
	assert(ret == true);

	// read partially mixed
	p = mix_buffer_read_fast(&mb, 20, &size);
	assert(p != NULL);
	assert(size == 40);
	assert(memcmp(p, (int16_t[]){50,50,50,50,50,50,50,50,50,50,20,20,20,20,20,20,20,20,20,20}, size) == 0);
	// read-pos = 15, write-pos = 25

	mix_buffer_destroy(&mb);



	// 2-channel

	memset(&mb, 0, sizeof(mb));
	ret = mix_buffer_init(&mb, AV_SAMPLE_FMT_S16, 500, 2, 100, 0);
	assert(ret == true);

	// pre-fill with zeroes

	p = mix_buffer_read_fast(&mb, 20, &size);
	assert(p != NULL);
	assert(size == 80);
	assert(memcmp(p, (int16_t[]){0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, size) == 0);

	p = mix_buffer_read_fast(&mb, 25, &size);
	assert(p != NULL);
	assert(size == 100);
	assert(memcmp(p, (int16_t[]){0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, size) == 0);

	// slow-path read around boundary

	p = mix_buffer_read_fast(&mb, 20, &size);
	assert(p == NULL);
	assert(size == 80);
	char sbuf[size];
	mix_buffer_read_slow(&mb, sbuf, 20);
	assert(memcmp(sbuf, (int16_t[]){0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, size) == 0);

	// write-in and read-out

	ret = mix_buffer_write(&mb, 0x1234, (int16_t[]){11,22,33,44,55,11,22,33,44,55}, 5);
	assert(ret == true);

	p = mix_buffer_read_fast(&mb, 5, &size);
	assert(p != NULL);
	assert(size == 20);
	assert(memcmp(p, (int16_t[]){11,22,33,44,55,11,22,33,44,55}, size) == 0);

	// subsequent read with pre-fill

	p = mix_buffer_read_fast(&mb, 25, &size);
	assert(p != NULL);
	assert(size == 100);
	assert(memcmp(p, (int16_t[]){0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, size) == 0);

	// write-in around boundary

	ret = mix_buffer_write(&mb, 0x1234, (int16_t[]){50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64}, 15);
	assert(ret == true);

	// read-out around boundary past end with pre-fill

	p = mix_buffer_read_fast(&mb, 20, &size);
	assert(p == NULL);
	assert(size == 80);
	mix_buffer_read_slow(&mb, sbuf, 20);
	assert(memcmp(sbuf, (int16_t[]){50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,0,0,0,0,0,0,0,0,0,0}, size) == 0);

	// write-in and partial read-out

	ret = mix_buffer_write(&mb, 0x1234, (int16_t[]){50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64}, 15);
	assert(ret == true);

	p = mix_buffer_read_fast(&mb, 5, &size);
	assert(p != NULL);
	assert(size == 20);
	assert(memcmp(p, (int16_t[]){50,51,52,53,54,55,56,57,58,59}, size) == 0);
	// read-pos = 20, write-pos = 30

	// another write-in and partial read-out

	ret = mix_buffer_write(&mb, 0x1234, (int16_t[]){65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79}, 15);
	assert(ret == true);

	p = mix_buffer_read_fast(&mb, 5, &size);
	assert(p != NULL);
	assert(size == 20);
	assert(memcmp(p, (int16_t[]){60,61,62,63,64,50,51,52,53,54}, size) == 0);
	// read-pos = 25, write-pos = 45

	// write-in around boundary

	ret = mix_buffer_write(&mb, 0x1234, (int16_t[]){80,81,82,83,84,85,86,87,88,89,80,81,82,83,84,85,86,87,88,89}, 10);
	assert(ret == true);
	// read-pos = 25, write-pos = 5

	// partial read-out

	p = mix_buffer_read_fast(&mb, 20, &size);
	assert(p != NULL);
	assert(size == 80);
	assert(memcmp(p, (int16_t[]){55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79}, size) == 0);
	// read-pos = 45, write-pos = 5

	// read-out across boundary plus pre-fill
	p = mix_buffer_read_fast(&mb, 15, &size);
	assert(p == NULL);
	assert(size == 60);
	mix_buffer_read_slow(&mb, sbuf, 15);
	assert(memcmp(sbuf, (int16_t[]){80,81,82,83,84,85,86,87,88,89,80,81,82,83,84,85,86,87,88,89,0,0,0,0,0,0,0,0,0,0}, size) == 0);
	// read-pos = 10, write-pos = 10

	// write and read to end of buffer

	ret = mix_buffer_write(&mb, 0x1234, (int16_t[]){30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69}, 40);
	assert(ret == true);

	p = mix_buffer_read_fast(&mb, 40, &size);
	assert(p != NULL);
	assert(size == 160);
	assert(memcmp(p, (int16_t[]){30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69}, size) == 0);
	// read-pos = 0, write-pos = 0

	// mix-in

	// write from source 1
	ret = mix_buffer_write(&mb, 0x1234, (int16_t[]){31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31}, 10);
	assert(ret == true);
	// write from source 2
	ret = mix_buffer_write(&mb, 0x6543, (int16_t[]){11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11}, 10);
	assert(ret == true);

	// read mixed output
	p = mix_buffer_read_fast(&mb, 10, &size);
	assert(p != NULL);
	assert(size == 40);
	assert(memcmp(p, (int16_t[]){42,42,42,42,42,42,42,42,42,42,42,42,42,42,42,42,42,42,42,42}, size) == 0);
	// read-pos = 10, write-pos = 10

	// write with only partial mix-in
	ret = mix_buffer_write(&mb, 0x1234, (int16_t[]){30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44}, 15);
	assert(ret == true);
	ret = mix_buffer_write(&mb, 0x6543, (int16_t[]){50,51,52,53,54,55,56,57,58,59,50,51,52,53,54,55,56,57,58,59}, 10);
	assert(ret == true);

	// read partially mixed output
	p = mix_buffer_read_fast(&mb, 15, &size);
	assert(p != NULL);
	assert(size == 60);
	assert(memcmp(p, (int16_t[]){80,82,84,86,88,90,92,94,96,98,90,92,94,96,98,85,87,89,91,93,35,36,37,38,39,40,41,42,43,44}, size) == 0);
	// read-pos = 25, write-pos = 25

	// partial write followed by larger mix-in
	ret = mix_buffer_write(&mb, 0x6543, (int16_t[]){50,51,52,53,54,55,56,57,58,59,50,51,52,53,54,55,56,57,58,59}, 10);
	assert(ret == true);
	ret = mix_buffer_write(&mb, 0x1234, (int16_t[]){30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44}, 15);
	assert(ret == true);

	// read partially mixed output plus fill-in
	p = mix_buffer_read_fast(&mb, 20, &size);
	assert(p != NULL);
	assert(size == 80);
	assert(memcmp(p, (int16_t[]){80,82,84,86,88,90,92,94,96,98,90,92,94,96,98,85,87,89,91,93,35,36,37,38,39,40,41,42,43,44,0,0,0,0,0,0,0,0,0,0}, size) == 0);
	// read-pos = 45, write-pos = 45

	// mix-in across boundary with overflows
	ret = mix_buffer_write(&mb, 0x6543, (int16_t[]){32100,32101,32102,32103,32104,32105,32106,32107,32108,32109,32110,32111,32112,32113,32114,32100,32101,32102,32103,32104,32105,32106,32107,32108,32109,32110,32111,32112,32113,32114}, 15);
	assert(ret == true);
	ret = mix_buffer_write(&mb, 0x1234, (int16_t[]){660,661,662,663,664,665,666,667,668,669,670,671,672,673,674,660,661,662,663,664,665,666,667,668,669,670,671,672,673,674}, 15);
	assert(ret == true);
	// read-pos = 45, write-pos = 10

	// continue mix-in with overflows before reading
	ret = mix_buffer_write(&mb, 0x1234, (int16_t[]){-32035,-32036,-32037,-32038,-32039,-32040,-32041,-32042,-32043,-32044,-32045,-32046,-32047,-32048,-32049, -32035,-32036,-32037,-32038,-32039,-32040,-32041,-32042,-32043,-32044,-32045,-32046,-32047,-32048,-32049}, 15);
	assert(ret == true);
	ret = mix_buffer_write(&mb, 0x6543, (int16_t[]){-720,-721,-722,-723,-724,-725,-726,-727,-728,-729,-730,-731,-732,-733,-734, -720,-721,-722,-723,-724,-725,-726,-727,-728,-729,-730,-731,-732,-733,-734}, 15);
	assert(ret == true);
	// read-pos = 45, write-pos = 25

	// read some mixed data, slow path across boundary
	p = mix_buffer_read_fast(&mb, 10, &size);
	assert(p == NULL);
	assert(size == 40);
	mix_buffer_read_slow(&mb, sbuf, 10);
	assert(memcmp(sbuf, (int16_t[]){32760,32762,32764,32766,32767,32767,32767,32767,32767,32767,32767,32767,32767,32767,32767,32760,32762,32764,32766,32767}, size) == 0);
	// read-pos = 5, write-pos = 25

	// read some more, fast path
	p = mix_buffer_read_fast(&mb, 10, &size);
	assert(p != NULL);
	assert(size == 40);
	assert(memcmp(p, (int16_t[]){32767,32767,32767,32767,32767,32767,32767,32767,32767,32767,-32755,-32757,-32759,-32761,-32763,-32765,-32767,-32768,-32768,-32768}, size) == 0);
	// read-pos = 15, write-pos = 25

	mix_buffer_destroy(&mb);



	// initial delay

	memset(&mb, 0, sizeof(mb));
	ret = mix_buffer_init(&mb, AV_SAMPLE_FMT_S16, 500, 1, 100, 10); // 5 samples delay
	assert(ret == true);

	// write-in and read-out

	ret = mix_buffer_write(&mb, 0x1234, (int16_t[]){11,22,33,44,55}, 5);
	assert(ret == true);

	p = mix_buffer_read_fast(&mb, 15, &size);
	assert(p != NULL);
	assert(size == 30);
	assert(memcmp(p, (int16_t[]){0,0,0,0,0,11,22,33,44,55,0,0,0,0,0}, size) == 0);

	ret = mix_buffer_write(&mb, 0x1234, (int16_t[]){11,22,33,44,55}, 5);
	assert(ret == true);

	p = mix_buffer_read_fast(&mb, 10, &size);
	assert(p != NULL);
	assert(size == 20);
	assert(memcmp(p, (int16_t[]){0,0,0,0,0,11,22,33,44,55}, size) == 0);

	ret = mix_buffer_write(&mb, 0x1234, (int16_t[]){11,22,33,44,55}, 5);
	assert(ret == true);

	p = mix_buffer_read_fast(&mb, 10, &size);
	assert(p != NULL);
	assert(size == 20);
	assert(memcmp(p, (int16_t[]){11,22,33,44,55,0,0,0,0,0}, size) == 0);

	// src now fallen behind, catch up with reader

	ret = mix_buffer_write(&mb, 0x1234, (int16_t[]){80,81,82,83,84}, 5);
	assert(ret == true);
	p = mix_buffer_read_fast(&mb, 10, &size);
	assert(p != NULL);
	assert(size == 20);
	assert(memcmp(p, (int16_t[]){0,0,0,0,0,80,81,82,83,84}, size) == 0);

	// mix two sources

	ret = mix_buffer_write(&mb, 0x1234, (int16_t[]){11,22,33,44,55}, 5);
	assert(ret == true);

	// add new source

	ret = mix_buffer_write(&mb, 0x6543, (int16_t[]){60,61,62,63,64}, 5);
	assert(ret == true);
	ret = mix_buffer_write(&mb, 0x1234, (int16_t[]){65,66,67,68,69}, 5);
	assert(ret == true);

	// output partially mixed, new source delayed

	p = mix_buffer_read_fast(&mb, 10, &size);
	assert(p == NULL);
	assert(size == 20);
	mix_buffer_read_slow(&mb, buf, 10);
	assert(memcmp(buf, (int16_t[]){11,22,33,44,55,125,127,129,131,133}, size) == 0);

	// caught up now. add new source with extra delay:
	// 10 ms constant, 15 ms extra = 25 ms total = 12.5 sampes (12)

	struct timeval last = { 100, 200 };
	struct timeval now = { 100, 15200 };

	ret = mix_buffer_write_delay(&mb, 0x3333, (int16_t[]){11,22,33,44,55}, 5, &last, &now);
	assert(ret == true);

	// mix-in previous source

	ret = mix_buffer_write(&mb, 0x6543, (int16_t[]){30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49}, 20);
	assert(ret == true);

	// read mixed output

	p = mix_buffer_read_fast(&mb, 20, &size);
	assert(p != NULL);
	assert(size == 40);
	assert(memcmp(p, (int16_t[]){30,31,32,33,34,35,36,37,38,39,40,41,53,65,77,89,101,47,48,49}, size) == 0);

	mix_buffer_destroy(&mb);

	return 0;
}
