#include "mix_buffer.h"
#include <assert.h>
#include <libavutil/samplefmt.h>
#include <string.h>
#include "statistics.h"


struct rtpengine_config rtpe_config;
struct global_stats_gauge rtpe_stats_gauge;
struct global_gauge_min_max rtpe_gauge_min_max;
struct global_stats_counter rtpe_stats;
struct global_stats_counter rtpe_stats_rate;
struct global_stats_counter rtpe_stats_intv;
struct global_stats_sampled rtpe_stats_sampled;
struct global_sampled_min_max rtpe_sampled_min_max;
struct global_sampled_min_max rtpe_sampled_graphite_min_max;
struct global_sampled_min_max rtpe_sampled_graphite_min_max_sampled;

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
	assert(memcmp(p, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", size) == 0);

	p = mix_buffer_read_fast(&mb, 25, &size);
	assert(p != NULL);
	assert(size == 50);
	assert(memcmp(p, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", size) == 0);

	// slow-path read around boundary

	p = mix_buffer_read_fast(&mb, 20, &size);
	assert(p == NULL);
	assert(size == 40);
	char buf[size];
	mix_buffer_read_slow(&mb, buf, 20);
	assert(memcmp(buf, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", size) == 0);

	// write-in and read-out

	ret = mix_buffer_write(&mb, 0x1234, "1122334455", 5);
	assert(ret == true);

	p = mix_buffer_read_fast(&mb, 5, &size);
	assert(p != NULL);
	assert(size == 10);
	assert(memcmp(p, "1122334455", size) == 0);

	// subsequent read with pre-fill

	p = mix_buffer_read_fast(&mb, 25, &size);
	assert(p != NULL);
	assert(size == 50);
	assert(memcmp(p, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", size) == 0);

	// write-in around boundary

	ret = mix_buffer_write(&mb, 0x1234, "qqwweerrttyyuuiiooppaassddffgg", 15);
	assert(ret == true);

	// read-out around boundary past end with pre-fill

	p = mix_buffer_read_fast(&mb, 20, &size);
	assert(p == NULL);
	assert(size == 40);
	mix_buffer_read_slow(&mb, buf, 20);
	assert(memcmp(buf, "qqwweerrttyyuuiiooppaassddffgg\0\0\0\0\0\0\0\0\0\0", size) == 0);

	// write-in and partial read-out

	ret = mix_buffer_write(&mb, 0x1234, "qqwweerrttyyuuiiooppaassddffgg", 15);
	assert(ret == true);

	p = mix_buffer_read_fast(&mb, 5, &size);
	assert(p != NULL);
	assert(size == 10);
	assert(memcmp(p, "qqwweerrtt", size) == 0);
	// read-pos = 20, write-pos = 30

	// another write-in and partial read-out

	ret = mix_buffer_write(&mb, 0x1234, "mmnnbbvvccxxzzllkkjjhhggffddss", 15);
	assert(ret == true);

	p = mix_buffer_read_fast(&mb, 5, &size);
	assert(p != NULL);
	assert(size == 10);
	assert(memcmp(p, "yyuuiioopp", size) == 0);
	// read-pos = 25, write-pos = 45

	// write-in around boundary

	ret = mix_buffer_write(&mb, 0x1234, "00112233445566778899", 10);
	assert(ret == true);
	// read-pos = 25, write-pos = 5

	// partial read-out

	p = mix_buffer_read_fast(&mb, 20, &size);
	assert(p != NULL);
	assert(size == 40);
	assert(memcmp(p, "aassddffggmmnnbbvvccxxzzllkkjjhhggffddss", size) == 0);
	// read-pos = 45, write-pos = 5

	// read-out across boundary plus pre-fill
	p = mix_buffer_read_fast(&mb, 15, &size);
	assert(p == NULL);
	assert(size == 30);
	mix_buffer_read_slow(&mb, buf, 15);
	assert(memcmp(buf, "00112233445566778899\0\0\0\0\0\0\0\0\0\0", size) == 0);
	// read-pos = 10, write-pos = 10

	// write and read to end of buffer

	ret = mix_buffer_write(&mb, 0x1234, "llkkccgg449900dd22bbqqddffpp[[rr..//5500kkxxmmnnffggoorrpp00ss9933[[ss==]]xx..ss", 40);
	assert(ret == true);

	p = mix_buffer_read_fast(&mb, 40, &size);
	assert(p != NULL);
	assert(size == 80);
	assert(memcmp(p, "llkkccgg449900dd22bbqqddffpp[[rr..//5500kkxxmmnnffggoorrpp00ss9933[[ss==]]xx..ss", size) == 0);
	// read-pos = 0, write-pos = 0

	// mix-in

	// write from source 1
	ret = mix_buffer_write(&mb, 0x1234, "\1\2\1\2\1\2\1\2\1\2\1\2\1\2\1\2\1\2\1\2", 10);
	assert(ret == true);
	// write from source 2
	ret = mix_buffer_write(&mb, 0x6543, "\3\5\3\5\3\5\3\5\3\5\3\5\3\5\3\5\3\5\3\5", 10);
	assert(ret == true);

	// read mixed output
	p = mix_buffer_read_fast(&mb, 10, &size);
	assert(p != NULL);
	assert(size == 20);
	assert(memcmp(p, "\4\7\4\7\4\7\4\7\4\7\4\7\4\7\4\7\4\7\4\7", size) == 0);
	// read-pos = 10, write-pos = 10

	// write with only partial mix-in
	ret = mix_buffer_write(&mb, 0x1234, "!!##$$%%&&''(())**++aabbccddee", 15);
	assert(ret == true);
	ret = mix_buffer_write(&mb, 0x6543, "AABBCCDDEEFFGGHHIIJJ", 10);
	assert(ret == true);

	// read partially mixed output
	p = mix_buffer_read_fast(&mb, 15, &size);
	assert(p != NULL);
	assert(size == 30);
	assert(memcmp(p, "bbeeggiikkmmooqqssuuaabbccddee", size) == 0);
	// read-pos = 25, write-pos = 25

	// partial write followed by larger mix-in
	ret = mix_buffer_write(&mb, 0x6543, "AABBCCDDEEFFGGHHIIJJ", 10);
	assert(ret == true);
	ret = mix_buffer_write(&mb, 0x1234, "!!##$$%%&&''(())**++aabbccddee", 15);
	assert(ret == true);

	// read partially mixed output plus fill-in
	p = mix_buffer_read_fast(&mb, 20, &size);
	assert(p != NULL);
	assert(size == 40);
	assert(memcmp(p, "bbeeggiikkmmooqqssuuaabbccddee\0\0\0\0\0\0\0\0\0\0", size) == 0);
	// read-pos = 45, write-pos = 45

	// mix-in across boundary
	ret = mix_buffer_write(&mb, 0x6543, "//..--,,++**))((''&&%%$$##\"\"!!", 15);
	assert(ret == true);
	ret = mix_buffer_write(&mb, 0x1234, "NNLLKKJJIIHHGGFFEEDDCCBBAA@@??", 15);
	assert(ret == true);
	// read-pos = 45, write-pos = 10

	// continue mix-in before reading
	ret = mix_buffer_write(&mb, 0x1234, "AABBCCDDEEFFGGHHIIJJKKLLMMNNOO", 15);
	assert(ret == true);
	ret = mix_buffer_write(&mb, 0x6543, "00112233445566778899::;;<<==>>", 15);
	assert(ret == true);
	// read-pos = 45, write-pos = 25

	// read some mixed data, slow path across boundary
	p = mix_buffer_read_fast(&mb, 10, &size);
	assert(p == NULL);
	assert(size == 20);
	mix_buffer_read_slow(&mb, buf, 10);
	assert(memcmp(buf, "}}zzxxvvttrrppnnlljj", size) == 0);
	// read-pos = 5, write-pos = 25

	// read some more, fast path
	p = mix_buffer_read_fast(&mb, 10, &size);
	assert(p != NULL);
	assert(size == 20);
	assert(memcmp(p, "hhffddbb``qqssuuwwyy{{", size) == 0);
	// read-pos = 15, write-pos = 25

	// read remainder
	p = mix_buffer_read_fast(&mb, 10, &size);
	assert(p != NULL);
	assert(size == 20);
	assert(memcmp(p, "{{}}\177\177\377\177\377\177\377\177\377\177\377\177\377\177\377\177", size) == 0);
	// read-pos = 25, write-pos = 25

	// write across boundary
	ret = mix_buffer_write(&mb, 0x1234, "000000000000000000000000000000000000000000000000000000000000", 30);
	assert(ret == true);
	// read-pos = 25, write-pos = 5

	// mix-in small piece
	ret = mix_buffer_write(&mb, 0x6543, "11111111111111111111", 10);
	assert(ret == true);

	// read partially mixed
	p = mix_buffer_read_fast(&mb, 20, &size);
	assert(p != NULL);
	assert(size == 40);
	assert(memcmp(p, "aaaaaaaaaaaaaaaaaaaa00000000000000000000", size) == 0);
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
	assert(memcmp(p, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", size) == 0);

	p = mix_buffer_read_fast(&mb, 25, &size);
	assert(p != NULL);
	assert(size == 100);
	assert(memcmp(p, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", size) == 0);

	// slow-path read around boundary

	p = mix_buffer_read_fast(&mb, 20, &size);
	assert(p == NULL);
	assert(size == 80);
	char sbuf[size];
	mix_buffer_read_slow(&mb, sbuf, 20);
	assert(memcmp(sbuf, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", size) == 0);

	// write-in and read-out

	ret = mix_buffer_write(&mb, 0x1234, "11223344551122334455", 5);
	assert(ret == true);

	p = mix_buffer_read_fast(&mb, 5, &size);
	assert(p != NULL);
	assert(size == 20);
	assert(memcmp(p, "11223344551122334455", size) == 0);

	// subsequent read with pre-fill

	p = mix_buffer_read_fast(&mb, 25, &size);
	assert(p != NULL);
	assert(size == 100);
	assert(memcmp(p, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", size) == 0);

	// write-in around boundary

	ret = mix_buffer_write(&mb, 0x1234, "qqwweerrttyyuuiiooppaassddffggqqwweerrttyyuuiiooppaassddffgg", 15);
	assert(ret == true);

	// read-out around boundary past end with pre-fill

	p = mix_buffer_read_fast(&mb, 20, &size);
	assert(p == NULL);
	assert(size == 80);
	mix_buffer_read_slow(&mb, sbuf, 20);
	assert(memcmp(sbuf, "qqwweerrttyyuuiiooppaassddffggqqwweerrttyyuuiiooppaassddffgg\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", size) == 0);

	// write-in and partial read-out

	ret = mix_buffer_write(&mb, 0x1234, "qqwweerrttyyuuiiooppaassddffggqqwweerrttyyuuiiooppaassddffgg", 15);
	assert(ret == true);

	p = mix_buffer_read_fast(&mb, 5, &size);
	assert(p != NULL);
	assert(size == 20);
	assert(memcmp(p, "qqwweerrttyyuuiioopp", size) == 0);
	// read-pos = 20, write-pos = 30

	// another write-in and partial read-out

	ret = mix_buffer_write(&mb, 0x1234, "mmnnbbvvccxxzzllkkjjhhggffddssmmnnbbvvccxxzzllkkjjhhggffddss", 15);
	assert(ret == true);

	p = mix_buffer_read_fast(&mb, 5, &size);
	assert(p != NULL);
	assert(size == 20);
	assert(memcmp(p, "aassddffggqqwweerrtt", size) == 0);
	// read-pos = 25, write-pos = 45

	// write-in around boundary

	ret = mix_buffer_write(&mb, 0x1234, "0011223344556677889900112233445566778899", 10);
	assert(ret == true);
	// read-pos = 25, write-pos = 5

	// partial read-out

	p = mix_buffer_read_fast(&mb, 20, &size);
	assert(p != NULL);
	assert(size == 80);
	assert(memcmp(p, "yyuuiiooppaassddffggmmnnbbvvccxxzzllkkjjhhggffddssmmnnbbvvccxxzzllkkjjhhggffddss", size) == 0);
	// read-pos = 45, write-pos = 5

	// read-out across boundary plus pre-fill
	p = mix_buffer_read_fast(&mb, 15, &size);
	assert(p == NULL);
	assert(size == 60);
	mix_buffer_read_slow(&mb, sbuf, 15);
	assert(memcmp(sbuf, "0011223344556677889900112233445566778899\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", size) == 0);
	// read-pos = 10, write-pos = 10

	// write and read to end of buffer

	ret = mix_buffer_write(&mb, 0x1234, "llkkccgg449900dd22bbqqddffpp[[rr..//5500kkxxmmnnffggoorrpp00ss9933[[ss==]]xx..ssllkkccgg449900dd22bbqqddffpp[[rr..//5500kkxxmmnnffggoorrpp00ss9933[[ss==]]xx..ss", 40);
	assert(ret == true);

	p = mix_buffer_read_fast(&mb, 40, &size);
	assert(p != NULL);
	assert(size == 160);
	assert(memcmp(p, "llkkccgg449900dd22bbqqddffpp[[rr..//5500kkxxmmnnffggoorrpp00ss9933[[ss==]]xx..ssllkkccgg449900dd22bbqqddffpp[[rr..//5500kkxxmmnnffggoorrpp00ss9933[[ss==]]xx..ss", size) == 0);
	// read-pos = 0, write-pos = 0

	// mix-in

	// write from source 1
	ret = mix_buffer_write(&mb, 0x1234, "\1\2\1\2\1\2\1\2\1\2\1\2\1\2\1\2\1\2\1\2\1\2\1\2\1\2\1\2\1\2\1\2\1\2\1\2\1\2\1\2", 10);
	assert(ret == true);
	// write from source 2
	ret = mix_buffer_write(&mb, 0x6543, "\3\5\3\5\3\5\3\5\3\5\3\5\3\5\3\5\3\5\3\5\3\5\3\5\3\5\3\5\3\5\3\5\3\5\3\5\3\5\3\5", 10);
	assert(ret == true);

	// read mixed output
	p = mix_buffer_read_fast(&mb, 10, &size);
	assert(p != NULL);
	assert(size == 40);
	assert(memcmp(p, "\4\7\4\7\4\7\4\7\4\7\4\7\4\7\4\7\4\7\4\7\4\7\4\7\4\7\4\7\4\7\4\7\4\7\4\7\4\7\4\7", size) == 0);
	// read-pos = 10, write-pos = 10

	// write with only partial mix-in
	ret = mix_buffer_write(&mb, 0x1234, "!!##$$%%&&''(())**++aabbccddee!!##$$%%&&''(())**++aabbccddee", 15);
	assert(ret == true);
	ret = mix_buffer_write(&mb, 0x6543, "AABBCCDDEEFFGGHHIIJJAABBCCDDEEFFGGHHIIJJ", 10);
	assert(ret == true);

	// read partially mixed output
	p = mix_buffer_read_fast(&mb, 15, &size);
	assert(p != NULL);
	assert(size == 60);
	assert(memcmp(p, "bbeeggiikkmmooqqssuu\377\177\377\177\377\177\377\177\377\177ggjjllnnpp''(())**++aabbccddee", size) == 0);
	// read-pos = 25, write-pos = 25

	// partial write followed by larger mix-in
	ret = mix_buffer_write(&mb, 0x6543, "AABBCCDDEEFFGGHHIIJJAABBCCDDEEFFGGHHIIJJ", 10);
	assert(ret == true);
	ret = mix_buffer_write(&mb, 0x1234, "!!##$$%%&&''(())**++aabbccddee!!##$$%%&&''(())**++aabbccddee", 15);
	assert(ret == true);

	// read partially mixed output plus fill-in
	p = mix_buffer_read_fast(&mb, 20, &size);
	assert(p != NULL);
	assert(size == 80);
	assert(memcmp(p, "bbeeggiikkmmooqqssuu\377\177\377\177\377\177\377\177\377\177ggjjllnnpp''(())**++aabbccddee\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", size) == 0);
	// read-pos = 45, write-pos = 45

	// mix-in across boundary
	ret = mix_buffer_write(&mb, 0x6543, "//..--,,++**))((''&&%%$$##\"\"!!//..--,,++**))((''&&%%$$##\"\"!!", 15);
	assert(ret == true);
	ret = mix_buffer_write(&mb, 0x1234, "NNLLKKJJIIHHGGFFEEDDCCBBAA@@??NNLLKKJJIIHHGGFFEEDDCCBBAA@@??", 15);
	assert(ret == true);
	// read-pos = 45, write-pos = 10

	// continue mix-in before reading
	ret = mix_buffer_write(&mb, 0x1234, "AABBCCDDEEFFGGHHIIJJKKLLMMNNOOAABBCCDDEEFFGGHHIIJJKKLLMMNNOO", 15);
	assert(ret == true);
	ret = mix_buffer_write(&mb, 0x6543, "00112233445566778899::;;<<==>>00112233445566778899::;;<<==>>", 15);
	assert(ret == true);
	// read-pos = 45, write-pos = 25

	// read some mixed data, slow path across boundary
	p = mix_buffer_read_fast(&mb, 10, &size);
	assert(p == NULL);
	assert(size == 40);
	mix_buffer_read_slow(&mb, sbuf, 10);
	assert(memcmp(sbuf, "}}zzxxvvttrrppnnlljjhhffddbb``}}zzxxvvtt", size) == 0);
	// read-pos = 5, write-pos = 25

	// read some more, fast path
	p = mix_buffer_read_fast(&mb, 10, &size);
	assert(p != NULL);
	assert(size == 40);
	assert(memcmp(p, "rrppnnlljjhhffddbb``qqssuuwwyy{{}}\177\177\377\177\377\177", size) == 0);
	// read-pos = 15, write-pos = 25

	mix_buffer_destroy(&mb);



	// initial delay

	memset(&mb, 0, sizeof(mb));
	ret = mix_buffer_init(&mb, AV_SAMPLE_FMT_S16, 500, 1, 100, 10); // 5 samples delay
	assert(ret == true);

	// write-in and read-out

	ret = mix_buffer_write(&mb, 0x1234, "1122334455", 5);
	assert(ret == true);

	p = mix_buffer_read_fast(&mb, 15, &size);
	assert(p != NULL);
	assert(size == 30);
	assert(memcmp(p, "\0\0\0\0\0\0\0\0\0\0" "1122334455" "\0\0\0\0\0\0\0\0\0\0", size) == 0);

	ret = mix_buffer_write(&mb, 0x1234, "1122334455", 5);
	assert(ret == true);

	p = mix_buffer_read_fast(&mb, 10, &size);
	assert(p != NULL);
	assert(size == 20);
	assert(memcmp(p, "\0\0\0\0\0\0\0\0\0\0" "1122334455", size) == 0);

	ret = mix_buffer_write(&mb, 0x1234, "1122334455", 5);
	assert(ret == true);

	p = mix_buffer_read_fast(&mb, 10, &size);
	assert(p != NULL);
	assert(size == 20);
	assert(memcmp(p, "1122334455" "\0\0\0\0\0\0\0\0\0\0", size) == 0);

	// src now fallen behind, catch up with reader

	ret = mix_buffer_write(&mb, 0x1234, "xxxxxxxxxx", 5);
	assert(ret == true);
	p = mix_buffer_read_fast(&mb, 10, &size);
	assert(p != NULL);
	assert(size == 20);
	assert(memcmp(p, "\0\0\0\0\0\0\0\0\0\0" "xxxxxxxxxx", size) == 0);

	// mix two sources

	ret = mix_buffer_write(&mb, 0x1234, "1122334455", 5);
	assert(ret == true);

	// add new source

	ret = mix_buffer_write(&mb, 0x6543, "9988776655", 5);
	assert(ret == true);
	ret = mix_buffer_write(&mb, 0x1234, "3344556677", 5);
	assert(ret == true);

	// output partially mixed, new source delayed

	p = mix_buffer_read_fast(&mb, 10, &size);
	assert(p == NULL);
	assert(size == 20);
	mix_buffer_read_slow(&mb, buf, 10);
	assert(memcmp(buf, "1122334455llllllllll" , size) == 0);

	// caught up now. add new source with extra delay:
	// 10 ms constant, 15 ms extra = 25 ms total = 12.5 sampes (12)

	struct timeval last = { 100, 200 };
	struct timeval now = { 100, 15200 };

	ret = mix_buffer_write_delay(&mb, 0x3333, "0011223344", 5, &last, &now);
	assert(ret == true);

	// mix-in previous source

	ret = mix_buffer_write(&mb, 0x6543, "3322114455998866334422339988776655443322", 20);
	assert(ret == true);

	// read mixed output

	p = mix_buffer_read_fast(&mb, 20, &size);
	assert(p != NULL);
	assert(size == 40);
	assert(memcmp(p, "332211445599886633442233iiiiiiiiii443322", size) == 0);

	mix_buffer_destroy(&mb);

	return 0;
}
