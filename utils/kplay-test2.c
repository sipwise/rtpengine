#include <stdio.h>
#include <fcntl.h>
#include <assert.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <sys/mman.h>

#define atomic64 uint64_t
#include "../kernel-module/xt_RTPENGINE.h"

#define PAGE_SIZE 4096

int main() {
	int fd = open("/proc/rtpengine/control", O_WRONLY);
	assert(fd >= 0);
	ssize_t ret = write(fd, "add 0\n", 6);
	assert(ret == 6 || (ret == -1 && errno == EEXIST));
	close(fd);

	fd = open("/proc/rtpengine/0/control", O_RDWR);
	assert(fd >= 0);

	struct global_stats_counter *rtpe_stats = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	assert(rtpe_stats != NULL && rtpe_stats != MAP_FAILED);

	struct rtpengine_command_init init = { .cmd = REMG_INIT };

	init.init = (struct rtpengine_init_info) {
		.last_cmd = __REMG_LAST,
		.msg_size = {
			[REMG_INIT] = sizeof(struct rtpengine_command_init),
			[REMG_ADD_TARGET] = sizeof(struct rtpengine_command_add_target),
			[REMG_DEL_TARGET] = sizeof(struct rtpengine_command_del_target),
			[REMG_ADD_DESTINATION] = sizeof(struct rtpengine_command_destination),
			[REMG_ADD_CALL] = sizeof(struct rtpengine_command_add_call),
			[REMG_DEL_CALL] = sizeof(struct rtpengine_command_del_call),
			[REMG_ADD_STREAM] = sizeof(struct rtpengine_command_add_stream),
			[REMG_DEL_STREAM] = sizeof(struct rtpengine_command_del_stream),
			[REMG_PACKET] = sizeof(struct rtpengine_command_packet),
			[REMG_INIT_PLAY_STREAMS] = sizeof(struct rtpengine_command_init_play_streams),
			[REMG_GET_PACKET_STREAM] = sizeof(struct rtpengine_command_get_packet_stream),
			[REMG_PLAY_STREAM_PACKET] = sizeof(struct rtpengine_command_play_stream_packet),
			[REMG_PLAY_STREAM] = sizeof(struct rtpengine_command_play_stream),
			[REMG_STOP_STREAM] = sizeof(struct rtpengine_command_stop_stream),
			[REMG_FREE_PACKET_STREAM] = sizeof(struct rtpengine_command_free_packet_stream),
		},
		.rtpe_stats = rtpe_stats,
	};

	ret = write(fd, &init, sizeof(init));
	assert(ret == sizeof(init));

	struct rtpengine_command_init_play_streams ips = {
		.cmd = REMG_INIT_PLAY_STREAMS,
		.num_packet_streams = 100,
		.num_play_streams = 40960,
	};
	ret = write(fd, &ips, sizeof(ips));
	assert(ret == sizeof(ips));

	struct rtpengine_command_get_packet_stream gps = { .cmd = REMG_GET_PACKET_STREAM };
	ret = read(fd, &gps, sizeof(gps));
	assert(ret == sizeof(gps));
	printf("packet stream idx %u\n", gps.packet_stream_idx);

	struct {
		struct rtpengine_command_play_stream_packet psp;
		char buf[160];
	} psp = {
		.psp = {
			.cmd = REMG_PLAY_STREAM_PACKET,
			.play_stream_packet = {
				.packet_stream_idx = gps.packet_stream_idx,
			},
		},
	};

	for (unsigned int i = 0; i < 256; i++) {
		psp.psp.play_stream_packet.delay_ms = i * 20;
		psp.psp.play_stream_packet.delay_ts = i * 160;
		memset(psp.psp.play_stream_packet.data, i, sizeof(psp.buf));
		ret = write(fd, &psp, sizeof(psp));
		assert(ret == sizeof(psp));
	}
	printf("packets ok\n");

	unsigned play_idx[4096];
	const unsigned int num_plays = sizeof(play_idx)/sizeof(*play_idx);

	struct {
		struct interface_stats_block iface_stats[num_plays];
		struct stream_stats stream_stats[num_plays];
		struct ssrc_stats ssrc_stats[num_plays];
	} *all_stats;
	const unsigned int map_size = PAGE_SIZE * 512;
	assert(sizeof(*all_stats) <= map_size);

	all_stats = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	assert(all_stats != NULL && all_stats != MAP_FAILED);

	for (unsigned int i = 0; i < num_plays; i++) {
		struct rtpengine_command_play_stream ps = {
			.cmd = REMG_PLAY_STREAM,
			.info = {
				.src_addr = {
					.family = AF_INET,
					.u = {
						.ipv4 = inet_addr("192.168.1.102"),
					},
					.port = 6666 + i,
				},
				.dst_addr = {
					.family = AF_INET,
					.u = {
						.ipv4 = inet_addr("192.168.1.66"),
					},
					.port = 9999,
				},
				.pt = 8,
				.ssrc = 0x12345678 + i,
				.ts = 76543210 + i,
				.seq = 5432 + i,
				.encrypt = {
					.cipher = REC_NULL,
					.hmac = REH_NULL,
				},
				.packet_stream_idx = gps.packet_stream_idx,
				.repeat = 50,
				.remove_at_end = false,
				.iface_stats = &all_stats->iface_stats[i],
				.stats = &all_stats->stream_stats[i],
				.ssrc_stats = &all_stats->ssrc_stats[i],
			},
		};
		ret = read(fd, &ps, sizeof(ps));
		assert(ret == sizeof(ps));
		printf("play stream idx %u\n", ps.play_idx);
		play_idx[i] = ps.play_idx;

		usleep(50000);
	}

	printf("sleep\n");
	sleep(350);

	printf("close fd, sleep\n");
	sleep(10);
	close(fd);
	munmap(rtpe_stats, PAGE_SIZE);
	munmap(all_stats, map_size);

	printf("del table\n");
	fd = open("/proc/rtpengine/control", O_WRONLY);
	assert(fd >= 0);
	ret = write(fd, "del 0\n", 6);
	assert(ret == 6);
	close(fd);

	return 0;
}
