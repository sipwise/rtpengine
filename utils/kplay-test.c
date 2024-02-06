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

#define atomic64 uint64_t
#include "../kernel-module/xt_RTPENGINE.h"

int main() {
	int fd = open("/proc/rtpengine/control", O_WRONLY);
	assert(fd >= 0);
	ssize_t ret = write(fd, "add 0\n", 6);
	assert(ret == 6 || (ret == -1 && errno == EEXIST));
	close(fd);

	fd = open("/proc/rtpengine/0/control", O_RDWR);
	assert(fd >= 0);

	struct rtpengine_command_init init = { .cmd = REMG_INIT };

	init.init = (struct rtpengine_init_info) {
		.last_cmd = __REMG_LAST,
		.msg_size = {
			[REMG_INIT] = sizeof(struct rtpengine_command_init),
			[REMG_ADD_TARGET] = sizeof(struct rtpengine_command_add_target),
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
	};

	ret = write(fd, &init, sizeof(init));
	assert(ret == sizeof(init));

	struct rtpengine_command_init_play_streams ips = {
		.cmd = REMG_INIT_PLAY_STREAMS,
		.num_packet_streams = 100,
		.num_play_streams = 1000,
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

	struct rtpengine_command_play_stream ps = {
		.cmd = REMG_PLAY_STREAM,
		.info = {
			.src_addr = {
				.family = AF_INET,
				.u = {
					.ipv4 = inet_addr("192.168.1.102"),
				},
				.port = 6666,
			},
			.dst_addr = {
				.family = AF_INET,
				.u = {
					.ipv4 = inet_addr("192.168.1.66"),
				},
				.port = 9999,
			},
			.pt = 8,
			.ssrc = 0x12345678,
			.ts = 76543210,
			.seq = 5432,
			.encrypt = {
				.cipher = REC_NULL,
				.hmac = REH_NULL,
			},
			.packet_stream_idx = 999999,
		},
	};
	ret = read(fd, &ps, sizeof(ps));
	assert(ret == -1 && errno == ERANGE);

	ps = (__typeof(ps)) {
		.cmd = REMG_PLAY_STREAM,
		.info = {
			.src_addr = {
				.family = AF_INET,
				.u = {
					.ipv4 = inet_addr("192.168.1.102"),
				},
				.port = 6666,
			},
			.dst_addr = {
				.family = AF_INET,
				.u = {
					.ipv4 = inet_addr("192.168.1.66"),
				},
				.port = 9999,
			},
			.pt = 8,
			.ssrc = 0x12345678,
			.ts = 76543210,
			.seq = 5432,
			.encrypt = {
				.cipher = REC_NULL,
				.hmac = REH_NULL,
			},
			.packet_stream_idx = gps.packet_stream_idx + 1,
		},
	};
	ret = read(fd, &ps, sizeof(ps));
	assert(ret == -1 && errno == ENOENT);

	ps = (__typeof(ps)) {
		.cmd = REMG_PLAY_STREAM,
		.info = {
			.src_addr = {
				.family = AF_INET,
				.u = {
					.ipv4 = inet_addr("192.168.1.102"),
				},
				.port = 6666,
			},
			.dst_addr = {
				.family = AF_INET,
				.u = {
					.ipv4 = inet_addr("192.168.1.66"),
				},
				.port = 9999,
			},
			.pt = 8,
			.ssrc = 0x12345678,
			.ts = 76543210,
			.seq = 5432,
			.encrypt = {
				.cipher = REC_NULL,
				.hmac = REH_NULL,
			},
			.packet_stream_idx = gps.packet_stream_idx,
			.repeat = 3,
			.remove_at_end = true,
		},
	};
	ret = read(fd, &ps, sizeof(ps));
	assert(ret == sizeof(ps));
	printf("play stream idx %u\n", ps.play_idx);

	struct rtpengine_command_free_packet_stream fps = {
		.cmd = REMG_FREE_PACKET_STREAM,
		.packet_stream_idx = 9999999,
	};
	ret = write(fd, &fps, sizeof(fps));
	assert(ret == -1 && errno == ERANGE);
	printf("ok\n");

	fps = (__typeof(fps)) {
		.cmd = REMG_FREE_PACKET_STREAM,
		.packet_stream_idx = gps.packet_stream_idx + 1,
	};
	ret = write(fd, &fps, sizeof(fps));
	assert(ret == -1 && errno == ENOENT);
	printf("ok\n");

//	test: remove while in use
//	fps = (__typeof(fps)) {
//		.cmd = REMG_FREE_PACKET_STREAM,
//		.packet_stream_idx = gps.packet_stream_idx,
//	};
//	ret = write(fd, &fps, sizeof(fps));
//	assert(ret == sizeof(fps));
//	printf("ok\n");

	printf("sleep\n");
	sleep(20);

	struct rtpengine_command_stop_stream ss = {
		.cmd = REMG_STOP_STREAM,
		.play_idx = ps.play_idx,
	};
	ret = read(fd, &ss, sizeof(ss));
	assert(ret == -1 && errno == ENOENT);

	ps = (__typeof(ps)) {
		.cmd = REMG_PLAY_STREAM,
		.info = {
			.src_addr = {
				.family = AF_INET,
				.u = {
					.ipv4 = inet_addr("192.168.1.102"),
				},
				.port = 6666,
			},
			.dst_addr = {
				.family = AF_INET,
				.u = {
					.ipv4 = inet_addr("192.168.1.66"),
				},
				.port = 9999,
			},
			.pt = 8,
			.ssrc = 0x12345678,
			.ts = 76543210,
			.seq = 5432,
			.encrypt = {
				.cipher = REC_NULL,
				.hmac = REH_NULL,
			},
			.packet_stream_idx = gps.packet_stream_idx,
		},
	};
	ret = read(fd, &ps, sizeof(ps));
	assert(ret == sizeof(ps));
	printf("play stream idx %u\n", ps.play_idx);

	printf("sleep\n");
	sleep(2);

//	test: remove while in use
//	fps = (__typeof(fps)) {
//		.cmd = REMG_FREE_PACKET_STREAM,
//		.packet_stream_idx = gps.packet_stream_idx,
//	};
//	ret = write(fd, &fps, sizeof(fps));
//	assert(ret == -1 && errno == EBUSY);

	ss = (__typeof(ss)) {
		.cmd = REMG_STOP_STREAM,
		.play_idx = 999999,
	};
	ret = read(fd, &ss, sizeof(ss));
	assert(ret == -1 && errno == ERANGE);

	ss = (__typeof(ss)) {
		.cmd = REMG_STOP_STREAM,
		.play_idx = ps.play_idx + 1,
	};
	ret = read(fd, &ss, sizeof(ss));
	assert(ret == -1 && errno == ENOENT);

	ss = (__typeof(ss)) {
		.cmd = REMG_STOP_STREAM,
		.play_idx = ps.play_idx,
	};
	ret = read(fd, &ss, sizeof(ss));
	assert(ret == sizeof(ss));
	printf("stop ok\n");

	ss = (__typeof(ss)) {
		.cmd = REMG_STOP_STREAM,
		.play_idx = ps.play_idx,
	};
	ret = read(fd, &ss, sizeof(ss));
	assert(ret == -1 && errno == ENOENT);

	fps = (__typeof(fps)) {
		.cmd = REMG_FREE_PACKET_STREAM,
		.packet_stream_idx = gps.packet_stream_idx,
	};
	ret = write(fd, &fps, sizeof(fps));
	printf("%zi %s\n", ret, strerror(errno));
	assert(ret == sizeof(fps));
	printf("free ok\n");

	sleep(3);

	fps = (__typeof(fps)) {
		.cmd = REMG_FREE_PACKET_STREAM,
		.packet_stream_idx = gps.packet_stream_idx,
	};
	ret = write(fd, &fps, sizeof(fps));
	assert(ret == -1 && errno == ENOENT);

	sleep(3);

	printf("closing fd\n");
	close(fd);

	sleep(3);

	fd = open("/proc/rtpengine/control", O_WRONLY);
	assert(fd >= 0);
	ret = write(fd, "del 0\n", 6);
	assert(ret == 6);
	close(fd);

	return 0;
}
