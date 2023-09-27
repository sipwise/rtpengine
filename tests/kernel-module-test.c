#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include "xt_RTPENGINE.h"

#define NUM_SOCKETS 41
#define PORT_BASE 36000
#define LOCALHOST htonl(0x7f000001)
#define LEN(x) (sizeof(x)-1)

#define MSGLEN(op, buf, len, args...) \
	printf("exec %s:%i\n", __FILE__, __LINE__); \
	rm = malloc(sizeof(*rm) + len); \
	*rm = (struct rtpengine_message) { .cmd = op, .u = { args } }; \
	if (len) \
		memcpy(&rm->data, buf, len); \
	ret = write(fd, rm, sizeof(*rm) + len); \
	printf("ret = %i\n", ret); \
	if (ret == -1) \
		printf("errno = %s\n", strerror(errno)); \
	assert(ret == sizeof(*rm) + len); \
	free(rm);

#define MSG(op, args...) MSGLEN(op, NULL, 0, args)
#define MSGBUF(op, buf, args...) MSGLEN(op, buf, LEN(buf), args)

#define SND(sock, port, data) \
	printf("exec %s:%i\n", __FILE__, __LINE__); \
	{ \
		struct sockaddr_in sin = { \
			.sin_family = AF_INET, \
			.sin_port = htons(PORT_BASE + port), \
			.sin_addr = { LOCALHOST }, \
		}; \
		ssize_t ret = sendto(fds[sock], data, LEN(data), 0, (struct sockaddr *) &sin, sizeof(sin)); \
		printf("ret = %zi\n", ret); \
		assert(ret == LEN(data)); \
	}
#define EXP(sock, data) \
	printf("exec %s:%i\n", __FILE__, __LINE__); \
	{ \
		char buf[65535]; \
		alarm(1); \
		ssize_t ret = recv(fds[sock], buf, sizeof(buf), 0); \
		alarm(0); \
		printf("ret = %zi, expect = %zi\n", ret, LEN(data)); \
		assert(ret == LEN(data)); \
		buf[ret] = '\0'; \
		printf("data ="); \
		for (int __i = 0; __i < ret; __i++) \
			printf(" %02x", (unsigned char) buf[__i]); \
		printf("\n"); \
		assert(memcmp(data, buf, LEN(data)) == 0); \
	}
#define EXPF(sock, data, port) \
	printf("exec %s:%i\n", __FILE__, __LINE__); \
	{ \
		struct sockaddr_in sin = { 0, }; \
		socklen_t sinlen = sizeof(sin); \
		char buf[65535]; \
		alarm(1); \
		ssize_t ret = recvfrom(fds[sock], buf, sizeof(buf), 0, (struct sockaddr *) &sin, &sinlen); \
		alarm(0); \
		printf("ret = %zi, expect = %zi\n", ret, LEN(data)); \
		assert(ret == LEN(data)); \
		buf[ret] = '\0'; \
		printf("data ="); \
		for (int __i = 0; __i < ret; __i++) \
			printf(" %02x", (unsigned char) buf[__i]); \
		printf("\n"); \
		assert(memcmp(data, buf, LEN(data)) == 0); \
		assert(sin.sin_family == AF_INET); \
		assert(sin.sin_addr.s_addr == LOCALHOST); \
		assert(sin.sin_port == htons(PORT_BASE + port)); \
	}

int main(void) {
	int fd = open("/proc/rtpengine/0/control", O_RDWR);
	assert(fd != -1);

	struct rtpengine_message *rm;
	int ret;

	MSG(REMG_NOOP,
		.noop = {
			.size = sizeof(*rm),
			.last_cmd = __REMG_LAST,
		},
	);

	// open a bunch of sockets
	int fds[NUM_SOCKETS];
	for (int i = 0; i < NUM_SOCKETS; i++) {
		fds[i] = socket(AF_INET, SOCK_DGRAM, 0);
		assert(fds[i] != -1);
		struct sockaddr_in sin = {
			.sin_family = AF_INET,
			.sin_port = htons(PORT_BASE + i),
			.sin_addr = { LOCALHOST },
		};
		int ret = bind(fds[i], (struct sockaddr *) &sin, sizeof(sin));
		assert(ret == 0);
	}

	// non-forwarding
	MSG(REMG_ADD_TARGET,
		.target = {
			.local = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 0,
			},
			.expected_src = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = 8888,
			},
			.decrypt = {
				.cipher = REC_NULL,
				.hmac = REH_NULL,
			},
			.src_mismatch = MSM_IGNORE,
			.num_destinations = 0,
			.non_forwarding = 1,
		},
	);
	SND(40, 0, "one");
	EXP(0, "one");

	// forwarding, incomplete
	MSG(REMG_ADD_TARGET,
		.target = {
			.local = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 1,
			},
			.expected_src = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = 9999,
			},
			.decrypt = {
				.cipher = REC_NULL,
				.hmac = REH_NULL,
			},
			.src_mismatch = MSM_IGNORE,
			.num_destinations = 1,
		},
	);
	SND(40, 1, "two");
	EXP(1, "two");

	// forwarding
	MSG(REMG_ADD_TARGET,
		.target = {
			.local = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 2,
			},
			.expected_src = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = 5555,
			},
			.decrypt = {
				.cipher = REC_NULL,
				.hmac = REH_NULL,
			},
			.src_mismatch = MSM_IGNORE,
			.num_destinations = 1,
		},
	);
	MSG(REMG_ADD_DESTINATION,
		.destination = {
			.local = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 2,
			},
			.num = 0,
			.output = {
				.src_addr = {
					.family = AF_INET,
					.u = {
						.ipv4 = LOCALHOST,
					},
					.port = PORT_BASE + 3,
				},
				.dst_addr = {
					.family = AF_INET,
					.u = {
						.ipv4 = LOCALHOST,
					},
					.port = PORT_BASE + 4,
				},
				.encrypt = {
					.cipher = REC_NULL,
					.hmac = REH_NULL,
				},
			},
		},
	);
	SND(40, 2, "three");
	EXPF(4, "three", 3);

	// RTCP output
	MSGBUF(REMG_SEND_RTCP,
		"foo",
		.send_packet = {
			.local = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 2,
			},
			.destination_idx = 0,
			.src_addr = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 3,
			},
			.dst_addr = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 4,
			},
		},
	);
	EXPF(4, "foo", 3);

	// multi forwarding, incomplete
	MSG(REMG_ADD_TARGET,
		.target = {
			.local = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 5,
			},
			.expected_src = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = 5555,
			},
			.decrypt = {
				.cipher = REC_NULL,
				.hmac = REH_NULL,
			},
			.src_mismatch = MSM_IGNORE,
			.num_destinations = 2,
		},
	);
	MSG(REMG_ADD_DESTINATION,
		.destination = {
			.local = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 5,
			},
			.num = 0,
			.output = {
				.src_addr = {
					.family = AF_INET,
					.u = {
						.ipv4 = LOCALHOST,
					},
					.port = PORT_BASE + 6,
				},
				.dst_addr = {
					.family = AF_INET,
					.u = {
						.ipv4 = LOCALHOST,
					},
					.port = PORT_BASE + 7,
				},
				.encrypt = {
					.cipher = REC_NULL,
					.hmac = REH_NULL,
				},
			},
		},
	);
	SND(40, 5, "four");
	EXP(5, "four");

	// multi forwarding
	MSG(REMG_ADD_TARGET,
		.target = {
			.local = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 8,
			},
			.expected_src = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = 5555,
			},
			.decrypt = {
				.cipher = REC_NULL,
				.hmac = REH_NULL,
			},
			.src_mismatch = MSM_IGNORE,
			.num_destinations = 2,
		},
	);
	MSG(REMG_ADD_DESTINATION,
		.destination = {
			.local = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 8,
			},
			.num = 0,
			.output = {
				.src_addr = {
					.family = AF_INET,
					.u = {
						.ipv4 = LOCALHOST,
					},
					.port = PORT_BASE + 9,
				},
				.dst_addr = {
					.family = AF_INET,
					.u = {
						.ipv4 = LOCALHOST,
					},
					.port = PORT_BASE + 10,
				},
				.encrypt = {
					.cipher = REC_NULL,
					.hmac = REH_NULL,
				},
			},
		},
	);
	MSG(REMG_ADD_DESTINATION,
		.destination = {
			.local = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 8,
			},
			.num = 1,
			.output = {
				.src_addr = {
					.family = AF_INET,
					.u = {
						.ipv4 = LOCALHOST,
					},
					.port = PORT_BASE + 11,
				},
				.dst_addr = {
					.family = AF_INET,
					.u = {
						.ipv4 = LOCALHOST,
					},
					.port = PORT_BASE + 12,
				},
				.encrypt = {
					.cipher = REC_NULL,
					.hmac = REH_NULL,
				},
			},
		},
	);
	SND(40, 8, "five");
	EXPF(10, "five", 9);
	EXPF(12, "five", 11);

	// RTCP output
	MSGLEN(REMG_SEND_RTCP,
		"foo",
		3,
		.send_packet = {
			.local = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 8,
			},
			.destination_idx = 0,
			.src_addr = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 9,
			},
			.dst_addr = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 10,
			},
		},
	);
	EXPF(10, "foo", 9);

	MSGLEN(REMG_SEND_RTCP,
		"foo",
		3,
		.send_packet = {
			.local = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 8,
			},
			.destination_idx = 1,
			.src_addr = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 11,
			},
			.dst_addr = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 12,
			},
		},
	);
	EXPF(12, "foo", 11);

	// RTCP output
	MSGBUF(REMG_SEND_RTCP,
		"foo",
		.send_packet = {
			.local = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 8,
			},
			.destination_idx = 0,
			.src_addr = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 9,
			},
			.dst_addr = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 10,
			},
		},
	);
	EXPF(10, "foo", 9);

	MSGBUF(REMG_SEND_RTCP,
		"foo",
		.send_packet = {
			.local = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 8,
			},
			.destination_idx = 1,
			.src_addr = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 11,
			},
			.dst_addr = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 12,
			},
		},
	);
	EXPF(12, "foo", 11);

	// multi forwarding RTP/SRTP
	MSG(REMG_ADD_TARGET,
		.target = {
			.local = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 13,
			},
			.expected_src = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = 5555,
			},
			.decrypt = {
				.cipher = REC_NULL,
				.hmac = REH_NULL,
			},
			.src_mismatch = MSM_IGNORE,
			.num_destinations = 4,
			.rtp = 1,

			.num_payload_types = 1,
			.payload_types = {
				{
					.pt_num = 0xf,
					.clock_rate = 8000,
				},
			},
		},
	);
	MSG(REMG_ADD_DESTINATION,
		.destination = {
			.local = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 13,
			},
			.num = 0,
			.output = {
				.src_addr = {
					.family = AF_INET,
					.u = {
						.ipv4 = LOCALHOST,
					},
					.port = PORT_BASE + 14,
				},
				.dst_addr = {
					.family = AF_INET,
					.u = {
						.ipv4 = LOCALHOST,
					},
					.port = PORT_BASE + 15,
				},
				.encrypt = {
					.cipher = REC_NULL,
					.hmac = REH_NULL,
				},
			},
		},
	);
	MSG(REMG_ADD_DESTINATION,
		.destination = {
			.local = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 13,
			},
			.num = 1,
			.output = {
				.src_addr = {
					.family = AF_INET,
					.u = {
						.ipv4 = LOCALHOST,
					},
					.port = PORT_BASE + 16,
				},
				.dst_addr = {
					.family = AF_INET,
					.u = {
						.ipv4 = LOCALHOST,
					},
					.port = PORT_BASE + 17,
				},
				.encrypt = {
					.cipher = REC_AES_CM_128,
					.hmac = REH_HMAC_SHA1,
					.master_key_len = 16,
					.master_salt_len = 14,
					.session_key_len = 16,
					.session_salt_len = 14,
					.rtp_auth_tag_len = 10,
					.rtcp_auth_tag_len = 10,
					.master_key = {0xe1, 0xf9, 0x7a, 0x0d, 0x3e, 0x01, 0x8b, 0xe0,
						0xd6, 0x4f, 0xa3, 0x2c, 0x06, 0xde, 0x41, 0x39},
					.master_salt = {0x0e, 0xc6, 0x75, 0xad, 0x49, 0x8a, 0xfe, 0xeb,
						0xb6, 0x96, 0x0b, 0x3a, 0xab, 0xe6},
				},
			},
		},
	);
	MSG(REMG_ADD_DESTINATION,
		.destination = {
			.local = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 13,
			},
			.num = 2,
			.output = {
				.src_addr = {
					.family = AF_INET,
					.u = {
						.ipv4 = LOCALHOST,
					},
					.port = PORT_BASE + 18,
				},
				.dst_addr = {
					.family = AF_INET,
					.u = {
						.ipv4 = LOCALHOST,
					},
					.port = PORT_BASE + 19,
				},
				.encrypt = {
					.cipher = REC_NULL,
					.hmac = REH_NULL,
				},
			},
		},
	);
	MSG(REMG_ADD_DESTINATION,
		.destination = {
			.local = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 13,
			},
			.num = 3,
			.output = {
				.src_addr = {
					.family = AF_INET,
					.u = {
						.ipv4 = LOCALHOST,
					},
					.port = PORT_BASE + 20,
				},
				.dst_addr = {
					.family = AF_INET,
					.u = {
						.ipv4 = LOCALHOST,
					},
					.port = PORT_BASE + 21,
				},
				.encrypt = {
					.cipher = REC_AES_CM_128,
					.hmac = REH_HMAC_SHA1,
					.master_key_len = 16,
					.master_salt_len = 14,
					.session_key_len = 16,
					.session_salt_len = 14,
					.rtp_auth_tag_len = 10,
					.rtcp_auth_tag_len = 10,
					.master_key = {0xe1, 0xf9, 0x7a, 0x0d, 0x3e, 0x01, 0x8b, 0xe0,
						0xd6, 0x4f, 0xa3, 0x2c, 0x06, 0xde, 0x41, 0x39},
					.master_salt = {0x0e, 0xc6, 0x75, 0xad, 0x49, 0x8a, 0xfe, 0xeb,
						0xb6, 0x96, 0x0b, 0x3a, 0xab, 0xe6},
				},
			},
		},
	);

	SND(40, 13, "\x80\x0f\x12\x34\xde\xca\xfb\xad\xca\xfe\xba\xbe\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab");
	EXPF(15, "\x80\x0f\x12\x34\xde\xca\xfb\xad\xca\xfe\xba\xbe\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab", 14);
	EXPF(17, "\x80\x0f\x12\x34\xde\xca\xfb\xad\xca\xfe\xba\xbe\x4e\x55\xdc\x4c\xe7\x99\x78\xd8\x8c\xa4\xd2\x15\x94\x9d\x24\x02\xb7\x8d\x6a\xcc\x99\xea\x17\x9b\x8d\xbb", 16);
	EXPF(19, "\x80\x0f\x12\x34\xde\xca\xfb\xad\xca\xfe\xba\xbe\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab", 18);
	EXPF(21, "\x80\x0f\x12\x34\xde\xca\xfb\xad\xca\xfe\xba\xbe\x4e\x55\xdc\x4c\xe7\x99\x78\xd8\x8c\xa4\xd2\x15\x94\x9d\x24\x02\xb7\x8d\x6a\xcc\x99\xea\x17\x9b\x8d\xbb", 20);

	// RTCP/SRTCP output
	MSGBUF(REMG_SEND_RTCP,
		"\x81\xc8\x00\x0c\x00\x00\x16\x1cxxxxxxxx\x00\x00\x26\xc0\x00\x00\x00\x25\x00\x00\x18\xdc\x00\x00\x12\x34\x06\x00\x00\x01\x00\x00\x04\x0d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x81\xca\x00\x05\x00\x00\x16\x1c\x01\x0cqwertyuiopas\x00\x00",
		.send_packet = {
			.local = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 13,
			},
			.destination_idx = 0,
			.src_addr = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 14,
			},
			.dst_addr = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 15,
			},
		},
	);
	EXPF(15, "\x81\xc8\x00\x0c\x00\x00\x16\x1cxxxxxxxx\x00\x00\x26\xc0\x00\x00\x00\x25\x00\x00\x18\xdc\x00\x00\x12\x34\x06\x00\x00\x01\x00\x00\x04\x0d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x81\xca\x00\x05\x00\x00\x16\x1c\x01\x0cqwertyuiopas\x00\x00", 14);

	MSGBUF(REMG_SEND_RTCP,
		"\x81\xc8\x00\x0c\x00\x00\x16\x1cxxxxxxxx\x00\x00\x26\xc0\x00\x00\x00\x25\x00\x00\x18\xdc\x00\x00\x12\x34\x06\x00\x00\x01\x00\x00\x04\x0d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x81\xca\x00\x05\x00\x00\x16\x1c\x01\x0cqwertyuiopas\x00\x00",
		.send_packet = {
			.local = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 13,
			},
			.destination_idx = 1,
			.src_addr = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 16,
			},
			.dst_addr = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 17,
			},
		},
	);
	EXPF(17, "\x81\xc8\x00\x0c\x00\x00\x16\x1c\x1c\xbb\xae\x0a\x56\x45\x3d\x64\x42\xe8\x47\x9d\xad\x5e\xad\xe1\x86\x48\x31\x43\xe3\x96\x93\x53\xa9\x4e\xed\x80\xd8\x50\xd3\x6b\xe6\x5e\xaf\x53\x19\xd1\xcb\x72\x2b\xcf\x8c\x10\x67\x8f\x12\x76\x74\xf1\x1d\x09\x30\x55\xb5\xb7\x9f\xef\xb4\x8b\xde\x32\x30\x5b\x80\x9f\x79\xed\x80\x00\x00\x00\x8d\x1f\x12\x4d\x03\x9e\x47\x7e\x76\xbc", 16);

	MSGBUF(REMG_SEND_RTCP,
		"\x81\xc8\x00\x0c\x00\x00\x16\x1cxxxxxxxx\x00\x00\x26\xc0\x00\x00\x00\x25\x00\x00\x18\xdc\x00\x00\x12\x34\x06\x00\x00\x01\x00\x00\x04\x0d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x81\xca\x00\x05\x00\x00\x16\x1c\x01\x0cqwertyuiopas\x00\x00",
		.send_packet = {
			.local = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 13,
			},
			.destination_idx = 3,
			.src_addr = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 20,
			},
			.dst_addr = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 21,
			},
		},
	);
	EXPF(21, "\x81\xc8\x00\x0c\x00\x00\x16\x1c\x1c\xbb\xae\x0a\x56\x45\x3d\x64\x42\xe8\x47\x9d\xad\x5e\xad\xe1\x86\x48\x31\x43\xe3\x96\x93\x53\xa9\x4e\xed\x80\xd8\x50\xd3\x6b\xe6\x5e\xaf\x53\x19\xd1\xcb\x72\x2b\xcf\x8c\x10\x67\x8f\x12\x76\x74\xf1\x1d\x09\x30\x55\xb5\xb7\x9f\xef\xb4\x8b\xde\x32\x30\x5b\x80\x9f\x79\xed\x80\x00\x00\x00\x8d\x1f\x12\x4d\x03\x9e\x47\x7e\x76\xbc", 20);

	MSGBUF(REMG_SEND_RTCP,
		"\x81\xc8\x00\x0c\x00\x00\x16\x1cxxxxxxxx\x00\x00\x26\xc0\x00\x00\x00\x25\x00\x00\x18\xdc\x00\x00\x12\x34\x06\x00\x00\x01\x00\x00\x04\x0d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x81\xca\x00\x05\x00\x00\x16\x1c\x01\x0cqwertyuiopas\x00\x00",
		.send_packet = {
			.local = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 13,
			},
			.destination_idx = 3,
			.src_addr = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 20,
			},
			.dst_addr = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 21,
			},
		},
	);
	EXPF(21, "\x81\xc8\x00\x0c\x00\x00\x16\x1c\xd0\x93\x46\xcf\xb7\xce\x6d\x5a\x3f\xcb\xbc\x2c\xf6\x6b\xa0\xc7\x8a\x24\x17\xa1\x00\x6f\x60\x03\xd0\xec\xa9\x54\x89\x55\x08\xb2\x36\xf0\xd4\xef\x18\xd9\xcb\x8e\x73\xf8\x24\xce\x15\x30\xb3\x59\xc6\xe3\xd0\xce\x60\x2f\xb3\xed\xea\xe7\x23\x93\x80\x10\x60\x7f\x39\x86\xf0\x6c\x80\x00\x00\x01\xfe\x43\x8f\x15\x0a\x7c\xfd\x6b\xfa\xe0", 20);

	// SRTP suites
	// AES CM 128
	// encrypt
	MSG(REMG_ADD_TARGET,
		.target = {
			.local = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 22,
			},
			.expected_src = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = 5555,
			},
			.decrypt = {
				.cipher = REC_NULL,
				.hmac = REH_NULL,
			},
			.src_mismatch = MSM_IGNORE,
			.num_destinations = 1,
			.rtp = 1,

			.num_payload_types = 1,
			.payload_types = {
				{
					.pt_num = 0x8,
					.clock_rate = 8000,
				},
			},
		},
	);
	MSG(REMG_ADD_DESTINATION,
		.destination = {
			.local = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 22,
			},
			.num = 0,
			.output = {
				.src_addr = {
					.family = AF_INET,
					.u = {
						.ipv4 = LOCALHOST,
					},
					.port = PORT_BASE + 23,
				},
				.dst_addr = {
					.family = AF_INET,
					.u = {
						.ipv4 = LOCALHOST,
					},
					.port = PORT_BASE + 24,
				},
				.encrypt = {
					.cipher = REC_AES_CM_128,
					.hmac = REH_HMAC_SHA1,
					.master_key_len = 16,
					.master_salt_len = 14,
					.session_key_len = 16,
					.session_salt_len = 14,
					.rtp_auth_tag_len = 10,
					.master_key = {0x86, 0x70, 0x84, 0x51, 0x5a, 0xa4, 0xf7, 0x73,
						0xd0, 0xcd, 0x56, 0xd0, 0x32, 0x34, 0x5b, 0x0b},
					.master_salt = {0xc1, 0xe3, 0xb1, 0x54, 0x17, 0x3d, 0xf1, 0x3f,
						0xb6, 0xa3, 0x86, 0x41, 0xc4, 0x0b},
				},
			},
		},
	);
	// decrypt
	MSG(REMG_ADD_TARGET,
		.target = {
			.local = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 23,
			},
			.expected_src = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = 5555,
			},
			.decrypt = {
				.cipher = REC_AES_CM_128,
				.hmac = REH_HMAC_SHA1,
				.master_key_len = 16,
				.master_salt_len = 14,
				.session_key_len = 16,
				.session_salt_len = 14,
				.rtp_auth_tag_len = 10,
				.master_key = {0x86, 0x70, 0x84, 0x51, 0x5a, 0xa4, 0xf7, 0x73,
					0xd0, 0xcd, 0x56, 0xd0, 0x32, 0x34, 0x5b, 0x0b},
				.master_salt = {0xc1, 0xe3, 0xb1, 0x54, 0x17, 0x3d, 0xf1, 0x3f,
					0xb6, 0xa3, 0x86, 0x41, 0xc4, 0x0b},
			},
			.src_mismatch = MSM_IGNORE,
			.num_destinations = 1,
			.rtp = 1,

			.num_payload_types = 1,
			.payload_types = {
				{
					.pt_num = 0x8,
					.clock_rate = 8000,
				},
			},
		},
	);
	MSG(REMG_ADD_DESTINATION,
		.destination = {
			.local = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 23,
			},
			.num = 0,
			.output = {
				.src_addr = {
					.family = AF_INET,
					.u = {
						.ipv4 = LOCALHOST,
					},
					.port = PORT_BASE + 22,
				},
				.dst_addr = {
					.family = AF_INET,
					.u = {
						.ipv4 = LOCALHOST,
					},
					.port = PORT_BASE + 25,
				},
				.encrypt = {
					.cipher = REC_NULL,
					.hmac = REH_NULL,
				},
			},
		},
	);
	SND(40, 22, "\x80\x08\x2d\x69\xad\x59\xbd\x9f\x7f\x19\x4c\xcb\x51\x57\xd5\xd4\xd4\xd5\x54\x56\x56\x57\x56\x51\x57\xd5\xd7\xd7\xd7\xd5\xd5\xd7\xd7\xd7\xd7\xd4\xd7\xd5\xd5\xd4\xd4\xd7\xd7\xd7\xd7\xd4\xd4\x54\x50\x52\x53\x53\x51\x50\x51\x57\x54\xd5\xd6\xd0\xd3\xd0\xd6\xd6\xd7\xd7\xd7\xd5\xd4\xd6\xd0\xd2\xd0\xd1\xd6\x55\x54\x57\x50\x51\x54\xd5\xd5\x54\x54\xd4\xd7\xd1\xd7\xd5\xd4\xd4\xd5\x54\x54\x55\x57\x56\x54\x54\x55\xd6\xd1\xd7\xd5\x54\x55\x57\x51\x51\x51\x51\x55\xd7\xd6\xd1\xd0\xd0\xd7\xd6\xd1\xd4\x54\xd5\xd4\xd5\xd5\xd6\xd6\xd4\xd4\xd6\xd7\x54\x53\x52\x52\x52\x52\x53\x5d\x52\x56\xd7\xd7\xd5\xd5\xd5\x55\x54\x54\x51\x50\x56\xd4\xd6\xd6\xd7\xd0\xd2\xd3\xd0\xd6\x54\x51\x53\x53\x50\x56\x57\x56\x54");
	EXPF(24, "\x80\x08\x2d\x69\xad\x59\xbd\x9f\x7f\x19\x4c\xcb\xe1\x2e\x4f\x7b\x81\x89\xf4\xce\xc0\x62\x3a\x38\x06\xa3\x39\x4b\xaa\x3d\x0f\xd5\xaf\x41\xa8\xc9\x34\xfe\x37\x49\x1b\x29\x08\xd5\x01\x6c\x54\x59\x9a\x16\xcf\xdf\xcb\x23\xc2\x87\xa2\x5d\x06\x1e\x30\xef\x5a\x48\xc3\x8c\x48\x30\xae\x5e\x91\x41\x3a\xa3\x81\x08\xdc\xa4\x50\xd9\x78\xac\xb3\xe2\x78\x84\xb2\xb7\xe7\xe3\xd4\x77\xb9\x11\x72\x18\x85\xee\xf2\xfc\x4c\xf8\x73\xb3\x3a\x04\x95\x26\x26\x4d\x71\xcc\x6e\x24\x3b\xfc\x7b\x4e\x4d\x87\x4f\x3b\xf9\x96\x13\x61\x15\x1e\xbe\xd3\xed\x3a\xa0\x5e\x57\x17\x26\x8f\x58\x0b\xf4\xb9\x6f\xe9\xd4\x4c\x15\x2e\xa9\x3b\xee\xf7\xfe\x39\x48\x33\xe5\x03\x35\xa6\x9d\xb1\x84\x9b\x25\x25\x06\x18\x1d\x34\xea\x26\x8a\x9e\x47\x54\xe3\xc1\x78\x15\x9c\x5e", 23);
	SND(40, 23, "\x80\x08\x2d\x69\xad\x59\xbd\x9f\x7f\x19\x4c\xcb\xe1\x2e\x4f\x7b\x81\x89\xf4\xce\xc0\x62\x3a\x38\x06\xa3\x39\x4b\xaa\x3d\x0f\xd5\xaf\x41\xa8\xc9\x34\xfe\x37\x49\x1b\x29\x08\xd5\x01\x6c\x54\x59\x9a\x16\xcf\xdf\xcb\x23\xc2\x87\xa2\x5d\x06\x1e\x30\xef\x5a\x48\xc3\x8c\x48\x30\xae\x5e\x91\x41\x3a\xa3\x81\x08\xdc\xa4\x50\xd9\x78\xac\xb3\xe2\x78\x84\xb2\xb7\xe7\xe3\xd4\x77\xb9\x11\x72\x18\x85\xee\xf2\xfc\x4c\xf8\x73\xb3\x3a\x04\x95\x26\x26\x4d\x71\xcc\x6e\x24\x3b\xfc\x7b\x4e\x4d\x87\x4f\x3b\xf9\x96\x13\x61\x15\x1e\xbe\xd3\xed\x3a\xa0\x5e\x57\x17\x26\x8f\x58\x0b\xf4\xb9\x6f\xe9\xd4\x4c\x15\x2e\xa9\x3b\xee\xf7\xfe\x39\x48\x33\xe5\x03\x35\xa6\x9d\xb1\x84\x9b\x25\x25\x06\x18\x1d\x34\xea\x26\x8a\x9e\x47\x54\xe3\xc1\x78\x15\x9c\x5e");
	EXPF(25, "\x80\x08\x2d\x69\xad\x59\xbd\x9f\x7f\x19\x4c\xcb\x51\x57\xd5\xd4\xd4\xd5\x54\x56\x56\x57\x56\x51\x57\xd5\xd7\xd7\xd7\xd5\xd5\xd7\xd7\xd7\xd7\xd4\xd7\xd5\xd5\xd4\xd4\xd7\xd7\xd7\xd7\xd4\xd4\x54\x50\x52\x53\x53\x51\x50\x51\x57\x54\xd5\xd6\xd0\xd3\xd0\xd6\xd6\xd7\xd7\xd7\xd5\xd4\xd6\xd0\xd2\xd0\xd1\xd6\x55\x54\x57\x50\x51\x54\xd5\xd5\x54\x54\xd4\xd7\xd1\xd7\xd5\xd4\xd4\xd5\x54\x54\x55\x57\x56\x54\x54\x55\xd6\xd1\xd7\xd5\x54\x55\x57\x51\x51\x51\x51\x55\xd7\xd6\xd1\xd0\xd0\xd7\xd6\xd1\xd4\x54\xd5\xd4\xd5\xd5\xd6\xd6\xd4\xd4\xd6\xd7\x54\x53\x52\x52\x52\x52\x53\x5d\x52\x56\xd7\xd7\xd5\xd5\xd5\x55\x54\x54\x51\x50\x56\xd4\xd6\xd6\xd7\xd0\xd2\xd3\xd0\xd6\x54\x51\x53\x53\x50\x56\x57\x56\x54", 22);

	// AEAD AES GCM 256
	// encrypt
	MSG(REMG_ADD_TARGET,
		.target = {
			.local = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 26,
			},
			.expected_src = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = 5555,
			},
			.decrypt = {
				.cipher = REC_NULL,
				.hmac = REH_NULL,
			},
			.src_mismatch = MSM_IGNORE,
			.num_destinations = 1,
			.rtp = 1,

			.num_payload_types = 1,
			.payload_types = {
				{
					.pt_num = 0x8,
					.clock_rate = 8000,
				},
			},
		},
	);
	MSG(REMG_ADD_DESTINATION,
		.destination = {
			.local = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 26,
			},
			.num = 0,
			.output = {
				.src_addr = {
					.family = AF_INET,
					.u = {
						.ipv4 = LOCALHOST,
					},
					.port = PORT_BASE + 27,
				},
				.dst_addr = {
					.family = AF_INET,
					.u = {
						.ipv4 = LOCALHOST,
					},
					.port = PORT_BASE + 28,
				},
				.encrypt = {
					.cipher = REC_AEAD_AES_GCM_256,
					.hmac = REH_NULL,
					.master_key_len = 32,
					.master_salt_len = 12,
					.session_key_len = 32,
					.session_salt_len = 12,
					.rtp_auth_tag_len = 0,
					.master_key = {0x81, 0xa4, 0xe5, 0x86, 0x21, 0x62, 0x6c, 0x57,
						0x9c, 0x5b, 0x8b, 0x2f, 0x1e, 0x27, 0x6a, 0x69,
						0x3c, 0xf2, 0xd5, 0xf6, 0xd0, 0xbc, 0x9a, 0x53,
						0x7c, 0x71, 0xdf, 0x22, 0x95, 0x38, 0x4c, 0xb2},
					.master_salt = {0x33, 0xaa, 0xf1, 0x5f, 0x42, 0x81, 0x10, 0x58,
						0xb0, 0x03, 0x8c, 0x0c},
				},
			},
		},
	);
	// decrypt
	MSG(REMG_ADD_TARGET,
		.target = {
			.local = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 27,
			},
			.expected_src = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = 5555,
			},
			.decrypt = {
				.cipher = REC_AEAD_AES_GCM_256,
				.hmac = REH_NULL,
				.master_key_len = 32,
				.master_salt_len = 12,
				.session_key_len = 32,
				.session_salt_len = 12,
				.rtp_auth_tag_len = 0,
				.master_key = {0x81, 0xa4, 0xe5, 0x86, 0x21, 0x62, 0x6c, 0x57,
					0x9c, 0x5b, 0x8b, 0x2f, 0x1e, 0x27, 0x6a, 0x69,
					0x3c, 0xf2, 0xd5, 0xf6, 0xd0, 0xbc, 0x9a, 0x53,
					0x7c, 0x71, 0xdf, 0x22, 0x95, 0x38, 0x4c, 0xb2},
				.master_salt = {0x33, 0xaa, 0xf1, 0x5f, 0x42, 0x81, 0x10, 0x58,
					0xb0, 0x03, 0x8c, 0x0c},
			},
			.src_mismatch = MSM_IGNORE,
			.num_destinations = 1,
			.rtp = 1,

			.num_payload_types = 1,
			.payload_types = {
				{
					.pt_num = 0x8,
					.clock_rate = 8000,
				},
			},
		},
	);
	MSG(REMG_ADD_DESTINATION,
		.destination = {
			.local = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 27,
			},
			.num = 0,
			.output = {
				.src_addr = {
					.family = AF_INET,
					.u = {
						.ipv4 = LOCALHOST,
					},
					.port = PORT_BASE + 26,
				},
				.dst_addr = {
					.family = AF_INET,
					.u = {
						.ipv4 = LOCALHOST,
					},
					.port = PORT_BASE + 29,
				},
				.encrypt = {
					.cipher = REC_NULL,
					.hmac = REH_NULL,
				},
			},
		},
	);
	SND(40, 26, "\x80\x08\x44\x0d\xc2\x3e\xd8\xc0\x21\x9f\x0b\x2e\x57\x55\x55\xd5\xd6\xd1\xd1\xd1\xd4\x55\x57\x56\x54\xd5\xd6\xd4\x55\xd5\xd4\xd1\xd0\xd7\xd4\x54\x54\x55\x55\x57\x51\x56\x56\x55\xd7\xd1\xd6\xd7\xd7\xd7\xd0\xd1\xd1\xd7\x55\x56\x51\x50\x51\x56\x50\x50\x52\x53\xd5\xdc\xdc\xd1\x55\x56\xd5\xdd\xdc\xd3\x57\x53\x53\x54\x57\x54\x54\x54\x54\xd5\x55\xd4\xd6\xd7\x54\x57\x56\x54\x55\x57\x5d\x5c\x53\x56\xd7\xd6\xd4\xd5\xd4\xd6\xd1\xd6\xd7\xd4\x55\x55\xd5\x55\x55\xd1\xd3\xd0\xd3\xdd\xd1\xd0\xd0\xd1\xd6\xd6\xd5\x55\x55\x56\x50\x53\x5f\x5e\x5f\x5d\x50\x56\x50\x56\x54\xd4\xd7\xd6\x55\x53\x5d\x56\xd6\xd0\xd6\x56\x5d\x5f\x51\xd0\xd3\xd4\x54\x54\xd4\xd1\xd6\xd6\xd1\xd1\xd6\xd4\xd5\x55\xd6\xd7\x55\x57");
	EXPF(28, "\x80\x08\x44\x0d\xc2\x3e\xd8\xc0\x21\x9f\x0b\x2e\xd0\x42\xf4\x50\xbb\x7d\x73\xab\xb9\x4e\xd8\x65\xe8\xbf\xeb\xfb\xdc\xdf\xf3\xa6\x63\x58\x84\x37\x49\xc9\xc9\x61\xd9\x43\x51\xde\xfa\x1f\xe5\x34\x9d\x05\x30\x0f\x06\x4f\xb1\x81\x13\x8c\x84\xb2\x26\x93\x0c\x8f\xf1\x6a\x97\x7b\x8c\xe0\xc8\x0a\x66\xe3\xdc\xe4\xd3\xec\x4e\xa5\x8d\x58\x55\x71\x2a\x19\x7c\xad\x55\x46\xe9\xcb\xb4\x79\xde\x8c\x2f\x33\xea\x70\x1b\x08\x4f\xf4\xf4\x2f\x2c\xe6\xb8\x5e\x2a\x65\xab\x06\x74\xbf\xc4\xb1\xc8\x27\x54\x53\xaf\xe8\xca\x1f\x75\xfa\x23\xe9\x6b\x2b\x3e\xed\x4d\x67\x4c\x71\x4c\x53\x74\x4b\x1e\xa7\x5b\x75\x49\x6b\xb3\x64\x6b\x0e\xa5\x12\x8f\x46\x2b\x7d\x17\x54\x2a\x75\xd1\x42\x6b\x7a\xbf\x0e\xd7\x19\x4a\x96\xea\xd9\xd1\xc8\x12\x30\xc3\x33\x4f\xc6\xa6\x0e\x36\xe0\x1f\x0c", 27);
	SND(40, 27, "\x80\x08\x44\x0d\xc2\x3e\xd8\xc0\x21\x9f\x0b\x2e\xd0\x42\xf4\x50\xbb\x7d\x73\xab\xb9\x4e\xd8\x65\xe8\xbf\xeb\xfb\xdc\xdf\xf3\xa6\x63\x58\x84\x37\x49\xc9\xc9\x61\xd9\x43\x51\xde\xfa\x1f\xe5\x34\x9d\x05\x30\x0f\x06\x4f\xb1\x81\x13\x8c\x84\xb2\x26\x93\x0c\x8f\xf1\x6a\x97\x7b\x8c\xe0\xc8\x0a\x66\xe3\xdc\xe4\xd3\xec\x4e\xa5\x8d\x58\x55\x71\x2a\x19\x7c\xad\x55\x46\xe9\xcb\xb4\x79\xde\x8c\x2f\x33\xea\x70\x1b\x08\x4f\xf4\xf4\x2f\x2c\xe6\xb8\x5e\x2a\x65\xab\x06\x74\xbf\xc4\xb1\xc8\x27\x54\x53\xaf\xe8\xca\x1f\x75\xfa\x23\xe9\x6b\x2b\x3e\xed\x4d\x67\x4c\x71\x4c\x53\x74\x4b\x1e\xa7\x5b\x75\x49\x6b\xb3\x64\x6b\x0e\xa5\x12\x8f\x46\x2b\x7d\x17\x54\x2a\x75\xd1\x42\x6b\x7a\xbf\x0e\xd7\x19\x4a\x96\xea\xd9\xd1\xc8\x12\x30\xc3\x33\x4f\xc6\xa6\x0e\x36\xe0\x1f\x0c");
	EXPF(29, "\x80\x08\x44\x0d\xc2\x3e\xd8\xc0\x21\x9f\x0b\x2e\x57\x55\x55\xd5\xd6\xd1\xd1\xd1\xd4\x55\x57\x56\x54\xd5\xd6\xd4\x55\xd5\xd4\xd1\xd0\xd7\xd4\x54\x54\x55\x55\x57\x51\x56\x56\x55\xd7\xd1\xd6\xd7\xd7\xd7\xd0\xd1\xd1\xd7\x55\x56\x51\x50\x51\x56\x50\x50\x52\x53\xd5\xdc\xdc\xd1\x55\x56\xd5\xdd\xdc\xd3\x57\x53\x53\x54\x57\x54\x54\x54\x54\xd5\x55\xd4\xd6\xd7\x54\x57\x56\x54\x55\x57\x5d\x5c\x53\x56\xd7\xd6\xd4\xd5\xd4\xd6\xd1\xd6\xd7\xd4\x55\x55\xd5\x55\x55\xd1\xd3\xd0\xd3\xdd\xd1\xd0\xd0\xd1\xd6\xd6\xd5\x55\x55\x56\x50\x53\x5f\x5e\x5f\x5d\x50\x56\x50\x56\x54\xd4\xd7\xd6\x55\x53\x5d\x56\xd6\xd0\xd6\x56\x5d\x5f\x51\xd0\xd3\xd4\x54\x54\xd4\xd1\xd6\xd6\xd1\xd1\xd6\xd4\xd5\x55\xd6\xd7\x55\x57", 26);

	// RTCP/SRTCP output
	MSGBUF(REMG_SEND_RTCP, send_packet,
		"\x81\xc8\x00\x0c\x00\x00\x16\x1cxxxxxxxx\x00\x00\x26\xc0\x00\x00\x00\x25\x00\x00\x18\xdc\x00\x00\x12\x34\x06\x00\x00\x01\x00\x00\x04\x0d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x81\xca\x00\x05\x00\x00\x16\x1c\x01\x0cqwertyuiopas\x00\x00",
			.local = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 26,
			},
			.destination_idx = 0,
			.src_addr = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 27,
			},
			.dst_addr = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 28,
			},
	);
	EXPF(28, "\x81\xc8\x00\x0c\x00\x00\x16\x1c\x96\xe5\xb7\xf4\x34\x2e\xed\xfa\x59\xed\x4d\x77\x30\x96\x2a\xb3\x62\x5b\xe9\x4d\x06\xfe\x70\xb2\x9a\x4b\xb9\x27\x14\x78\x64\x15\x0c\xe6\xe6\x0d\xcc\x2f\x7f\x5f\x21\xf3\xfa\x03\x6f\xd2\xc1\xb5\x9c\x12\x76\x1b\x68\xe8\x12\xc8\xa7\x6d\x79\xce\x13\x14\xce\x33\x36\x58\x98\x6f\xe7\x95\xb5\x35\x0c\x25\x92\xbe\x2e\xb3\xb6\x2d\x51\x38\xfb\x09\x80\x00\x00\x00", 27);

	// SRTCP SSRC index tracking
	MSG(REMG_ADD_TARGET,
		.target = {
			.local = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 30,
			},
			.expected_src = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = 5555,
			},
			.decrypt = {
				.cipher = REC_NULL,
				.hmac = REH_NULL,
			},
			.src_mismatch = MSM_IGNORE,
			.num_destinations = 1,
			.rtp = 1,

			.num_payload_types = 1,
			.payload_types = {
				{
					.pt_num = 0xf,
					.clock_rate = 8000,
				},
			},

			.ssrc = {htonl(0x12345678), htonl(0x87654321), 0, 0,},
		},
	);
	MSG(REMG_ADD_DESTINATION,
		.destination = {
			.local = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 30,
			},
			.num = 0,
			.output = {
				.src_addr = {
					.family = AF_INET,
					.u = {
						.ipv4 = LOCALHOST,
					},
					.port = PORT_BASE + 31,
				},
				.dst_addr = {
					.family = AF_INET,
					.u = {
						.ipv4 = LOCALHOST,
					},
					.port = PORT_BASE + 32,
				},
				.encrypt = {
					.cipher = REC_AES_CM_128,
					.hmac = REH_HMAC_SHA1,
					.master_key_len = 16,
					.master_salt_len = 14,
					.session_key_len = 16,
					.session_salt_len = 14,
					.rtp_auth_tag_len = 10,
					.rtcp_auth_tag_len = 10,
					.master_key = {0xe1, 0xf9, 0x7a, 0x0d, 0x3e, 0x01, 0x8b, 0xe0,
						0xd6, 0x4f, 0xa3, 0x2c, 0x06, 0xde, 0x41, 0x39},
					.master_salt = {0x0e, 0xc6, 0x75, 0xad, 0x49, 0x8a, 0xfe, 0xeb,
						0xb6, 0x96, 0x0b, 0x3a, 0xab, 0xe6},
				},
			},
		},
	);

	MSGBUF(REMG_SEND_RTCP,
		"\x81\xc8\x00\x0c\x12\x34\x56\x78xxxxxxxx\x00\x00\x26\xc0\x00\x00\x00\x25\x00\x00\x18\xdc\x00\x00\x12\x34\x06\x00\x00\x01\x00\x00\x04\x0d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x81\xca\x00\x05\x00\x00\x16\x1c\x01\x0cqwertyuiopas\x00\x00",
		.send_packet = {
			.local = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 30,
			},
			.destination_idx = 0,
			.src_addr = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 31,
			},
			.dst_addr = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 32,
			},
		},
	);
	EXPF(32, "\x81\xc8\x00\x0c\x12\x34\x56\x78\x09\x11\x4b\x0c\x97\xba\x5c\x20\x2c\x0c\x52\x0c\xea\x0c\xe6\x5b\x8f\x66\xad\x0d\x0b\x84\xb7\x9e\x0c\x6b\x80\xbc\xb1\x94\xb3\x1a\x0a\x1a\x30\x18\x06\xc7\x14\x91\x5a\xb1\xae\xd1\xee\x23\x64\x54\x82\x65\x27\x9c\x3e\xcd\xdc\x87\xff\x68\x84\x7c\x17\x6d\xd7\xc8\xae\xb6\x4b\x73\x80\x00\x00\x00\x00\x0b\x24\x46\x81\xdd\x28\x6b\xe8\xac", 31);

	MSGBUF(REMG_SEND_RTCP,
		"\x81\xc8\x00\x0c\x12\x34\x56\x78xxxxxxxx\x00\x00\x26\xc0\x00\x00\x00\x25\x00\x00\x18\xdc\x00\x00\x12\x34\x06\x00\x00\x01\x00\x00\x04\x0d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x81\xca\x00\x05\x00\x00\x16\x1c\x01\x0cqwertyuiopas\x00\x00",
		.send_packet = {
			.local = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 30,
			},
			.destination_idx = 0,
			.src_addr = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 31,
			},
			.dst_addr = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 32,
			},
		},
	);
	EXPF(32, "\x81\xc8\x00\x0c\x12\x34\x56\x78\x04\xf8\xc2\xb5\x4e\x74\xc8\xa2\x35\x9d\x2f\x11\x67\x2f\xb9\xee\x89\xf9\xd8\xd7\x27\x80\xf6\xe5\x06\xff\xae\x5f\x7b\x3e\xd1\x7b\xa9\x35\xac\x48\x21\xf6\x52\xfc\x8e\xab\x1e\xa1\x62\x36\x45\x2f\x4d\xb0\x75\x36\xdf\x63\x48\xdc\xae\x7d\x4c\x56\x2b\x0d\x21\xc9\x0b\xbb\x81\x55\x80\x00\x00\x01\x3b\xb6\x51\x08\x1d\xb6\x0b\xc2\x62\x4b", 31);

	MSGBUF(REMG_SEND_RTCP,
		"\x81\xc8\x00\x0c\x87\x65\x43\x21xxxxxxxx\x00\x00\x26\xc0\x00\x00\x00\x25\x00\x00\x18\xdc\x00\x00\x12\x34\x06\x00\x00\x01\x00\x00\x04\x0d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x81\xca\x00\x05\x00\x00\x16\x1c\x01\x0cqwertyuiopas\x00\x00",
		.send_packet = {
			.local = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 30,
			},
			.destination_idx = 0,
			.src_addr = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 31,
			},
			.dst_addr = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 32,
			},
		},
	);
	EXPF(32, "\x81\xc8\x00\x0c\x87\x65\x43\x21\xe0\x5d\x5d\x6e\x68\xc4\xcc\x58\xd8\xed\xfb\x58\x9f\xdc\xac\x39\x11\x36\x63\x69\xa1\xf9\x12\x22\x0d\x85\xec\x55\x93\xf7\xf3\x8d\xfd\x39\xe9\x55\xee\x70\x73\x0c\x55\xf4\x41\x6e\x68\xe7\xa9\x1c\x25\x50\x3f\x3c\x3a\xa7\x49\x3a\x38\xee\xf3\x95\x4b\x78\x9f\x6e\x07\x16\x78\x2f\x80\x00\x00\x00\x74\x3b\xc2\xd6\x6a\x20\xa5\x20\xd6\x9a", 31);

	MSGBUF(REMG_SEND_RTCP,
		"\x81\xc8\x00\x0c\x87\x65\x43\x21xxxxxxxx\x00\x00\x26\xc0\x00\x00\x00\x25\x00\x00\x18\xdc\x00\x00\x12\x34\x06\x00\x00\x01\x00\x00\x04\x0d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x81\xca\x00\x05\x00\x00\x16\x1c\x01\x0cqwertyuiopas\x00\x00",
		.send_packet = {
			.local = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 30,
			},
			.destination_idx = 0,
			.src_addr = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 31,
			},
			.dst_addr = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 32,
			},
		},
	);
	EXPF(32, "\x81\xc8\x00\x0c\x87\x65\x43\x21\xa8\xf0\x49\x6a\x19\x93\x12\xb7\x15\x08\xaf\xea\x9f\xb8\x07\x51\x0b\x21\xfc\xd2\xcd\x34\x80\x9b\x17\x3d\xfe\xf6\x34\x74\x09\x33\xdb\x77\xb8\xfc\x24\x27\x52\xdf\x47\xe0\xe2\x42\x51\x8b\x99\x56\x3f\x86\x3b\x4f\xe1\x1a\x2e\xc1\xaa\x19\x3f\xae\xae\x0e\xd8\x6d\x0d\xd1\x72\xa4\x80\x00\x00\x01\x86\xe0\x95\x0b\x40\x1f\xa0\x75\x18\x71", 31);

	// SRTCP decryption, AES-CM-128
	MSG(REMG_ADD_TARGET, target,
			.local = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 33,
			},
			.expected_src = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = 5555,
			},
			.decrypt = {
				.cipher = REC_AES_CM_128,
				.hmac = REH_HMAC_SHA1,
				.master_key_len = 16,
				.master_salt_len = 14,
				.session_key_len = 16,
				.session_salt_len = 14,
				.rtp_auth_tag_len = 10,
				.rtcp_auth_tag_len = 10,
				.master_key = {0xe1, 0xf9, 0x7a, 0x0d, 0x3e, 0x01, 0x8b, 0xe0,
					0xd6, 0x4f, 0xa3, 0x2c, 0x06, 0xde, 0x41, 0x39},
				.master_salt = {0x0e, 0xc6, 0x75, 0xad, 0x49, 0x8a, 0xfe, 0xeb,
					0xb6, 0x96, 0x0b, 0x3a, 0xab, 0xe6},
			},
			.src_mismatch = MSM_IGNORE,
			.num_destinations = 1,
			.rtp = 1,
			.rtcp = 1,
			.rtcp_fw = 1,

			.num_payload_types = 1,
			.payload_types = {
				{
					.pt_num = 0xf,
					.clock_rate = 8000,
				},
			},
	);
	MSG(REMG_ADD_DESTINATION, destination,
			.local = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 33,
			},
			.num = 0,
			.output = {
				.src_addr = {
					.family = AF_INET,
					.u = {
						.ipv4 = LOCALHOST,
					},
					.port = PORT_BASE + 34,
				},
				.dst_addr = {
					.family = AF_INET,
					.u = {
						.ipv4 = LOCALHOST,
					},
					.port = PORT_BASE + 35,
				},
				.encrypt = {
					.cipher = REC_NULL,
					.hmac = REH_NULL,
				},
			},
	);

	SND(40, 33, "\x81\xc8\x00\x0c\x12\x34\x56\x78\x09\x11\x4b\x0c\x97\xba\x5c\x20\x2c\x0c\x52\x0c\xea\x0c\xe6\x5b\x8f\x66\xad\x0d\x0b\x84\xb7\x9e\x0c\x6b\x80\xbc\xb1\x94\xb3\x1a\x0a\x1a\x30\x18\x06\xc7\x14\x91\x5a\xb1\xae\xd1\xee\x23\x64\x54\x82\x65\x27\x9c\x3e\xcd\xdc\x87\xff\x68\x84\x7c\x17\x6d\xd7\xc8\xae\xb6\x4b\x73\x80\x00\x00\x00\x00\x0b\x24\x46\x81\xdd\x28\x6b\xe8\xac");
	EXPF(35, "\x81\xc8\x00\x0c\x12\x34\x56\x78xxxxxxxx\x00\x00\x26\xc0\x00\x00\x00\x25\x00\x00\x18\xdc\x00\x00\x12\x34\x06\x00\x00\x01\x00\x00\x04\x0d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x81\xca\x00\x05\x00\x00\x16\x1c\x01\x0cqwertyuiopas\x00\x00", 34);

	// SRTCP decryption, AES-GCM
	MSG(REMG_ADD_TARGET, target,
			.local = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 36,
			},
			.expected_src = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = 5555,
			},
			.decrypt = {
				.cipher = REC_AEAD_AES_GCM_256,
				.hmac = REH_NULL,
				.master_key_len = 32,
				.master_salt_len = 12,
				.session_key_len = 32,
				.session_salt_len = 12,
				.rtp_auth_tag_len = 0,
				.master_key = {0x81, 0xa4, 0xe5, 0x86, 0x21, 0x62, 0x6c, 0x57,
					0x9c, 0x5b, 0x8b, 0x2f, 0x1e, 0x27, 0x6a, 0x69,
					0x3c, 0xf2, 0xd5, 0xf6, 0xd0, 0xbc, 0x9a, 0x53,
					0x7c, 0x71, 0xdf, 0x22, 0x95, 0x38, 0x4c, 0xb2},
				.master_salt = {0x33, 0xaa, 0xf1, 0x5f, 0x42, 0x81, 0x10, 0x58,
					0xb0, 0x03, 0x8c, 0x0c},
			},
			.src_mismatch = MSM_IGNORE,
			.num_destinations = 1,
			.rtp = 1,
			.rtcp = 1,
			.rtcp_fw = 1,

			.num_payload_types = 1,
			.payload_types = {
				{
					.pt_num = 0xf,
					.clock_rate = 8000,
				},
			},
	);
	MSG(REMG_ADD_DESTINATION, destination,
			.local = {
				.family = AF_INET,
				.u = {
					.ipv4 = LOCALHOST,
				},
				.port = PORT_BASE + 36,
			},
			.num = 0,
			.output = {
				.src_addr = {
					.family = AF_INET,
					.u = {
						.ipv4 = LOCALHOST,
					},
					.port = PORT_BASE + 37,
				},
				.dst_addr = {
					.family = AF_INET,
					.u = {
						.ipv4 = LOCALHOST,
					},
					.port = PORT_BASE + 38,
				},
				.encrypt = {
					.cipher = REC_NULL,
					.hmac = REH_NULL,
				},
			},
	);

	SND(40, 36, "\x81\xc8\x00\x0c\x00\x00\x16\x1c\x96\xe5\xb7\xf4\x34\x2e\xed\xfa\x59\xed\x4d\x77\x30\x96\x2a\xb3\x62\x5b\xe9\x4d\x06\xfe\x70\xb2\x9a\x4b\xb9\x27\x14\x78\x64\x15\x0c\xe6\xe6\x0d\xcc\x2f\x7f\x5f\x21\xf3\xfa\x03\x6f\xd2\xc1\xb5\x9c\x12\x76\x1b\x68\xe8\x12\xc8\xa7\x6d\x79\xce\x13\x14\xce\x33\x36\x58\x98\x6f\xe7\x95\xb5\x35\x0c\x25\x92\xbe\x2e\xb3\xb6\x2d\x51\x38\xfb\x09\x80\x00\x00\x00");
	EXPF(38, "\x81\xc8\x00\x0c\x00\x00\x16\x1cxxxxxxxx\x00\x00\x26\xc0\x00\x00\x00\x25\x00\x00\x18\xdc\x00\x00\x12\x34\x06\x00\x00\x01\x00\x00\x04\x0d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x81\xca\x00\x05\x00\x00\x16\x1c\x01\x0cqwertyuiopas\x00\x00", 37);

	return 0;
}
