#include <stdio.h>
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
#include "../kernel-module/xt_RTPENGINE.h"

#define NUM_SOCKETS 41
#define PORT_BASE 37526
#define LOCALHOST htonl(0x7f000001)
#define LEN(x) (sizeof(x)-1)

#define MSG(op, args...) \
	printf("exec %s:%i\n", __FILE__, __LINE__); \
	rm = (struct rtpengine_message) { .cmd = op, .u = { args } }; \
	ret = write(fd, &rm, sizeof(rm)); \
	printf("ret = %i\n", ret); \
	assert(ret == sizeof(rm));

#define SND(sock, port, data) \
	printf("exec %s:%i\n", __FILE__, __LINE__); \
	{ \
		struct sockaddr_in sin = { \
			.sin_family = AF_INET, \
			.sin_port = htons(PORT_BASE + port), \
			.sin_addr = { LOCALHOST }, \
		}; \
		ret = sendto(fds[sock], data, LEN(data), 0, (struct sockaddr *) &sin, sizeof(sin)); \
		printf("ret = %i\n", ret); \
		assert(ret == LEN(data)); \
	}
#define EXP(sock, data) \
	printf("exec %s:%i\n", __FILE__, __LINE__); \
	{ \
		char buf[65535]; \
		alarm(1); \
		ret = recv(fds[sock], buf, sizeof(buf), 0); \
		alarm(0); \
		printf("ret = %i\n", ret); \
		assert(ret == LEN(data)); \
		buf[ret] = '\0'; \
		printf("data ="); \
		for (int __i = 0; __i < ret; __i++) \
			printf(" %02x", (unsigned char) buf[__i]); \
		printf("\n"); \
		assert(strcmp(data, buf) == 0); \
	}
#define EXPF(sock, data, port) \
	printf("exec %s:%i\n", __FILE__, __LINE__); \
	{ \
		struct sockaddr_in sin = { 0, }; \
		socklen_t sinlen = sizeof(sin); \
		char buf[65535]; \
		alarm(1); \
		ret = recvfrom(fds[sock], buf, sizeof(buf), 0, (struct sockaddr *) &sin, &sinlen); \
		alarm(0); \
		printf("ret = %i\n", ret); \
		assert(ret == LEN(data)); \
		buf[ret] = '\0'; \
		printf("data ="); \
		for (int __i = 0; __i < ret; __i++) \
			printf(" %02x", (unsigned char) buf[__i]); \
		printf("\n"); \
		assert(strcmp(data, buf) == 0); \
		assert(sin.sin_family == AF_INET); \
		assert(sin.sin_addr.s_addr == LOCALHOST); \
		assert(sin.sin_port == htons(PORT_BASE + port)); \
	}

int main(void) {
	int fd = open("/proc/rtpengine/0/control", O_RDWR);
	assert(fd != -1);

	struct rtpengine_message rm;
	int ret;

	MSG(REMG_NOOP,
		.noop = {
			.size = sizeof(rm),
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
		ret = bind(fds[i], (struct sockaddr *) &sin, sizeof(sin));
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
			.payload_types = {0xf},
			.clock_rates = {8000},
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
					.auth_tag_len = 10,
					.master_key = {0xe1, 0xf9, 0x7a, 0x0d, 0x3e, 0x01, 0x8b, 0xe0,
						0xd6, 0x4f, 0xa3, 0x2c, 0x06, 0xde, 0x41, 0x39},
					.master_salt = {0x0e, 0xc6, 0x75, 0xad, 0x49, 0x8a, 0xfe, 0xeb,
						0xb6, 0x96, 0x0b, 0x3a, 0xab, 0xe6},
				},
				.ssrc_out = 0x11223344, // ignored
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
					.auth_tag_len = 10,
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
			.payload_types = {8},
			.clock_rates = {8000},
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
					.auth_tag_len = 10,
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
				.auth_tag_len = 10,
				.master_key = {0x86, 0x70, 0x84, 0x51, 0x5a, 0xa4, 0xf7, 0x73,
					0xd0, 0xcd, 0x56, 0xd0, 0x32, 0x34, 0x5b, 0x0b},
				.master_salt = {0xc1, 0xe3, 0xb1, 0x54, 0x17, 0x3d, 0xf1, 0x3f,
					0xb6, 0xa3, 0x86, 0x41, 0xc4, 0x0b},
			},
			.src_mismatch = MSM_IGNORE,
			.num_destinations = 1,
			.rtp = 1,

			.num_payload_types = 1,
			.payload_types = {8},
			.clock_rates = {8000},
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
			.payload_types = {8},
			.clock_rates = {8000},
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
					.auth_tag_len = 0,
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
				.auth_tag_len = 0,
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
			.payload_types = {8},
			.clock_rates = {8000},
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

	return 0;
}
