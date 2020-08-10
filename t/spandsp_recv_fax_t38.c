#undef NDEBUG
#include <stdio.h>
#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>
#include <spandsp/telephony.h>
#include <spandsp/logging.h>
#include <spandsp/t38_core.h>
#include <spandsp/t30.h>
#include <spandsp/t30_api.h>
#include <spandsp/t38_terminal.h>
#include <spandsp/fax.h>
#include "compat.h"
#include "spandsp_logging.h"



#define SAMPLES_PER_CHUNK 160
#ifndef FALSE
# define FALSE false
#endif


static int packet_handler(t38_core_state_t *s, void *user_data, const uint8_t *buf, int len, int count) {
	static uint16_t seq = 0;

	fprintf(stderr, "recv: writing %i bytes %i times\n", len, count);

	for (int i = 0; i < count; i++) {
		uint16_t hdr[2] = {seq, len};
		int ret = write(1, hdr, sizeof(hdr));
		assert(ret == sizeof(hdr));
		ret = write(1, buf, len);
		assert(ret == len);
	}

	seq++;

	return 0;
}

static void phase_e_handler(PHASE_E_HANDLER_ARGS) {
	fprintf(stderr, "phase E result %i\n", result);
	assert(result == T30_ERR_OK);
}

static size_t nb_read(int fd, void *b, size_t len) {
	size_t left = len;
	while (left) {
		ssize_t ret = read(fd, b + len - left, left);
		if (ret > 0) {
			left -= ret;
			continue;
		}
		if (ret == 0)
			return 0;
		if (errno == EAGAIN && left != len) {
			usleep(10000);
			continue;
		}
		return -1;
	}
	return len;
}

int main(int argc, char **argv) {
	assert(argc == 2);
	const char *output_file_name = argv[1];

	t38_terminal_state_t *fax = t38_terminal_init(NULL, FALSE, packet_handler, NULL);
	assert(fax != NULL);

	int use_tep = 0;
	int supported_modems = T30_SUPPORT_V27TER | T30_SUPPORT_V29 | T30_SUPPORT_V17;
	int use_ecm = 0;
	int t38_version = 0;
	int options = 0;


	// taken from t38_terminal_tests.c
	t30_state_t *t30 = t38_terminal_get_t30_state(fax);
	t38_core_state_t *t38 = t38_terminal_get_t38_core_state(fax);
	t38_set_t38_version(t38, t38_version);
	t38_terminal_set_config(fax, options);
	t38_terminal_set_tep_mode(fax, use_tep);

	t30_set_supported_modems(t30, supported_modems);
	t30_set_tx_ident(t30, "22222222");
	t30_set_tx_nsf(t30, (const uint8_t *) "\x50\x00\x00\x00Spandsp\x00", 12);
	t30_set_rx_file(t30, output_file_name, -1);
	t30_set_ecm_capability(t30, use_ecm);
	t30_set_phase_e_handler(t30, phase_e_handler, NULL);

	fcntl(0, F_SETFL, O_NONBLOCK);

	while (1) {
		int done = t38_terminal_send_timeout(fax, SAMPLES_PER_CHUNK);
		if (done)
			break;

		uint16_t hdr[2];
		int ret = nb_read(0, hdr, sizeof(hdr));
		if (ret < 0 && errno == EAGAIN) {
			usleep(20000);
			continue;
		}
		assert(ret == sizeof(hdr));
		uint8_t buf[512];
		assert(hdr[1] <= sizeof(buf));
		do
			ret = nb_read(0, buf, hdr[1]);
		while (ret < 0 && errno == EAGAIN);
		assert(ret == hdr[1]);
		fprintf(stderr, "recv: processing %u bytes, seq %u\n", hdr[1], hdr[0]);
		t38_core_rx_ifp_packet(t38, buf, hdr[1], hdr[0]);
	}

	return 0;
}
