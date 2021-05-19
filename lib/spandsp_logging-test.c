#ifdef WITH_TRANSCODING
#include <inttypes.h>
#include <sys/types.h>
#include <stdbool.h>
#include <stddef.h>
#include <spandsp/telephony.h>
#include <spandsp/logging.h>
#include "compat.h"
#include "spandsp_logging.h"

void logfunc(SPAN_LOG_ARGS) {
	return;
}

int main(void) {
	return 0;
	logging_state_t *ls = NULL;
	my_span_set_log(ls, logfunc);
	my_span_mh(NULL);
	return 0;
}
#else
int main(void) {
	return 0;
}
#endif
