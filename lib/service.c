#ifdef HAVE_LIBSYSTEMD
#include <systemd/sd-daemon.h>
#endif
#include "service.h"

void service_notify(const char *message) {
#ifdef HAVE_LIBSYSTEMD
	sd_notify(0, message);
#endif
}
