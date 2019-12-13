#include "types.h"

int timerfd_init(handler_t * ptr_handler, int interval);
int timerfd_destroy(int tmpfd);