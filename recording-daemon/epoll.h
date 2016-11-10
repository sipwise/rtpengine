#ifndef _EPOLL_H_
#define _EPOLL_H_

#include <sys/types.h>
#include <sys/epoll.h>
#include <stdint.h>
#include "types.h"


void epoll_setup(void);
void epoll_cleanup(void);

int epoll_add(int fd, uint32_t events, handler_t *handler);
void epoll_del(int fd);


void *poller_thread(void *ptr);


#endif
