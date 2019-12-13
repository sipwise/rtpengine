#include <sys/timerfd.h>
#include "log.h"
#include "timer.h"
#include "epoll.h"

// interval is in milliseconds
int timerfd_init(handler_t * ptr_handler, int interval)
{
    int tmfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (tmfd < 0) {
        ilog(LOG_ERR, "timerfd_create error, Error:[%d:%s]", errno, strerror(errno));
        return -1;
    }

    struct itimerspec its;
    its.it_value.tv_sec = interval/1000;
    its.it_value.tv_nsec = interval%1000 * 1000000;
    its.it_interval.tv_sec = its.it_value.tv_sec;
    its.it_interval.tv_nsec = its.it_value.tv_nsec;

    int ret = timerfd_settime(tmfd, 0, &its, NULL);
    if (ret < 0) {
        ilog(LOG_ERR, "timerfd_settime error, Error:[%d:%s]", errno, strerror(errno));
        close(tmfd);
        return -1;
    }

    if (epoll_add(tmfd, EPOLLIN, ptr_handler)) {
        ilog(LOG_ERR, "epoll_add error, Error:[%d:%s]", errno, strerror(errno));
        close(tmfd);
        return -1;
    }
 
    return tmfd;
}

int timerfd_destroy(int tmfd)
{
    epoll_del(tmfd);
    close(tmfd);
    return 0;
}
