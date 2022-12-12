#include <dlfcn.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/time.h>
#include <stdlib.h>

static inline long long timeval_us(const struct timeval *t) {
        return (long long) ((long long) t->tv_sec * 1000000LL) + t->tv_usec;
}
static inline void timeval_from_us(struct timeval *t, long long us) {
        t->tv_sec = us/1000000LL;
        t->tv_usec = us%1000000LL;
}
static inline long long timespec_ns(const struct timespec *t) {
        return (long long) ((long long) t->tv_sec * 1000000000LL) + t->tv_nsec;
}
static inline void timespec_from_ns(struct timespec *t, long long ns) {
        t->tv_sec = ns/1000000000LL;
        t->tv_nsec = ns%1000000000LL;
}
static long long offset = 0;
int gettimeofday(struct timeval *restrict tv, void *restrict tz) {
	__typeof__ (gettimeofday) *fn = dlsym(RTLD_NEXT, "gettimeofday");
	int ret = fn(tv, tz);
	if (ret)
		return ret;
	long r = random();
	if (r < ((1L<<31) / 100)) {
		// 1% chance
		long long add = random() & 0xffff;
		offset += add;
		fprintf(stderr, "moving clock forward by %lli us\n", add);
	}
	long long tvs = timeval_us(tv);
	tvs += offset;
	timeval_from_us(tv, tvs);
	return ret;
}
int pthread_cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex, const struct timespec *abstime) {
	__typeof__ (pthread_cond_timedwait) *fn = dlsym(RTLD_NEXT, "pthread_cond_timedwait");
	if (!abstime)
		return fn(cond, mutex, abstime);
	struct timespec tn;
	long long ns = timespec_ns(abstime);
	ns -= offset * 1000LL;
	timespec_from_ns(&tn, ns);
	return fn(cond, mutex, &tn);
}
