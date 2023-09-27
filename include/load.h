#ifndef _LOAD_H_
#define _LOAD_H_

extern int load_average; // times 100
extern int cpu_usage; // times 100

enum thread_looper_action load_thread(void);

#endif
