#ifndef _MQTT_H_
#define _MQTT_H_

#include <stdbool.h>
#include "main.h"

struct call;
struct call_media;


#ifdef HAVE_MQTT


int mqtt_init(void);
void mqtt_loop(void *);
int mqtt_publish_scope(void);
void mqtt_publish(char *);
void mqtt_timer_run_media(struct call *, struct call_media *);
void mqtt_timer_run_call(struct call *);
void mqtt_timer_run_global(void);
void mqtt_timer_run_summary(void);


#else

#include "compat.h"

INLINE int mqtt_init(void) { return 0; }
INLINE void mqtt_publish(char *s) { }
INLINE int mqtt_publish_scope(void) { return MPS_NONE; };
INLINE void mqtt_timer_run_media(struct call *c, struct call_media *m) { }
INLINE void mqtt_timer_run_call(struct call *c) { }
INLINE void mqtt_timer_run_global(void) { }
INLINE void mqtt_timer_run_summary(void) { }

#endif
#endif
