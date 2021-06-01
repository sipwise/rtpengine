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
void mqtt_timer_run(struct call *, struct call_media *);


#else

#include "compat.h"

INLINE int mqtt_init(void) { return 0; }
INLINE void mqtt_publish(char *s) { }
INLINE int mqtt_publish_scope(void) { return MPS_NONE; };
INLINE void mqtt_timer_run(struct call *c, struct call_media *m) { }

#endif
#endif
