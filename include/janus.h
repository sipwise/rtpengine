#ifndef __JANUS_H__
#define __JANUS_H__

struct websocket_conn;
struct websocket_message;
struct janus_session;
struct call_monologue;


void janus_init(void);
void janus_free(void);

const char *websocket_janus_process(struct websocket_message *wm);
void janus_detach_websocket(struct janus_session *session, struct websocket_conn *wc);
void janus_media_up(struct call_monologue *);


#endif
