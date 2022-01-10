#ifndef CLI_UDP_H_
#define CLI_UDP_H_

#include "socket.h"
#include "obj.h"
#include "tcp_listener.h"

struct cli {
   struct obj      obj;

   struct poller       *poller;

   struct streambuf_listener listener;
};

struct cli_writer;
struct call;
struct call_monologue;

struct cli_writer {
	void (*cw_printf)(struct cli_writer *, const char *, ...) __attribute__ ((format (printf, 2, 3)));
	void *ptr;
	struct call *call;
	struct call_monologue *ml;
};

struct cli *cli_new(struct poller *p, endpoint_t *);

void cli_handle(str *instr, struct cli_writer *);

#endif /* CLI_UDP_H_ */
