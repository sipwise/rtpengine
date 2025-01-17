#ifndef CLI_UDP_H_
#define CLI_UDP_H_

#include "socket.h"
#include "obj.h"
#include "tcp_listener.h"
#include "types.h"

struct cli {
   struct obj      obj;

   struct streambuf_listener listener;
};

struct cli_writer;
struct call_monologue;

struct cli_writer {
	size_t (*cw_printf)(struct cli_writer *, const char *, ...) __attribute__ ((format (printf, 2, 3)));
	void *ptr;
	call_t *call;
	struct call_monologue *ml;
};

struct cli *cli_new(const endpoint_t *);

void cli_handle(str *instr, struct cli_writer *);
const char *cli_ng(ng_command_ctx_t *);

#endif /* CLI_UDP_H_ */
