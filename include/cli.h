#ifndef CLI_UDP_H_
#define CLI_UDP_H_

#include "socket.h"
#include "obj.h"
#include "tcp_listener.h"

struct cli {
   struct obj      obj;

   struct poller       *poller;

   struct streambuf_listener listeners[2];
};

struct cli *cli_new(struct poller *p, endpoint_t *);

#endif /* CLI_UDP_H_ */
