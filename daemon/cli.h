#ifndef CLI_UDP_H_
#define CLI_UDP_H_

#include "socket.h"
#include "obj.h"

struct cli {
   struct obj      obj;

   struct callmaster   *callmaster;
   socket_t sock;
   struct poller       *poller;
   mutex_t         lock;

};

struct cli *cli_new(struct poller *p, const endpoint_t *, struct callmaster *m);

#endif /* CLI_UDP_H_ */
