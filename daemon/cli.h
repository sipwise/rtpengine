#ifndef CLI_UDP_H_
#define CLI_UDP_H_

#include <netinet/in.h>

struct cli {
   struct obj      obj;

   struct callmaster   *callmaster;
   int fd;
   struct poller       *poller;
   mutex_t         lock;

};

struct cli *cli_new(struct poller *p, u_int32_t ip, u_int16_t port, struct callmaster *m);

#endif /* CLI_UDP_H_ */
