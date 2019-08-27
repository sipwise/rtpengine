#include "epoll.h"

struct tcpserver_s;
typedef struct tcpserver_s tcpserver_t;

struct tcpclient_s {
    int fd;
    handler_t handler;
    tcpserver_t *pServer;
};

typedef struct tcpclient_s tcpclient_t;

#define MAX_CLIENT_NUMBER 1024
struct tcpserver_s {
  in_addr_t addr;    /* local IP or INADDR_ANY   */
  int port;          /* local port to listen on  */
  int fd;            /* listener descriptor      */
  tcpclient_t* clients[MAX_CLIENT_NUMBER];     /* array of client descriptors */
  int ticks;         /* uptime in seconds        */
  handler_t handler;
}; 
typedef struct tcpserver_s tcpserver_t;


int tcpserver_setup(void);
void tcpserver_close(void);