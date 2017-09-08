#ifndef _IPTABLES_H_
#define _IPTABLES_H_


#include "socket.h"
#include "str.h"


extern char *g_iptables_chain;

int iptables_add_rule(const socket_t *local_sock, const str *comment);
int iptables_del_rule(const socket_t *local_sock);



#endif
