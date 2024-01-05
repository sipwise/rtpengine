#ifndef _IPTABLES_H_
#define _IPTABLES_H_

#include "socket.h"
#include "str.h"

void iptables_init(void);
extern int (*iptables_add_rule)(const socket_t *local_sock, const str *comment);
extern int (*iptables_del_rule)(const socket_t *local_sock);

#endif
