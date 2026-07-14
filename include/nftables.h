#ifndef _NFTABLES_H_
#define _NFTABLES_H_

#include <stdbool.h>

typedef struct {
	int table;
	int family;
	bool append;
	bool xtables;
	bool may_exist;
	bool created;
} nftables_args;

char *nftables_setup(const char *chain, const char *base_chain, nftables_args);
char *nftables_shutdown(const char *chain, const char *base_chain, nftables_args);
int nftables_check(const char *chain, const char *base_chain, nftables_args);

#endif
