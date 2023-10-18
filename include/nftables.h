#ifndef _NFTABLES_H_
#define _NFTABLES_H_

typedef struct {
	int table;
} nftables_args;

const char *nftables_setup(const char *chain, const char *base_chain, nftables_args);
const char *nftables_shutdown(const char *chain, const char *base_chain);

#endif
