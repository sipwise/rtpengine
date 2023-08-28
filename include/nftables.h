#ifndef _NFTABLES_H_
#define _NFTABLES_H_

const char *nftables_setup(const char *chain, const char *base_chain, int table);
const char *nftables_shutdown(const char *chain, const char *base_chain);

#endif
