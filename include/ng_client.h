#ifndef _NG_CLIENT_H_
#define _NG_CLIENT_H_

#include "types.h"
#include "bencode.h"

void ng_client_init(void);
void ng_client_cleanup(void);

bencode_item_t *ng_client_request(const endpoint_t *dst, const str *req, bencode_buffer_t *);

#endif
