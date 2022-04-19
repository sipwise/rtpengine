#ifndef __SSLLIB_H__
#define __SSLLIB_H__


#include <openssl/ssl.h>



#if OPENSSL_VERSION_NUMBER >= 0x30000000L
extern EVP_MAC_CTX *rtpe_hmac_sha1_base;
#endif



void rtpe_ssl_init(void);


#endif
