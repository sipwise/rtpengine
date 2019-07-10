#ifndef _ah_client_h
#define _ah_client_h

// The following section is used to make the code enable in IDE 
// _WITH_AH_CLIENT will be injected from Makefile during compile
#ifndef _WITH_AH_CLIENT
#define _WITH_AH_CLIENT 1
#endif

#if _WITH_AH_CLIENT 
#include "stream.h"
#include "types.h"
#include "log.h"
#include "arpa/inet.h"	//inet_addr
#include <unistd.h>

#define UIDLEN     18           // UID
#ifndef BOOL
typedef unsigned int BOOL;
#endif
#ifndef TRUE 
#define TRUE    (1)
#endif  
#ifndef FALSE
#define FALSE   (0)
#endif

typedef int socket_handler_t;

void init_ahclient(char * ah_ip, unsigned int ah_port);
void destroy_ahclient(void);

void ahclient_post_stream(const metafile_t * metafile, int id, const unsigned char * buf, int len);
void ahclient_close_stream(const metafile_t * metafile);

socket_handler_t create_ah_connection(void);

// Helper functions
char * show_UID(char * uid, char * show_buf);
void log_bineary_buffer(const unsigned char * buf, int len, int show_line);

#endif  // _WITH_AH_CLIENT

#endif // _ah_client_h
