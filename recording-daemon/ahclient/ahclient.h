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

typedef struct sockaddr_in sockaddr_in_t;
typedef int socket_handler_t;

// Forward declaration
typedef struct ahclient_mux_channel ahclient_mux_channel_t;

// linklist of ahclient_mux_channel_t
typedef struct channel_node {
    ahclient_mux_channel_t * channel;
    struct  channel_node * next;
} channel_node_t; 

typedef struct  ahclient 
{
    sockaddr_in_t   ah_server_address;

    // mutex to protext the linked list: channels
    pthread_mutex_t channels_mutex;
    channel_node_t * channels;
} ahclient_t;

void init_ahclient(void);
void destroy_ahclient(void);

void ahclient_post_stream(metafile_t * metafile, unsigned char * buf, int len);
void ahclient_close_stream(metafile_t * metafile);

// find a channel from the linked list, if not found, will create one
// ahclient_mux_channel_t * find_channel(UID callid);

socket_handler_t create_ah_connection(void);
#endif  // _WITH_AH_CLIENT

#endif // _ah_client_h
