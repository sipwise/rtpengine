#ifndef _ahclient_channel_h
#define _ahclient_channel_h

#include "ahclient.h"

#if _WITH_AH_CLIENT
#include "sys/socket.h"
#include <pthread.h>
#include <semaphore.h>
#include <netinet/in.h>

#define BLOCK_BUFFERSIZE 8192
#define USM_BUFFERSIZE  BLOCK_BUFFERSIZE*16

#define NETWORK_PACKET_SIGNATURE    "SOKQ"              // Signature for network packets
#define PAYLOAD_TYPE_BUFFER    3                   // Payload points to a memory buffer
#define STREAM_HEADER_SIGANATURE    "SPKSTM"

typedef struct audio_strem_header {
    char signature[6];                  // "SPKSTM"
    char call_id[18];
    unsigned char audio_format;          // 1=16-Bit PCM, 6=alaw, 7=mulaw
    unsigned char channel_count;
    unsigned short sample_rate;
    unsigned short sample_count;
} audio_strem_header_t;
void init_audio_strem_header_t(audio_strem_header_t * audio_strem_header, metafile_t * metafile );

typedef struct ahclient_payload_header {
    char            signature[4];
    unsigned int    length;
    unsigned int    event_id;
    int16_t         payload_type;
} ahclient_payload_header_t;
void init_ahclient_payload_header_t(ahclient_payload_header_t * ahclient_payload_header);

typedef struct unsent_buf_node {
    unsigned char * buf;
    int             len;
    struct unsent_buf_node * next;
} unsent_buf_node_t;

// For each call will create a channel and a socket to sent the stream
typedef struct ahclient_mux_channel {
    socket_handler_t   socket_handler;
    
    pthread_t   sub_subthread;
    sem_t       thread_sem;

    ahclient_payload_header_t payload_header;
    audio_strem_header_t stream_header;

    pthread_mutex_t buffer_mutex;
    // linked list of unsent buffer
    unsent_buf_node_t * unsent_buf_head;
    unsent_buf_node_t * unsent_buf_tail;
  
    BOOL        close_channel;
} ahclient_mux_channel_t;

unsent_buf_node_t * new_unsent_buf_node(ahclient_mux_channel_t *  channel, unsigned char * buf, int len);
void delete_unsent_buf_node(unsent_buf_node_t * node, BOOL recursive);

ahclient_mux_channel_t * new_ahclient_mux_channel(metafile_t * metafile);
void delete_ahclient_mux_channel(ahclient_mux_channel_t *  instance);
void send_close_signal(ahclient_mux_channel_t * instance);

void ahchannel_post_stream(ahclient_mux_channel_t *  channel, unsigned char * buf, int lne);

#endif  // _WITH_AH_CLIENT
#endif