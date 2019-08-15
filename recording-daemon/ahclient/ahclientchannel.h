#ifndef _ahclient_channel_h
#define _ahclient_channel_h

#include "ahclient.h"

#if _WITH_AH_CLIENT

#include "sys/socket.h"
#include <pthread.h>
#include <semaphore.h>
#include <netinet/in.h>

#define  CHANNEL_COUNT    2

typedef struct audio_strem_header {
    char            signature[6];                  // "SPKSTM"
    char            connection_uid[18];
    unsigned char   audio_format;          // 1=16-Bit PCM, 6=alaw, 7=mulaw
    unsigned char   channel_count;
    unsigned short  sample_rate;
    unsigned short  sample_count;
    char           alignment_padding;  // Use this to calculat the actual size of struct 
} audio_strem_header_t;

void init_audio_strem_header_t(audio_strem_header_t * audio_strem_header, const char * connection_uid );

#define AHCLIENT_PACKET_HEADER_LEGTH 8 // = sizeof (signature) + sizeof(length)
typedef struct ahclient_payload_header {
    char            signature[4];       // SOKQ
    unsigned int    length;
    unsigned int    event_id;
    int16_t         payload_type;
    char            alignment_padding;  // Use this to calculat the actual size of struct 
} ahclient_payload_header_t;
void init_ahclient_payload_header_t(ahclient_payload_header_t * ahclient_payload_header);

typedef struct ahclient_eof_header {
    char            signature[4];                   // SOKQ
    unsigned int    length;
    unsigned int    event_id;
    int16_t         payload_type;
    char            spk_signature[6];                  // "SPKSTM"
    char            connection_uid[18];
    char            alignment_padding;  // Use this to calculat the actual size of struct 
} ahclient_eof_header_t;

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

    ahclient_payload_header_t   payload_header;
    audio_strem_header_t        stream_header;

    pthread_mutex_t     buffer_mutex[CHANNEL_COUNT];
    unsent_buf_node_t * unsent_buf_head[CHANNEL_COUNT];
    unsent_buf_node_t * unsent_buf_tail[CHANNEL_COUNT];
    unsigned int        unsent_buf_size[CHANNEL_COUNT];
    unsigned int        sem_posted_at;
    unsigned int        steam_posted_size;
    BOOL                eof_flag[CHANNEL_COUNT];

    unsigned int    retry_buf_len;
    unsigned char * retry_buf;

    unsigned int    audio_raw_bytes_sent;

    BOOL        close_channel;
    BOOL        eof;
} ahclient_mux_channel_t;

unsent_buf_node_t * new_unsent_buf_node(ahclient_mux_channel_t *  channel,int id, const unsigned char * buf, int len);
void delete_unsent_buf_node(unsent_buf_node_t * node, BOOL recursive);

ahclient_mux_channel_t * new_ahclient_mux_channel(cconst char * connection_uid);
// Send close signal to one channel of this streaming, if all stream closed, will return TRUE 
BOOL close_stream(ahclient_mux_channel_t *  channel, int id);
void delete_ahclient_mux_channel(ahclient_mux_channel_t *  instance);
void send_close_signal(ahclient_mux_channel_t * instance);

void ahchannel_post_stream(ahclient_mux_channel_t *  channel, int id, const unsigned char * buf, int lne);

#endif  // _WITH_AH_CLIENT
#endif