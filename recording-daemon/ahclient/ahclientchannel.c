#include "ahclient.h"

#if _WITH_AH_CLIENT

#include "ahclientchannel.h"
#include  <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "log.h"
#include <semaphore.h>
#include <pthread.h>

#define actual_size_without_padding(x)  ((unsigned char * ) &((x).alignment_padding)  -  (unsigned char * ) (&(x)))

const int  BLOCK_BUFFERSIZE                     = 8192;
const char *  NETWORK_PACKET_SIGNATURE          = "SOKQ";          // Signature for network packets
const char * STREAM_HEADER_SIGANATURE           = "SPKSTM";
const int   SOCKET_RESENT_MAX_RETRY             = 2;
const int   SOCKET_RECONNECT_MAX_RETRY          = 3;
const int   SOCKET_RECONNECT_WAIT_TIME_SECOND   = 30;
const int   SOCKET_RESENT_WAIT_TIME_SECOND      = 3;
const unsigned char     WAVE_FORMAT_MULAW       = 7;
const unsigned int      ENENT_ID_AUDIO_RECEIVED = 1001;
const unsigned int      ENENT_ID_AUDIO_END      = 1002;
const unsigned short    PAYLOAD_TYPE_BUFFER     = 3;              // Payload points to a memory buffer
const unsigned short    PAYLOAD_TYPE_EOF        = 0;              // EOF, no payload

const unsigned short    RTP_HEADER_SIZE = 40;


void init_audio_strem_header_t(audio_strem_header_t * audio_strem_header, const char * connection_uid)
{
    if (audio_strem_header) {
        strncpy(audio_strem_header->signature, STREAM_HEADER_SIGANATURE, sizeof(audio_strem_header->signature));  // Constant value
        strncpy(audio_strem_header->connection_uid, connection_uid, UIDLEN);  // Constant value
        audio_strem_header->audio_format = WAVE_FORMAT_MULAW;
        audio_strem_header->channel_count = 2; 
        audio_strem_header->sample_rate = 8000; 
    }
}

void init_ahclient_payload_header_t(ahclient_payload_header_t * ahclient_payload_header ){
    if (ahclient_payload_header != NULL){
        strncpy(ahclient_payload_header->signature, NETWORK_PACKET_SIGNATURE, sizeof(ahclient_payload_header->signature));  // Constant value
        ahclient_payload_header->length = 0;    // Packet length, will be chaned for each packet
        ahclient_payload_header->event_id = ENENT_ID_AUDIO_RECEIVED;   
        ahclient_payload_header->payload_type =  PAYLOAD_TYPE_BUFFER;    // Constant value
    }
}

void init_ahclient_eof_header(ahclient_eof_header_t * eof_header, const char * connection_uid) {
    if (eof_header != NULL){
        strncpy(eof_header->signature, NETWORK_PACKET_SIGNATURE, sizeof(eof_header->signature));  // Constant value
        eof_header->length = 30;    // size of  event_id(4) + payload_type(2) + spk_signature(6) + connection_uid(18)
        eof_header->event_id = ENENT_ID_AUDIO_END;   
        eof_header->payload_type =  PAYLOAD_TYPE_EOF;    // Constant value
        strncpy(eof_header->spk_signature, STREAM_HEADER_SIGANATURE, sizeof(eof_header->spk_signature));  // Constant value
        strncpy(eof_header->connection_uid, connection_uid, UIDLEN);  // Constant value
    }
}

// remove the  next node from the linked list and return it
unsent_buf_node_t * get_next_node(ahclient_mux_channel_t *  channel, int channel_index) {

    pthread_mutex_lock(&channel->buffer_mutex[channel_index]);
    unsent_buf_node_t *  node = channel->unsent_buf_head[channel_index];
    if (node != NULL) {
        channel->unsent_buf_size[channel_index] -= node->len;
        channel->unsent_buf_head[channel_index] = node->next;
        if (channel->unsent_buf_head[channel_index] == NULL ) {
            channel->unsent_buf_tail[channel_index] = NULL;
        }
    }   
    pthread_mutex_unlock(&channel->buffer_mutex[channel_index]);

    return node;
}

// Restore this node back to the head of the linked list
void restore_node(ahclient_mux_channel_t *  channel, int id, unsent_buf_node_t * node) {
    pthread_mutex_lock(&channel->buffer_mutex[id]);
    if (channel->unsent_buf_head[id] != NULL) {
        node->next = channel->unsent_buf_head[id];
    } else {
        channel->unsent_buf_tail[id] = node;
    }
    channel->unsent_buf_head[id] = node;
    channel->unsent_buf_size[id] += node->len;
    pthread_mutex_unlock(&channel->buffer_mutex[id]);
    return;
}

// get data from both channel and mux the data
// The package size is limit to BLOCK_BUFFERSIZE
// If the available data size is smaller than BLOCK_BUFFERSIZE, will return null is flush is false
// or will return whatever in the queue when flush is true
unsigned char *  gen_mux_buffer(ahclient_mux_channel_t *  channel, BOOL flush,  int * buf_len) {
    static int payload_header_size = actual_size_without_padding(channel->payload_header);
    static int stream_header_size =  actual_size_without_padding(channel->stream_header);

    *buf_len = 0;

    if (channel) {

        if (channel->retry_buf) {
            *buf_len = channel->retry_buf_len;

            unsigned char * buf = channel->retry_buf;
            channel->retry_buf = NULL;
            return buf;
        }
        
        int i = 0;
        unsigned int min_channel_buf_size = BLOCK_BUFFERSIZE, max_channel_buf_size = 0;
        for (i = 0; i < CHANNEL_COUNT; ++i) {
            if (channel->unsent_buf_size[i] > max_channel_buf_size) 
                max_channel_buf_size = channel->unsent_buf_size[i];
            if (channel->unsent_buf_size[i] < min_channel_buf_size) 
                min_channel_buf_size = channel->unsent_buf_size[i];    
        } 
                 
        unsigned int send_size = min_channel_buf_size;

        if ( min_channel_buf_size < BLOCK_BUFFERSIZE) {
            if  ( !flush)
                return NULL; // not to sent
            else send_size = max_channel_buf_size;
        }
        
        unsigned char * send_buf = NULL;
        
        if (send_size == 0  ) {  // EOF of stream; if it's not flush, already returned above
            if (channel->eof == FALSE) {       // Have not generated the EOF packet 
                char uid[UIDLEN + 1];
                ilog(LOG_INFO,"Packing the EOF for call with connection_uis : %s ", show_UID(channel->stream_header.connection_uid, uid));
                send_buf = malloc(sizeof(ahclient_eof_header_t));
                ahclient_eof_header_t  * eof_header  = (ahclient_eof_header_t  *) send_buf;
                init_ahclient_eof_header(eof_header, channel->stream_header.connection_uid);
                *buf_len =  actual_size_without_padding(*eof_header);
                channel->eof = TRUE;
            }
        }  else {
            // generate sending buffer
            *buf_len = send_size * CHANNEL_COUNT + payload_header_size + stream_header_size;
            send_buf = malloc(*buf_len);
            unsigned char * tmp = send_buf;

            // append header
            channel->payload_header.length = *buf_len - AHCLIENT_PACKET_HEADER_LEGTH;
            memcpy(tmp, (const void *)(&channel->payload_header), payload_header_size);
            tmp += payload_header_size;

            channel->stream_header.sample_count = send_size * CHANNEL_COUNT;
            memcpy(tmp, (const void *)(&channel->stream_header), stream_header_size);
            tmp += stream_header_size;
            
            // mux buffer
            int p = 0;
            unsent_buf_node_t * channel_node[CHANNEL_COUNT] = {0};
            unsigned char * channel_buf[CHANNEL_COUNT] = {0};
            int    channel_buf_len[CHANNEL_COUNT] = {0};

            for ( p = 0; p < send_size; ++p) {
                for ( i = 0; i < CHANNEL_COUNT; ++i ) {
                    if (channel_buf_len[i] == 0 ) {
                        delete_unsent_buf_node(channel_node[i], FALSE);
                        channel_node[i] = get_next_node(channel, i);
                        if (channel_node[i] == NULL) {
                            channel_buf_len[i] = -1;
                            channel_buf[i] = NULL;
                        } else {
                            channel_buf_len[i] = channel_node[i]->len; 
                            channel_buf[i] = channel_node[i]->buf;
                        }
                    }
                    
                    if (channel_buf_len[i] == -1) {     // all data for this channel sent, append '\0'
                        *tmp++ = 0;
                    } else {
                        *tmp++ = *channel_buf[i]++;
                        channel_buf_len[i]--;
                    }
                }
            }

            // if there are some unsent data in the node, restore the data back to linked list
            for ( i = 0; i < CHANNEL_COUNT; ++i ) {
                if (channel_buf_len[i] > 0) {   // restore unsent data
                    unsent_buf_node_t * node =  new_unsent_buf_node(channel, i, channel_buf[i], channel_buf_len[i]);
                    restore_node(channel, i, node);
                    delete_unsent_buf_node(channel_node[i], FALSE);
                } 
            }
        }

        return send_buf;
    }
    return NULL;

}

void ahchannel_sent_stream(ahclient_mux_channel_t *  channel, BOOL flush)
{

    int buf_size;
    unsigned char * send_buf = NULL;

    int resend_count = 0;
    int reconnect_count = 0;
    char uid[UIDLEN + 1];
    show_UID(channel->stream_header.connection_uid, uid);

    while (resend_count < SOCKET_RESENT_MAX_RETRY && reconnect_count < SOCKET_RECONNECT_MAX_RETRY)  {

        if ( send_buf == NULL ) send_buf = gen_mux_buffer(channel, flush, &buf_size);
        if ( send_buf == NULL)  break;   // nothing to sent

        if (channel->socket_handler != INVALID_SOCKET_HANDLER) {
            BOOL sent = (-1 != send(channel->socket_handler, 
                                send_buf, 
                                buf_size, 0));
            if ( sent ) {
                channel->audio_raw_bytes_sent += buf_size;
                ilog(LOG_DEBUG,"Socket sent %d bytes (total raw bytes sent : %d) to AH client succeed for call with connection_uid : %s ", buf_size, channel->audio_raw_bytes_sent, uid);
                // Enable the following line will print the bineary data into friendly hex mode
                // log_bineary_buffer(send_buf, buf_size, 10);
                free(send_buf);
                send_buf = NULL;
                resend_count = 0;
                reconnect_count = 0;
            } else {
                resend_count++;
                ilog(LOG_ERROR,"Socket sents to AH client failed for call with connection_uid : %s retry:%d", uid, resend_count);
                if ( resend_count == SOCKET_RESENT_MAX_RETRY) {
                    // shutdown connection, discard the unsent data and time-outed ACK
                    shutdown(channel->socket_handler, 2);
                    channel->socket_handler = INVALID_SOCKET_HANDLER;  // Will be reconnet
                    resend_count = 0;
                    // If it's not flush, we can try to re-connect in next semaphore
                    if (!flush) break;
                } else {
                    sleep(SOCKET_RESENT_WAIT_TIME_SECOND);
                }

            }
        } else {
            reconnect_count++;
            channel->socket_handler = create_ah_connection();       
            if (channel->socket_handler  == INVALID_SOCKET_HANDLER )  {
                if (flush && reconnect_count < SOCKET_RECONNECT_MAX_RETRY) {    //  this is the last semaphone, need to close the channel, we should wait and retry instead of waiting for the next semaphone
                    sleep(SOCKET_RECONNECT_WAIT_TIME_SECOND);
                    ilog(LOG_ERROR,"Re connect socket to AH client retry:%d", reconnect_count);
                } else {
                    // if it's not flush, we can try  reconnect on next semaphore
                    break;
                }
            }
        }    
    }

    if (send_buf) { // sent failed , save it for next semaphone arrived
        if (flush) {
            free(send_buf);
        } else {
            channel->retry_buf = send_buf;
            channel->retry_buf_len = buf_size;
        }
    }

    if (flush) {
        int log_type = (reconnect_count == SOCKET_RECONNECT_MAX_RETRY ? LOG_ERROR : LOG_INFO);
        ilog(log_type,"Quit %s sending thread, sent [%d] bytes with %d bytes unsent data", uid, channel->audio_raw_bytes_sent,  channel->unsent_buf_size[0] + channel->unsent_buf_size[1] );
    }
    
}


void * ahclient_mux_channel_sending_thread(void * arg)
{
    ahclient_mux_channel_t * channel = (ahclient_mux_channel_t * )arg;
    channel->socket_handler = create_ah_connection();   // Create a connection for this thread
    while(1) {
        sem_wait(&channel->thread_sem); 
        ahchannel_sent_stream(channel, channel->close_channel);
        if (channel->close_channel) {
             return NULL; // quit sub thread
        }
    }
    pthread_exit(NULL);
}

ahclient_mux_channel_t * new_ahclient_mux_channel(const char * connection_uid)
{
    // create instance
    ahclient_mux_channel_t * instance = ( ahclient_mux_channel_t * )malloc(sizeof(ahclient_mux_channel_t ));
    instance->close_channel = FALSE;
    instance->eof = FALSE;

    // init mutex & semaphore
    sem_init(&(instance->thread_sem), 0, 0);

    for (int i = 0; i < CHANNEL_COUNT; i++) {
        pthread_mutex_init(&(instance->buffer_mutex[i]), NULL);
         // initial lined list header
        instance->unsent_buf_head[i] = NULL;
        instance->unsent_buf_tail[i] = NULL;
        instance->unsent_buf_size[i] = 0;
        instance->eof_flag[i] = FALSE;
    }
    instance->sem_posted_at = 0;
    instance->steam_posted_size = 0;

    instance->retry_buf = NULL;
    instance->audio_raw_bytes_sent = 0;

    // init payload header
    init_ahclient_payload_header_t(&instance->payload_header);
    // init stream header
    init_audio_strem_header_t(&instance->stream_header, connection_uid);

    // init socket connection
    instance->socket_handler = INVALID_SOCKET_HANDLER;  // will be created in child thread
 
    // start child thread
    pthread_create(&instance->sub_subthread , NULL, &ahclient_mux_channel_sending_thread, (void *)instance);

    return instance;
}

unsent_buf_node_t * new_unsent_buf_node(ahclient_mux_channel_t *  channel,int id, const unsigned char * buf, int len)
{

    unsent_buf_node_t * node = (unsent_buf_node_t *)malloc(sizeof(unsent_buf_node_t));
    node->len = len;
    node->buf = (unsigned char *)malloc(node->len);
    memcpy(node->buf, buf, len);
    node->next = NULL;
  
    return node;
}

void delete_unsent_buf_node(unsent_buf_node_t * node, BOOL recursive)
{
    if (node) {
        free(node->buf);
        if (recursive) delete_unsent_buf_node(node->next, recursive);
        free(node);
    }
}

void send_close_signal(ahclient_mux_channel_t *  instance)
{
    //ilog(LOG_INFO, "send_close_signal");
    if (instance) {
        instance->close_channel = TRUE;
    }
}

BOOL close_stream(ahclient_mux_channel_t *  channel, int id)
{
    id = (id == 0 ? 0 : 1);

    char uid[UIDLEN +1];
    ilog(LOG_INFO,"EOF received for channel : %s ID: %d", show_UID(channel->stream_header.connection_uid, uid), id);

    if (channel) {
        channel->eof_flag[id] = TRUE;
        int i ;
        for (i = 0; i < CHANNEL_COUNT; ++i) {
            if (channel->eof_flag[i] == FALSE) return FALSE;
        }
        return TRUE;
    }
    return FALSE;
}



void delete_ahclient_mux_channel(ahclient_mux_channel_t *  instance)
{
    if (instance) {
        // close sub thread
        send_close_signal(instance);
        sem_post(&instance->thread_sem); // post a semaphore to make sure sub thread catch this signal
        pthread_join(instance->sub_subthread, NULL);

        // close socket
        if (instance->socket_handler != INVALID_SOCKET_HANDLER)
            close(instance->socket_handler);

        // destroy semaphore
        sem_destroy(&instance->thread_sem);

        // delete node & mutex
        int i;
        for (i = 0; i < CHANNEL_COUNT; ++i) {
            pthread_mutex_destroy(&instance->buffer_mutex[i]);
            delete_unsent_buf_node(instance->unsent_buf_head[i], TRUE);
        }
        if (instance->retry_buf) free(instance->retry_buf);
        free(instance);
        instance = NULL;
    }
}

void ahchannel_post_stream(ahclient_mux_channel_t *  channel, int _id, const unsigned char  * buf, int len)
{

    int id = (_id == 0 ? 0 : 1);
    if (len <= RTP_HEADER_SIZE) return;
    // remove rtp header
    len -= RTP_HEADER_SIZE;
    buf += RTP_HEADER_SIZE;

    unsent_buf_node_t * node = new_unsent_buf_node(channel, id , buf,  len);

    pthread_mutex_lock(&channel->buffer_mutex[id]);

    if (channel->unsent_buf_tail[id] == NULL) {
        channel->unsent_buf_head[id] = node;
    } else {
        channel->unsent_buf_tail[id]->next = node;
    }
    channel->unsent_buf_tail[id] = node;
    
    channel->unsent_buf_size[id] += len;

    channel->steam_posted_size += len;

    if (channel->steam_posted_size - channel->sem_posted_at >= BLOCK_BUFFERSIZE * CHANNEL_COUNT) {
        channel->sem_posted_at = channel->steam_posted_size;
        sem_post(&channel->thread_sem); // post a semaphore 
    }

    pthread_mutex_unlock(&channel->buffer_mutex[id]);

}

#endif // _WITH_AH_CLIENT
