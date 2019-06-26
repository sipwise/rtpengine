
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


const int   SOCKET_RESENT_MAX_RETRY     = 2;
const int   SOCKET_RECONNECT_MAX_RETRY  = 2;
const unsigned char  WAVE_FORMAT_MULAW  = 7;

void init_audio_strem_header_t(audio_strem_header_t * audio_strem_header, metafile_t * metafile )
{
    if (audio_strem_header) {
        strncpy(audio_strem_header->signature, STREAM_HEADER_SIGANATURE, sizeof(audio_strem_header->signature));  // Constant value
        strncpy(audio_strem_header->call_id, metafile->call_id, UIDLEN);  // Constant value
        audio_strem_header->audio_format = WAVE_FORMAT_MULAW;
        audio_strem_header->channel_count = 2; 
        audio_strem_header->sample_rate = 8000; 
    }
}

void init_ahclient_payload_header_t(ahclient_payload_header_t * ahclient_payload_header){
    if (ahclient_payload_header != NULL){
        strncpy(ahclient_payload_header->signature, NETWORK_PACKET_SIGNATURE, sizeof(ahclient_payload_header->signature));  // Constant value
        ahclient_payload_header->length = 0;    // This can change if used for multiple messages
        ahclient_payload_header->event_id = 0;   // This can change if used for multiple messages
        ahclient_payload_header->payload_type = PAYLOAD_TYPE_BUFFER;    // Constant value
    }
}

unsent_buf_node_t * get_next_node(ahclient_mux_channel_t *  channel) {

    pthread_mutex_lock(&channel->buffer_mutex);
    unsent_buf_node_t *  node = channel->unsent_buf_head;
    if (node != NULL) {
        channel->unsent_buf_head = node->next;
        if (channel->unsent_buf_head == NULL ) {
            channel->unsent_buf_tail = NULL;
        }
    }   
    pthread_mutex_unlock(&channel->buffer_mutex);

    return node;
}

void restore_node(ahclient_mux_channel_t *  channel, unsent_buf_node_t * node) {
    pthread_mutex_lock(&channel->buffer_mutex);
    if (channel->unsent_buf_head != NULL) {
        node->next = channel->unsent_buf_head;
    } else {
        channel->unsent_buf_tail = node;
    }
    channel->unsent_buf_head = node;
    pthread_mutex_unlock(&channel->buffer_mutex);
    return;
}

void ahchannel_sent_stream(ahclient_mux_channel_t *  channel)
{
    int resend_count = 0;
    int reconnect_count = 0;

    if (channel) {

        unsent_buf_node_t * node = get_next_node(channel);
        while (node != NULL && resend_count < SOCKET_RESENT_MAX_RETRY && reconnect_count < SOCKET_RECONNECT_MAX_RETRY)  {
            if (channel->socket_handler > 0) {
                BOOL sent = (-1 != send(channel->socket_handler, 
                                    node->buf, 
                                    node->len, 0));
                if ( sent ) {
                    ilog(LOG_DEBUG,"Socket sent %d bytes to AH client succeed for call id : %s ", node->len, channel->stream_header.call_id);
                    // delete this node
                    delete_unsent_buf_node(node, FALSE);
                    // try to get next packet
                    node = get_next_node(channel);
                    // reset retry count
                    resend_count = 0;
                    reconnect_count = 0;
                } else {
                    resend_count++;
                    ilog(LOG_ERROR,"Socket sents to AH client failed for call id : %s retry:%d", channel->stream_header.call_id, resend_count);
                    if ( resend_count == SOCKET_RESENT_MAX_RETRY) {
                        resend_count = 0;
                        // disconnet, will retry in next while loop
                        close(channel->socket_handler);
                        channel->socket_handler = 0;  // Will be reconnet
                    }
                }
            } else {
                reconnect_count++;
                ilog(LOG_ERROR,"Re connect socket to AH client retry:%d", reconnect_count);
                channel->socket_handler = create_ah_connection();        
            }
        }
        
        if (node) { // sent failed; put this node back to linked list; will retry when next semaphore came
            restore_node(channel, node);
        }

    }
}

void * ahclient_mux_channel_sending_thread(void * arg)
{
    ahclient_mux_channel_t * channel = (ahclient_mux_channel_t * )arg;
    while(1) {

        sem_wait(&channel->thread_sem); 
        ahchannel_sent_stream(channel);
        if (channel->close_channel) {
            ilog(LOG_DEBUG,"Sending thread for Channel of call id %s quit.", channel->stream_header.call_id);
            return NULL; // quit sub thread
        }

    }
    pthread_exit(NULL);
}

ahclient_mux_channel_t * new_ahclient_mux_channel(metafile_t * metafile)
{
    // create instance
    ahclient_mux_channel_t * instance = ( ahclient_mux_channel_t * )malloc(sizeof(ahclient_mux_channel_t ));
    instance->close_channel = FALSE;

    // init mutex & semaphore
    pthread_mutex_init(&(instance->buffer_mutex), NULL);
    sem_init(&(instance->thread_sem), 0, 0);

    // init payload header
    init_ahclient_payload_header_t(&instance->payload_header);
    // init stream header
    init_audio_strem_header_t(&instance->stream_header, metafile );

    // init socket connection
    instance->socket_handler = create_ah_connection();

    // initial lined list header
    instance->unsent_buf_head = NULL;
    instance->unsent_buf_tail = NULL;

    // start child thread
    pthread_create(&instance->sub_subthread , NULL, &ahclient_mux_channel_sending_thread, (void *)instance);

    return instance;
}

unsent_buf_node_t * new_unsent_buf_node(ahclient_mux_channel_t *  channel, unsigned char * buf, int len)
{
    static int header_size = sizeof(ahclient_payload_header_t) + sizeof (audio_strem_header_t);

    unsent_buf_node_t * node = (unsent_buf_node_t *)malloc(sizeof(unsent_buf_node_t));
    node->len = len + header_size;
    node->buf = (unsigned char *)malloc(node->len);
    // append header
    unsigned char  * tmp = node->buf;
    memcpy(tmp, (const void *)(&channel->payload_header), sizeof(ahclient_payload_header_t));
    tmp += sizeof(ahclient_payload_header_t);
    memcpy(tmp, (const void *)(&channel->stream_header), sizeof(audio_strem_header_t));
    tmp += sizeof(audio_strem_header_t);
    // copy data
    memcpy(tmp, buf, len);

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
    if (instance) {
        pthread_mutex_lock(&instance->buffer_mutex);
        instance->close_channel = TRUE;
        pthread_mutex_unlock(&instance->buffer_mutex);
    }
}

void delete_ahclient_mux_channel(ahclient_mux_channel_t *  instance)
{
    if (instance) {
        // close sub thread
        send_close_signal(instance);
        sem_post(&instance->thread_sem); // post a semaphore to make sure sub thread catch this signal
        pthread_join(instance->sub_subthread, NULL);

        // close socket
        close(instance->socket_handler);

        // destroy mutex & semaphore
        sem_destroy(&instance->thread_sem);
        pthread_mutex_destroy(&instance->buffer_mutex);

        // delete node
        delete_unsent_buf_node(instance->unsent_buf_head, TRUE);

        free(instance);
        instance = NULL;
    }
}

void ahchannel_post_stream(ahclient_mux_channel_t *  channel, unsigned char  * buf, int len)
{
    // TODO : add data to this channel and post a thamophare
    unsent_buf_node_t * node = new_unsent_buf_node(channel, buf, len);
    pthread_mutex_lock(&channel->buffer_mutex);

    if (channel->unsent_buf_tail == NULL) {
        channel->unsent_buf_head = node;
    } else {
        channel->unsent_buf_tail->next = node;
    }
    channel->unsent_buf_tail = node;

    pthread_mutex_unlock(&channel->buffer_mutex);
    sem_post(&channel->thread_sem); // post a semaphore 

}

#endif // _WITH_AH_CLIENT
