
#include "ahclientchannel.h"

#if _WITH_AH_CLIENT

//#include "taskqueue.h"
#include  <stdlib.h>
#include <stdio.h>
#include <semaphore.h>
#include <pthread.h>

const char * AH_IP = "10.141.0.97";
const unsigned int AH_PORT = 5570;

//// ahclient related
// A global singleton instance of ahclient
ahclient_t * ahclient_instance = NULL;

void init_ah_server_address(sockaddr_in_t * ahserver) {
    ahserver->sin_addr.s_addr = inet_addr(AH_IP);
    ahserver->sin_port = htons(AH_PORT);
    ahserver->sin_family = AF_INET;  /* internetwork: UDP, TCP, etc. */
}

// WARN : it's not a thread safe singleton, should not be called from multiple threads
void init_ahclient(void){
    if (ahclient_instance == NULL) {
        // Create instance
        ahclient_instance = (ahclient_t *)malloc(sizeof( ahclient_t));
   
        // Init AH server address
        init_ah_server_address(&ahclient_instance->ah_server_address);

        // Init channels linklist to NULL
        ahclient_instance->channels = NULL;

        // init Mutex
        pthread_mutex_init(&(ahclient_instance->channels_mutex), NULL);
    }
}

// WARN : it's not a thread safe singleton, should not be called from multiple threads
void destroy_ahclient(void) {
    if (ahclient_instance != NULL) {

        // lock channels mutex to close all channel
        pthread_mutex_lock(&ahclient_instance->channels_mutex);

        // send close signal to all channels
        channel_node_t * node = ahclient_instance->channels;
        while(node)  {
            ahclient_mux_channel_t * channel = node->channel;
            send_close_signal(channel);
            sem_post(&channel->thread_sem); // post a semaphore to make sure sub 
            node = node->next;
        }

        node = ahclient_instance->channels;
        // close all channels and release the resource
        while(node) {
            ahclient_mux_channel_t * channel = node->channel;
            // close all sub thread
            pthread_join(channel->sub_subthread, NULL);

            // close socket
            close(channel->socket_handler);

            // destroy mutex & semaphore
            sem_destroy(&channel->thread_sem);
            pthread_mutex_destroy(&channel->buffer_mutex);

            free(channel);
            channel = NULL;

            // release current node
            channel_node_t * next = node->next;
            free(node);
            node = next;
        }
        ahclient_instance->channels = NULL;
        pthread_mutex_unlock(&ahclient_instance->channels_mutex);

        // destroy channels mutex
        pthread_mutex_destroy(&ahclient_instance->channels_mutex);

        free(ahclient_instance);
    }
}

socket_handler_t create_ah_connection(void){

    socket_handler_t handler = socket(AF_INET , SOCK_STREAM , 0);  // create a socket handler

    if (handler < 0 ) {
        ilog(LOG_ERROR,"Couldn't create a socket handler for ah client.");
		return -1;
    }

    if (connect(handler, &(ahclient_instance->ah_server_address), sizeof(sockaddr_in_t)) < 0) {
        ilog(LOG_ERROR,"Couldn't create a socket connection for ah client.");
		return -1;
    }

	ilog(LOG_INFO, "ah server server connected.");
    return handler;
}

BOOL same_uid(char * a, char * b) {
    BOOL ret = FALSE;
    if ( a != NULL && b != NULL) {
        int i = 0;
        for (; i < UIDLEN; ++i) {
            if (a[i] != b[i]) break;
        }
        ret = (i == UIDLEN);
    }
    return ret;
}

// lock channels_mutex before call this function 
channel_node_t * find_channe_nodel(metafile_t * metafile, channel_node_t ** p_pre_node, BOOL create)
{
    
    channel_node_t * channel_node = NULL;
    channel_node_t * node = ahclient_instance->channels;
    channel_node_t * pre_node = NULL;

    while(node)  {
        if (same_uid(metafile->call_id, node->channel->stream_header.call_id)) {
            channel_node = node; break;
        }
        pre_node = node;
        node = node->next;
    }
    if (channel_node == NULL && create) {
        // not found 
        ahclient_mux_channel_t * channel = new_ahclient_mux_channel(metafile);
        channel_node = (channel_node_t *)malloc(sizeof(channel_node_t));
        channel_node->channel = channel;
        // attach the new node to the head of the linked list
        channel_node->next = ahclient_instance->channels;
        ahclient_instance->channels = channel_node;
    }

    if (p_pre_node) *p_pre_node = pre_node;

    return channel_node;
}


/**********************
/* Will create a new channel for each call, add this channel to a linked list
/* ahchannel_post_stream will asynchorize append the buffer to the linked list in which channel
/* Whitin each channel, has a worker thread to sent the buffer to AH server 
********************/
void ahclient_post_stream(metafile_t * metafile, unsigned char * buf, int len)
{
    // TODO : attach stream to proper channel 
    pthread_mutex_lock(&ahclient_instance->channels_mutex);
    channel_node_t * channel_node = find_channe_nodel(metafile, NULL, TRUE);
    pthread_mutex_unlock(&ahclient_instance->channels_mutex);

    ahchannel_post_stream(channel_node->channel, buf, len);
}

/**********************
/* Will close this channel
/* Send a close signal to the worker thread, first try to sent out all remaining data
/* then it will try to shutdown the socket connection and release all resource
********************/
void ahclient_close_stream(metafile_t * metafile) {

    channel_node_t * channel_node = NULL;
    channel_node_t * pre_node = NULL;

    pthread_mutex_lock(&ahclient_instance->channels_mutex);
    channel_node = find_channe_nodel(metafile, &pre_node, FALSE);

    if (channel_node) {
        // safe delete channel
        delete_ahclient_mux_channel(channel_node->channel);
        // maintain the linked list
        if (pre_node == NULL) {
            ahclient_instance->channels = channel_node->next;
        } else {
            pre_node->next = channel_node->next;
        }
        // delete current node
        free(channel_node);
    }
    pthread_mutex_unlock(&ahclient_instance->channels_mutex);
}

#endif // _WITH_AH_CLIENT