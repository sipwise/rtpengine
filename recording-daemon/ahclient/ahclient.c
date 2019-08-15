
#include "ahclientchannel.h"

#if _WITH_AH_CLIENT

//#include "taskqueue.h"
#include  <stdlib.h>
#include <stdio.h>
#include <semaphore.h>
#include <pthread.h>
#include <sys/time.h> 

typedef struct sockaddr_in sockaddr_in_t;
const char * TRANSCRIBE_FLAG = "TRANSCRIBE=yes";
const unsigned long AH_SERVER_CHECK_INTERVAL  = 10; // When AH server disconnected, try to reconnect after 10 seconds

// linklist of ahclient_mux_channel_t
typedef struct channel_node {
    ahclient_mux_channel_t * channel;
    struct  channel_node * next;
} channel_node_t; 

typedef struct  ahclient 
{
    sockaddr_in_t   ah_server_address;

    time_t          ah_last_disconnect_ts;
    pthread_mutex_t ah_check_mutex;

    // mutex to protext the linked list: channels
    pthread_mutex_t channels_mutex;
    channel_node_t * channels;
    int channel_count;
    BOOL transcribe_all;
} ahclient_t;

//// ahclient related
// A global singleton instance of ahclient
ahclient_t * ahclient_instance = NULL;
const int  STREAM_ID_L_RTP = 0;
const int  STREAM_ID_R_RTP = 2;


// WARN : it's not a thread safe singleton, should not be called from multiple threads
void init_ahclient(char * ah_ip, unsigned int ah_port, BOOL transcribe_all){
    ilog(LOG_INFO, "init_ahclient : %s:%d transcribe_all = %d", ah_ip, ah_port, transcribe_all);

    if (ahclient_instance == NULL) {
        // Create instance
        ahclient_instance = (ahclient_t *)malloc(sizeof( ahclient_t));

        ahclient_instance->ah_last_disconnect_ts = 0;
        pthread_mutex_init(&(ahclient_instance->ah_check_mutex), NULL);

        // Init AH server address
        ahclient_instance->ah_server_address.sin_addr.s_addr = inet_addr(ah_ip);
        ahclient_instance->ah_server_address.sin_port = htons(ah_port);
        ahclient_instance->ah_server_address.sin_family = AF_INET;

        // Init channels linklist to NULL
        ahclient_instance->channels = NULL;
        ahclient_instance->channel_count = 0;
        ahclient_instance->transcribe_all = transcribe_all;

        // init Mutex
        pthread_mutex_init(&(ahclient_instance->channels_mutex), NULL);
    }
}

// WARN : it's not a thread safe singleton, should not be called from multiple threads
void destroy_ahclient(void) {
    ilog(LOG_INFO, "destroy_ahclient");

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
        // When detroy ah_client, we don't need to run in async mode to close all channels
        while(node) {
            ahclient_mux_channel_t * channel = node->channel;
            // close all sub thread
            pthread_join(channel->sub_subthread, NULL);

            // close socket
            close(channel->socket_handler);

            // destroy mutex & semaphore
            sem_destroy(&channel->thread_sem);
            // delete node & mutex
            int i;
            for (i = 0; i < CHANNEL_COUNT; ++i) {
                pthread_mutex_destroy(&channel->buffer_mutex[i]);
                delete_unsent_buf_node(channel->unsent_buf_head[i], TRUE);
            }
            if (channel->retry_buf) free(channel->retry_buf);

            free(channel);
            channel = NULL;

            // release current node
            channel_node_t * next = node->next;
            free(node);
            node = next;
        }
        ahclient_instance->channels = NULL;
        pthread_mutex_unlock(&ahclient_instance->channels_mutex);

        // destroy mutex
        pthread_mutex_destroy(&ahclient_instance->channels_mutex);
        pthread_mutex_destroy(&ahclient_instance->ah_check_mutex);

        free(ahclient_instance);
    }
}

socket_handler_t create_ah_connection(void){

    socket_handler_t handler = INVALID_SOCKET_HANDLER;

    pthread_mutex_lock(&ahclient_instance->ah_check_mutex);
    time_t current_time = time(NULL);
    if ( difftime(current_time, ahclient_instance->ah_last_disconnect_ts) >= AH_SERVER_CHECK_INTERVAL ) {
        handler = socket(AF_INET , SOCK_STREAM , 0);  // create a socket handler

        if (handler < 0 ) {
            ilog(LOG_ERROR,"Couldn't create a socket handler for ah client: %d:%s.", errno, strerror(errno));
            time(&ahclient_instance->ah_last_disconnect_ts);    // Update last disconnect time
            handler = INVALID_SOCKET_HANDLER;
        } else  if (connect(handler, &(ahclient_instance->ah_server_address), sizeof(sockaddr_in_t)) < 0) {
            ilog(LOG_ERROR," Couldn't create a socket connection for ah client errno: %d : %s", errno, strerror(errno));
            close(handler);
            handler = INVALID_SOCKET_HANDLER;
            time(&ahclient_instance->ah_last_disconnect_ts);    // Update last disconnect time
        } else {
            ilog(LOG_INFO, "ah server server connected.");
        }
    }
   
    pthread_mutex_unlock(&ahclient_instance->ah_check_mutex);

    return handler;
   
}

BOOL same_uid(const char * a, const char * b) {
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
channel_node_t * find_channe_nodel(const metafile_t * metafile, channel_node_t ** p_pre_node, BOOL create)
{
    
    channel_node_t * channel_node = NULL;
    channel_node_t * node = ahclient_instance->channels;
    channel_node_t * pre_node = NULL;

    char connection_uid[UIDLEN + 1];
    if ( get_connection_uid(metafile, connection_uid, UIDLEN + 1) ) {  // if connection UID unavailable, do nothing

        while(node)  {
            if (same_uid(connection_uid, node->channel->stream_header.connection_uid)) {
                channel_node = node; break;
            }
            pre_node = node;
            node = node->next;
        }
        if (channel_node == NULL && create) {
            // not found 
            ahclient_mux_channel_t * channel = new_ahclient_mux_channel(connection_uid);
            channel_node = (channel_node_t *)malloc(sizeof(channel_node_t));
            channel_node->channel = channel;
            // attach the new node to the head of the linked list
            channel_node->next = ahclient_instance->channels;
            ahclient_instance->channels = channel_node;
            ahclient_instance->channel_count++;
            ilog(LOG_INFO, "[total channel: %d] New channel created for Call [%s]",ahclient_instance->channel_count, connection_uid);

        }

        if (p_pre_node) *p_pre_node = pre_node;
    }

    return channel_node;
}

BOOL transcript_stream(const metafile_t * metafile)
{
    return (strstr(metafile->metadata, TRANSCRIBE_FLAG) != NULL);
}


/**********************
* Will create a new channel for each call, add this channel to a linked list
* ahchannel_post_stream will asynchorize append the buffer to the linked list in which channel
* Whitin each channel, has a worker thread to sent the buffer to AH server 
********************/
void ahclient_post_stream(const metafile_t * metafile, int id, const unsigned char * buf, int len)
{
    if (ahclient_instance && (ahclient_instance->transcribe_all || transcript_stream(metafile))) {
        if (id != STREAM_ID_L_RTP && id != STREAM_ID_R_RTP) return;
        pthread_mutex_lock(&ahclient_instance->channels_mutex);
        channel_node_t * channel_node = find_channe_nodel(metafile, NULL, TRUE);
        pthread_mutex_unlock(&ahclient_instance->channels_mutex);

        if (channel_node ) {   // could be NULL when connection_uid unavailable
            ahchannel_post_stream(channel_node->channel, id, buf, len);
        }
    }
}

void * async_close_channel(void * arg) 
{
    channel_node_t * channel_node = (channel_node_t *)arg;
   
    // safe delete channel
    delete_ahclient_mux_channel(channel_node->channel);       
    free(channel_node);
    
    return NULL;
}

/**********************
* Will close this channel
* Send a close signal to the worker thread, first try to sent out all remaining data
* then it will try to shutdown the socket connection and release all resource
********************/
void ahclient_close_stream(const metafile_t * metafile, int id) {
 
    if (ahclient_instance && (ahclient_instance->transcribe_all || transcript_stream(metafile))) {
        if (id != STREAM_ID_L_RTP && id != STREAM_ID_R_RTP) return;

        channel_node_t * channel_node = NULL;
        channel_node_t * pre_node = NULL;

        pthread_mutex_lock(&ahclient_instance->channels_mutex);
        channel_node = find_channe_nodel(metafile, &pre_node, FALSE);

        if (channel_node) {

            if (close_stream(channel_node->channel, id)) {
                
                // maintain the linked list
                if (pre_node == NULL) {
                    ahclient_instance->channels = channel_node->next;
                } else {
                    pre_node->next = channel_node->next;
                }
                // delete current node
                ahclient_instance->channel_count--;
                char uid[UIDLEN + 1];
                ilog(LOG_INFO, "[total channel left: %d] Closing channel for Call [%s] ",ahclient_instance->channel_count, show_UID(metafile->call_id, uid));
               
                // RT-738 : asynchronous mode to close a channel
                pthread_t thread_id;
                pthread_create(&thread_id , NULL, &async_close_channel, (void *)channel_node);
            }

        }

        pthread_mutex_unlock(&ahclient_instance->channels_mutex);
    }
}

#define SHOW_BYTES_PER_LINE     16
#define SIZE_OF_SHOW_BUF_LINE   SHOW_BYTES_PER_LINE * 4 + 16
#define printable(c)            ((c) >= 0x21 && (c) <= 0x7e)
void log_bineary_buffer(const unsigned char *  buf,  int buf_len, int show_line)
{
    char line[SIZE_OF_SHOW_BUF_LINE]; 
    if (show_line == -1) { // display all
        show_line = (( buf_len + 1 ) >> 4); 
    }

    int c = 1;
    while ( buf != NULL && buf_len > 0 && c <= show_line ) {
        char * show_buf = line;

        int i = 0;
        int max_len = ((SHOW_BYTES_PER_LINE < buf_len) ? SHOW_BYTES_PER_LINE : buf_len);

        for (i = 0; i < max_len; i++) {
            sprintf(show_buf, "%02x ", buf[i]);
            show_buf += 3;
        }
        for ( ; i < SHOW_BYTES_PER_LINE; i++) {
            *show_buf++  = '.';
            *show_buf++  = '.';
            *show_buf++  = ' ';
        }
            *show_buf++  = '|';
            *show_buf++  = ' ';
            
        for (i = 0; i < max_len; i++) {
            if (printable(*buf)) 
                *show_buf++  = *buf++ ;
            else {
                *show_buf++  = '.';
                buf++;
            }
        }
        buf_len -= SHOW_BYTES_PER_LINE;

        if ( buf_len <= 0) {
            memcpy(show_buf, "<END>\n", 6);
        } 
        *show_buf++  = 0;

        ilog(LOG_INFO, "%02d : %s", c, line);
        c++;
    }

    return;
}

char * show_UID(char * uid, char * show_buf)
{
    memcpy(show_buf, uid, UIDLEN);
    show_buf[UIDLEN] = 0;
    return show_buf;
}


#endif // _WITH_AH_CLIENT