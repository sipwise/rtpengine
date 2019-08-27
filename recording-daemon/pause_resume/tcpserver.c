#include "tcpserver.h"
#include "log.h"
#include "metafile.h"

tcpserver_t tcpserver = {
  .addr = INADDR_ANY, /* by default, listen on all local IP's   */
  .port = 8082,
  .fd = -1
};

static int remove_client(tcpclient_t* pClient){
    tcpserver_t *pServer = pClient->pServer;
    for (int i=0; i<MAX_CLIENT_NUMBER; i++){
        if (pServer->clients[i] == pClient){
            pServer->clients[i] = NULL;
            return 1;
        }
    }
    return 0;
  }

static void close_client(tcpclient_t* pClient){
    epoll_del(pClient->fd);
    close(pClient->fd);
    free(pClient);
}

#define MAX_ARG_NUMBER 16
#define MAX_COMMAND_LENGTH 2048
static void process_client(handler_t *handler){
    tcpclient_t* pClient = handler->ptr;
    if (pClient == NULL)
        return;
    char buf[MAX_COMMAND_LENGTH];
    int len = read(pClient->fd, buf, sizeof(buf));
    if (len == 0){
        remove_client(pClient);
        close_client(pClient);
        return;
    }
    else if (len < 0){
        ilog(LOG_ERR,  "recv: %s\n", strerror(errno)); 
        return;
    }
    // read in bytes;
    int argc = 0;
    char *argv[MAX_ARG_NUMBER];
    argv[argc++] = buf;
    int new_flag = 0;

    if (len == MAX_COMMAND_LENGTH)
        len--;

    for (int i=0; i<len; i++){
        if (buf[i] == ' '){
            buf[i] = '\0';
            new_flag = 1;
        }
        else{
            if (new_flag){
                if (argc < MAX_ARG_NUMBER)
                    argv[argc++] = buf+i;
                new_flag = 0;
            }
        }
    }
    buf[len] = '\0';
    if (strcmp(argv[0], "stopRecording") == 0){
        dbg("====> stopRecording command: %s", buf);
        if (argc < 2)
            ilog(LOG_ERR, "Missing call id");
        else
            metafile_stop_recording(argv[1]);
    }
    else if (strcmp(argv[0], "startRecording") == 0){
       dbg("====> startRecording command: %s", buf);
        if (argc < 2)
            ilog(LOG_ERR, "Missing call id");
        else
            metafile_start_recording(argv[1]);
    }
    else if (strcmp(argv[0], "health") == 0){
        dbg("====> healthCheck command: %s", buf);
    }
    else {
        dbg("====> not a valid command: %s", buf);    
    }
}

/* accept a new client connection to the listening socket */
static void accept_client(handler_t *handler){
    int fd;
    struct sockaddr_in in;
    socklen_t sz = sizeof(in);
    tcpserver_t *pServer = handler->ptr;

    fd = accept(pServer->fd,(struct sockaddr*)&in, &sz);
    if (fd == -1) {
        ilog(LOG_ERR, "accept: %s\n", strerror(errno)); 
        goto done;
    }

    dbg( "connection fd %d from %s:%d\n", fd,
        inet_ntoa(in.sin_addr), (int)ntohs(in.sin_port));

    tcpclient_t *pClient = (tcpclient_t *)malloc(sizeof(tcpclient_t));
    pClient->pServer = pServer;
    pClient->handler.ptr = pClient;
    pClient->handler.func = process_client;
	if (epoll_add(fd, EPOLLIN, &pClient->handler)) {
        ilog(LOG_ERR, "epoll_add error, Error:[%d:%s]", errno, strerror(errno));		
		close(fd);
		return;
	}
	pClient->fd = fd;
    for (int i=0; i<MAX_CLIENT_NUMBER; i++){
        if (pServer->clients[i] == NULL){
            pServer->clients[i] = pClient;
            break;
        }
    }

 done:
    return;
}


int tcpserver_setup() {
    int rc = -1, one=1;

    for (int i=0; i<MAX_CLIENT_NUMBER; i++)
        tcpserver.clients[i] = NULL;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        ilog(LOG_ERR, "socket: %s\n", strerror(errno));
        goto done;
    }

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = tcpserver.addr;
    sin.sin_port = htons(tcpserver.port);

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (bind(fd, (struct sockaddr*)&sin, sizeof(sin)) == -1) {
        ilog(LOG_ERR, "bind: %s\n", strerror(errno));
        goto done;
    }

    if (listen(fd,1) == -1) {
       ilog(LOG_ERR, "listen: %s\n", strerror(errno));
        goto done;
    }

    rc=0;

	tcpserver.handler.ptr = &tcpserver;
	tcpserver.handler.func = accept_client;
	if (epoll_add(fd, EPOLLIN, &tcpserver.handler)) {
        ilog(LOG_ERR, "epoll_add error, Error:[%d:%s]", errno, strerror(errno));		
		close(fd);
		return -1;
	}
	tcpserver.fd = fd;

 done:
    if ((rc < 0) && (fd != -1)) close(fd);
    return rc;
}

void tcpserver_close(){
    for (int i=0; i<MAX_CLIENT_NUMBER; i++){
        tcpclient_t *pClient = tcpserver.clients[i];
        if (pClient != NULL){
            close(pClient->fd);
            tcpserver.clients[i] = NULL;
        }
    }
    if (tcpserver.fd != -1) 
        close(tcpserver.fd);    
}


