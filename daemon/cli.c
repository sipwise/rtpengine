#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <netinet/in.h>
#include <errno.h>
#include <glib.h>

#include "poller.h"
#include "aux.h"
#include "log.h"
#include "call.h"
#include "cli.h"


static const char* TRUNCATED = "    ... Output truncated. Increase Output Buffer ...\n";

#define truncate_output(x) do { x -= strlen(TRUNCATED)+1; x += sprintf(x,"%s",TRUNCATED); } while (0);

#define ADJUSTLEN(printlen,outbuflen,replybuffer) do { if (printlen>=(outbufend-replybuffer)) \
                           truncate_output(replybuffer); \
       replybuffer += (printlen>=outbufend-replybuffer)?outbufend-replybuffer:printlen; } while (0);

static void cli_incoming_list_totals(char* buffer, int len, struct callmaster* m, char* replybuffer, const char* outbufend) {
	int printlen=0;
	printlen = snprintf(replybuffer,(outbufend-replybuffer), "\nTotal statistics (does not include current running sessions):\n\n");
	ADJUSTLEN(printlen,outbufend,replybuffer);
	printlen = snprintf(replybuffer,(outbufend-replybuffer), " Uptime of rtpengine                             :%llu seconds\n", (unsigned long long)time(NULL)-m->totalstats.started);
	ADJUSTLEN(printlen,outbufend,replybuffer);
	printlen = snprintf(replybuffer,(outbufend-replybuffer), " Total managed sessions                          :%llu\n", (unsigned long long)m->totalstats.total_managed_sess);
	ADJUSTLEN(printlen,outbufend,replybuffer);
	printlen = snprintf(replybuffer,(outbufend-replybuffer), " Total timed-out sessions via TIMEOUT            :%llu\n",(unsigned long long)m->totalstats.total_timeout_sess);
	ADJUSTLEN(printlen,outbufend,replybuffer);
	printlen = snprintf(replybuffer,(outbufend-replybuffer), " Total timed-out sessions via SILENT_TIMEOUT     :%llu\n",(unsigned long long)m->totalstats.total_silent_timeout_sess);
	ADJUSTLEN(printlen,outbufend,replybuffer);
	printlen = snprintf(replybuffer,(outbufend-replybuffer), " Total regular terminated sessions               :%llu\n",(unsigned long long)m->totalstats.total_regular_term_sess);
	ADJUSTLEN(printlen,outbufend,replybuffer);
	printlen = snprintf(replybuffer,(outbufend-replybuffer), " Total forced terminated sessions                :%llu\n",(unsigned long long)m->totalstats.total_forced_term_sess);
	ADJUSTLEN(printlen,outbufend,replybuffer);
	printlen = snprintf(replybuffer,(outbufend-replybuffer), " Total relayed packets                           :%llu\n",(unsigned long long)m->totalstats.total_relayed_packets);
	ADJUSTLEN(printlen,outbufend,replybuffer);
	printlen = snprintf(replybuffer,(outbufend-replybuffer), " Total relayed packet errors                     :%llu\n",(unsigned long long)m->totalstats.total_relayed_errors);
	ADJUSTLEN(printlen,outbufend,replybuffer);
	printlen = snprintf(replybuffer,(outbufend-replybuffer), " Total number of streams with no relayed packets :%llu\n", (unsigned long long)m->totalstats.total_nopacket_relayed_sess);
	ADJUSTLEN(printlen,outbufend,replybuffer);
	printlen = snprintf(replybuffer,(outbufend-replybuffer), " Total number of 1-way streams                   :%llu\n",(unsigned long long)m->totalstats.total_oneway_stream_sess);
	ADJUSTLEN(printlen,outbufend,replybuffer);
	printlen = snprintf(replybuffer,(outbufend-replybuffer), " Average call duration                           :%ld.%06ld\n\n",m->totalstats.total_average_call_dur.tv_sec,m->totalstats.total_average_call_dur.tv_usec);
	ADJUSTLEN(printlen,outbufend,replybuffer);
}

static void cli_incoming_list_callid(char* buffer, int len, struct callmaster* m, char* replybuffer, const char* outbufend) {
   str callid;
   struct call* c=0;
   struct call_monologue *ml;
   struct call_media *md;
   struct packet_stream *ps;
   GSList *l;
   GList *k, *o;
   char buf[64];
   int printlen=0;
   char tagtypebuf[16]; memset(&tagtypebuf,0,16);
   struct timeval tim_result_duration; memset(&tim_result_duration,0,sizeof(struct timeval));
   struct timeval now; memset(&now,0,sizeof(struct timeval));

   if (len<=1) {
       printlen = snprintf(replybuffer,(outbufend-replybuffer), "%s\n", "More parameters required.");
       ADJUSTLEN(printlen,outbufend,replybuffer);
       return;
   }
   ++buffer; --len; // one space
   str_init_len(&callid,buffer,len);

   c = call_get(&callid, m);

   if (!c) {
       printlen = snprintf(replybuffer,(outbufend-replybuffer), "\nCall Id not found (%s).\n\n",callid.s);
       ADJUSTLEN(printlen,outbufend,replybuffer);
       return;
   }

   printlen = snprintf (replybuffer,(outbufend-replybuffer), "\ncallid: %30s | deletionmark:%4s | created:%12i  | proxy:%s\n\n", c->callid.s , c->ml_deleted?"yes":"no", (int)c->created, c->created_from);
   ADJUSTLEN(printlen,outbufend,replybuffer);

   for (l = c->monologues; l; l = l->next) {
	   ml = l->data;
	   if (!ml->terminated.tv_sec) {
		   gettimeofday(&now, NULL);
	   } else {
		   now = ml->terminated;
	   }
	   timeval_subtract(&tim_result_duration,&now,&ml->started);
	   printlen = snprintf(replybuffer,(outbufend-replybuffer), "--- Tag '"STR_FORMAT"' type: %s, callduration "
            "%ld.%06ld , in dialogue with '"STR_FORMAT"'\n",
			STR_FMT(&ml->tag), get_tag_type_text(tagtypebuf,ml->tagtype),
            tim_result_duration.tv_sec,
            tim_result_duration.tv_usec,
            ml->active_dialogue ? ml->active_dialogue->tag.len : 6,
                ml->active_dialogue ? ml->active_dialogue->tag.s : "(none)");
       ADJUSTLEN(printlen,outbufend,replybuffer);

       for (k = ml->medias.head; k; k = k->next) {
           md = k->data;

           for (o = md->streams.head; o; o = o->next) {
               ps = o->data;

               if (PS_ISSET(ps, FALLBACK_RTCP))
                   continue;

               smart_ntop_p(buf, &ps->endpoint.ip46, sizeof(buf));

               printlen = snprintf(replybuffer,(outbufend-replybuffer), "------ Media #%u, port %5u <> %15s:%-5hu%s, "
                    "%llu p, %llu b, %llu e\n",
                    md->index,
                    (unsigned int) (ps->sfd ? ps->sfd->fd.localport : 0),
                    buf, ps->endpoint.port,
                    (!PS_ISSET(ps, RTP) && PS_ISSET(ps, RTCP)) ? " (RTCP)" : "",
                        (unsigned long long) ps->stats.packets,
                        (unsigned long long) ps->stats.bytes,
                        (unsigned long long) ps->stats.errors);
               ADJUSTLEN(printlen,outbufend,replybuffer);
           }
       }
   }
   printlen = snprintf(replybuffer,(outbufend-replybuffer), "\n");
   ADJUSTLEN(printlen,outbufend,replybuffer);

   rwlock_unlock_w(&c->master_lock); // because of call_get(..)
}

static void cli_incoming_list(char* buffer, int len, struct callmaster* m, char* replybuffer, const char* outbufend) {
   GHashTableIter iter;
   gpointer key, value;
   str *ptrkey;
   struct call *call;
   int printlen=0;

   static const char* LIST_NUMSESSIONS = "numsessions";
   static const char* LIST_SESSIONS = "sessions";
   static const char* LIST_SESSION = "session";
   static const char* LIST_TOTALS = "totals";

   if (len<=1) {
       printlen = snprintf(replybuffer, outbufend-replybuffer, "%s\n", "More parameters required.");
       ADJUSTLEN(printlen,outbufend,replybuffer);
       return;
   }
   ++buffer; --len; // one space

   if (len>=strlen(LIST_NUMSESSIONS) && strncmp(buffer,LIST_NUMSESSIONS,strlen(LIST_NUMSESSIONS)) == 0) {
       rwlock_lock_r(&m->hashlock);
       printlen = snprintf(replybuffer, outbufend-replybuffer, "Current Sessions on rtpengine:%i\n", g_hash_table_size(m->callhash));
       ADJUSTLEN(printlen,outbufend,replybuffer);
       rwlock_unlock_r(&m->hashlock);
   } else if (len>=strlen(LIST_SESSIONS) && strncmp(buffer,LIST_SESSIONS,strlen(LIST_SESSIONS)) == 0) {
       rwlock_lock_r(&m->hashlock);
       if (g_hash_table_size(m->callhash)==0) {
           printlen = snprintf(replybuffer, outbufend-replybuffer, "No sessions on this media relay.\n");
           ADJUSTLEN(printlen,outbufend,replybuffer);
           rwlock_unlock_r(&m->hashlock);
           return;
       }
       g_hash_table_iter_init (&iter, m->callhash);
       while (g_hash_table_iter_next (&iter, &key, &value)) {
           ptrkey = (str*)key;
           call = (struct call*)value;
           printlen = snprintf(replybuffer, outbufend-replybuffer, "callid: %30s | deletionmark:%4s | created:%12i  | proxy:%s\n", ptrkey->s, call->ml_deleted?"yes":"no", (int)call->created, call->created_from);
           ADJUSTLEN(printlen,outbufend,replybuffer);
       }
       rwlock_unlock_r(&m->hashlock);
   } else if (len>=strlen(LIST_SESSION) && strncmp(buffer,LIST_SESSION,strlen(LIST_SESSION)) == 0) {
       cli_incoming_list_callid(buffer+strlen(LIST_SESSION), len-strlen(LIST_SESSION), m, replybuffer, outbufend);
   } else if (len>=strlen(LIST_TOTALS) && strncmp(buffer,LIST_TOTALS,strlen(LIST_TOTALS)) == 0) {
       cli_incoming_list_totals(buffer+strlen(LIST_TOTALS), len-strlen(LIST_TOTALS), m, replybuffer, outbufend);
   } else {
       printlen = snprintf(replybuffer, outbufend-replybuffer, "%s:%s\n", "Unknown 'list' command", buffer);
       ADJUSTLEN(printlen,outbufend,replybuffer);
   }
}

static void cli_incoming_terminate(char* buffer, int len, struct callmaster* m, char* replybuffer, const char* outbufend) {
   str termparam;
   struct call* c=0;
   int printlen=0;
   GHashTableIter iter;
   gpointer key, value;
   struct call_monologue *ml;
   GSList *i;

   if (len<=1) {
       printlen = snprintf(replybuffer, outbufend-replybuffer, "%s\n", "More parameters required.");
       ADJUSTLEN(printlen,outbufend,replybuffer);
       return;
   }
   ++buffer; --len; // one space
   str_init_len(&termparam,buffer,len);

   // --- terminate all calls
   if (!str_memcmp(&termparam,"all")) {
       while (g_hash_table_size(m->callhash)) {
           g_hash_table_iter_init (&iter, m->callhash);
           g_hash_table_iter_next (&iter, &key, &value);
           c = (struct call*)value;
           if (!c) continue;
           if (!c->ml_deleted) {
        	   for (i = c->monologues; i; i = i->next) {
        		   ml = i->data;
        		   memset(&ml->terminated,0,sizeof(struct timeval));
        		   gettimeofday(&(ml->terminated), NULL);
        		   ml->term_reason = FORCED;
        	   }
           }
           call_destroy(c);
       }
       ilog(LOG_INFO,"All calls terminated by operator.");
       printlen = snprintf(replybuffer, outbufend-replybuffer, "%s\n", "All calls terminated by operator.");
       ADJUSTLEN(printlen,outbufend,replybuffer);
       return;
   }

   // --- terminate a dedicated call id
   c = call_get(&termparam, m);

   if (!c) {
       printlen = snprintf(replybuffer, outbufend-replybuffer, "\nCall Id not found (%s).\n\n",termparam.s);
       ADJUSTLEN(printlen,outbufend,replybuffer);
       return;
   }

   if (!c->ml_deleted) {
	   for (i = c->monologues; i; i = i->next) {
		   ml = i->data;
		   memset(&ml->terminated,0,sizeof(struct timeval));
		   gettimeofday(&(ml->terminated), NULL);
		   ml->term_reason = FORCED;
	   }
   }
   call_destroy(c);

   printlen = snprintf(replybuffer, outbufend-replybuffer, "\nCall Id (%s) successfully terminated by operator.\n\n",termparam.s);
   ADJUSTLEN(printlen,outbufend,replybuffer);
   ilog(LOG_WARN, "Call Id (%s) successfully terminated by operator.",termparam.s);

   rwlock_unlock_w(&c->master_lock);
}

static void cli_incoming(int fd, void *p, uintptr_t u) {
   int nfd;
   struct sockaddr_in sin;
   struct cli *cli = (void *) p;
   socklen_t sinl;
   static const int BUFLENGTH = 4096*1024;
        char replybuffer[BUFLENGTH]; memset(&replybuffer,0,BUFLENGTH);
        char* outbuf = replybuffer;
        const char* outbufend = replybuffer+BUFLENGTH;
   static const int MAXINPUT = 1024;
   char inbuf[MAXINPUT]; memset(&inbuf,0,MAXINPUT);
   int inlen = 0, readbytes = 0;
   int rc=0;

   mutex_lock(&cli->lock);
next:
   sinl = sizeof(sin);
   nfd = accept(fd, (struct sockaddr *) &sin, &sinl);
   if (nfd == -1) {
       if (errno == EAGAIN || errno == EWOULDBLOCK) {
           sprintf(replybuffer, "Could currently not accept CLI commands. Reason:%s\n", strerror(errno));
           goto cleanup;
       }
       ilog(LOG_INFO, "Accept error:%s\n", strerror(errno));
       goto next;
   }

   ilog(LOG_INFO, "New cli connection from " DF, DP(sin));

   do {
       readbytes = read(nfd, inbuf+inlen, MAXINPUT);
       if (readbytes == -1) {
           if (errno == EAGAIN || errno == EWOULDBLOCK) {
               ilog(LOG_INFO, "Could currently not read CLI commands. Reason:%s\n", strerror(errno));
               goto cleanup;
           }
           ilog(LOG_INFO, "Could currently not read CLI commands. Reason:%s\n", strerror(errno));
       }
       inlen += readbytes;
   } while (readbytes > 0);

   ilog(LOG_INFO, "Got CLI command:%s\n",inbuf);

   static const char* LIST = "list";
   static const char* TERMINATE = "terminate";

   if (inlen>=strlen(LIST) && strncmp(inbuf,LIST,strlen(LIST)) == 0) {
       cli_incoming_list(inbuf+strlen(LIST), inlen-strlen(LIST), cli->callmaster, outbuf, outbufend);

   } else  if (inlen>=strlen(TERMINATE) && strncmp(inbuf,TERMINATE,strlen(TERMINATE)) == 0) {
       cli_incoming_terminate(inbuf+strlen(TERMINATE), inlen-strlen(TERMINATE), cli->callmaster, outbuf, outbufend);
   } else {
       sprintf(replybuffer, "%s:%s\n", "Unknown or incomplete command:", inbuf);
   }

   do {
       rc += write( nfd, (char *)&replybuffer, strlen(replybuffer) );
   } while (rc < strlen(replybuffer));

cleanup:
   close(nfd);
   mutex_unlock(&cli->lock);
}

static void control_closed(int fd, void *p, uintptr_t u) {
   abort();
}

struct cli *cli_new(struct poller *p, u_int32_t ip, u_int16_t port, struct callmaster *m) {
   struct cli *c;
   int fd;
   struct sockaddr_in sin;
   struct poller_item i;

   if (!p || !m)
       return NULL;

   fd = socket(AF_INET, SOCK_STREAM, 0);
   if (fd == -1)
       return NULL;

   nonblock(fd);
   reuseaddr(fd);

   ZERO(sin);
   sin.sin_family = AF_INET;
   sin.sin_addr.s_addr = ip;
   sin.sin_port = htons(port);
   if (bind(fd, (struct sockaddr *) &sin, sizeof(sin)))
       goto fail;

   if (listen(fd, 5))
       goto fail;

   c = obj_alloc0("cli_udp", sizeof(*c), NULL);
   c->fd = fd;
   c->poller = p;
   c->callmaster = m;
   mutex_init(&c->lock);

   ZERO(i);
   i.fd = fd;
   i.closed = control_closed;
   i.readable = cli_incoming;
   i.obj = &c->obj;
   if (poller_add_item(p, &i))
       goto fail2;

   obj_put(c);
   return c;

fail2:
   obj_put(c);
fail:
   close(fd);
   return NULL;
}
