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
#include "socket.h"

#include "rtpengine_config.h"

static const char* TRUNCATED = "    ... Output truncated. Increase Output Buffer ...\n";

#define truncate_output(x) strcpy(x - strlen(TRUNCATED) - 1, TRUNCATED)

#define ADJUSTLEN(printlen,outbuflen,replybuffer) do { \
               replybuffer += (printlen>=outbufend-replybuffer)?outbufend-replybuffer:printlen; \
               if (replybuffer == outbufend) \
                       truncate_output(replybuffer); \
       } while (0);

static void cli_incoming_list_totals(char* buffer, int len, struct callmaster* m, char* replybuffer, const char* outbufend) {
	int printlen=0;
	struct timeval avg;
	u_int64_t num_sessions;

	mutex_lock(&m->totalstats.total_average_lock);
	avg = m->totalstats.total_average_call_dur;
	num_sessions = m->totalstats.total_managed_sess;
	mutex_unlock(&m->totalstats.total_average_lock);

	printlen = snprintf(replybuffer,(outbufend-replybuffer), "\nTotal statistics (does not include current running sessions):\n\n");
	ADJUSTLEN(printlen,outbufend,replybuffer);
	printlen = snprintf(replybuffer,(outbufend-replybuffer), " Uptime of rtpengine                             :%llu seconds\n", (unsigned long long)time(NULL)-m->totalstats.started);
	ADJUSTLEN(printlen,outbufend,replybuffer);
	printlen = snprintf(replybuffer,(outbufend-replybuffer), " Total managed sessions                          :"UINT64F"\n", num_sessions);
	ADJUSTLEN(printlen,outbufend,replybuffer);
	printlen = snprintf(replybuffer,(outbufend-replybuffer), " Total rejected sessions                         :"UINT64F"\n", atomic64_get(&m->totalstats.total_rejected_sess));
	ADJUSTLEN(printlen,outbufend,replybuffer);
	printlen = snprintf(replybuffer,(outbufend-replybuffer), " Total timed-out sessions via TIMEOUT            :"UINT64F"\n",atomic64_get(&m->totalstats.total_timeout_sess));
	ADJUSTLEN(printlen,outbufend,replybuffer);
	printlen = snprintf(replybuffer,(outbufend-replybuffer), " Total timed-out sessions via SILENT_TIMEOUT     :"UINT64F"\n",atomic64_get(&m->totalstats.total_silent_timeout_sess));
	ADJUSTLEN(printlen,outbufend,replybuffer);
	printlen = snprintf(replybuffer,(outbufend-replybuffer), " Total regular terminated sessions               :"UINT64F"\n",atomic64_get(&m->totalstats.total_regular_term_sess));
	ADJUSTLEN(printlen,outbufend,replybuffer);
	printlen = snprintf(replybuffer,(outbufend-replybuffer), " Total forced terminated sessions                :"UINT64F"\n",atomic64_get(&m->totalstats.total_forced_term_sess));
	ADJUSTLEN(printlen,outbufend,replybuffer);
	printlen = snprintf(replybuffer,(outbufend-replybuffer), " Total relayed packets                           :"UINT64F"\n",atomic64_get(&m->totalstats.total_relayed_packets));
	ADJUSTLEN(printlen,outbufend,replybuffer);
	printlen = snprintf(replybuffer,(outbufend-replybuffer), " Total relayed packet errors                     :"UINT64F"\n",atomic64_get(&m->totalstats.total_relayed_errors));
	ADJUSTLEN(printlen,outbufend,replybuffer);
	printlen = snprintf(replybuffer,(outbufend-replybuffer), " Total number of streams with no relayed packets :"UINT64F"\n", atomic64_get(&m->totalstats.total_nopacket_relayed_sess));
	ADJUSTLEN(printlen,outbufend,replybuffer);
	printlen = snprintf(replybuffer,(outbufend-replybuffer), " Total number of 1-way streams                   :"UINT64F"\n",atomic64_get(&m->totalstats.total_oneway_stream_sess));
	ADJUSTLEN(printlen,outbufend,replybuffer);
	printlen = snprintf(replybuffer,(outbufend-replybuffer), " Average call duration                           :%ld.%06ld\n\n",avg.tv_sec,avg.tv_usec);
	ADJUSTLEN(printlen,outbufend,replybuffer);

	printlen = snprintf(replybuffer,(outbufend-replybuffer), "Control statistics:\n\n");
	ADJUSTLEN(printlen,outbufend,replybuffer);
	printlen = snprintf(replybuffer,(outbufend-replybuffer), " %10s | %10s | %10s | %10s | %10s | %10s | %10s | %10s \n",
			"Proxy", "Offer", "Answer", "Delete", "Ping", "List", "Query", "Errors");
	ADJUSTLEN(printlen,outbufend,replybuffer);

	mutex_lock(&m->cngs_lock);
	GList *list = g_hash_table_get_values(m->cngs_hash);

	if (!list) {
		printlen = snprintf(replybuffer,(outbufend-replybuffer), "\n                  No proxies have yet tried to send data.");
		ADJUSTLEN(printlen,outbufend,replybuffer);
	}
	for (GList *l = list; l; l = l->next) {
		struct control_ng_stats* cur = l->data;

		printlen = snprintf(replybuffer,(outbufend-replybuffer), " %10s | %10u | %10u | %10u | %10u | %10u | %10u | %10u \n",
				sockaddr_print_buf(&cur->proxy),
				cur->offer,
				cur->answer,
				cur->delete,
				cur->ping,
				cur->list,
				cur->query,
				cur->errors);
		ADJUSTLEN(printlen,outbufend,replybuffer);
	}
	printlen = snprintf(replybuffer,(outbufend-replybuffer), "\n\n");
	ADJUSTLEN(printlen,outbufend,replybuffer);
	mutex_unlock(&m->cngs_lock);
	g_list_free(list);
}

static void cli_incoming_list_callid(char* buffer, int len, struct callmaster* m, char* replybuffer, const char* outbufend) {
   str callid;
   struct call* c=0;
   struct call_monologue *ml;
   struct call_media *md;
   struct packet_stream *ps;
   GSList *l;
   GList *k, *o;
   int printlen=0;
   struct timeval tim_result_duration;
   struct timeval now;

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

   printlen = snprintf (replybuffer,(outbufend-replybuffer), "\ncallid: %30s | deletionmark:%4s | created:%12i  | proxy:%s | tos:%u | last_signal:%llu\n\n",
		   c->callid.s , c->ml_deleted?"yes":"no", (int)c->created, c->created_from, (unsigned int)c->tos, (unsigned long long)c->last_signal);
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
			STR_FMT(&ml->tag), get_tag_type_text(ml->tagtype),
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

#if (RE_HAS_MEASUREDELAY)
               if (!PS_ISSET(ps, RTP) && PS_ISSET(ps, RTCP)) {
            	   printlen = snprintf(replybuffer,(outbufend-replybuffer), "------ Media #%u, port %5u <> %15s:%-5hu%s, "
            			   ""UINT64F" p, "UINT64F" b, "UINT64F" e, "UINT64F" last_packet\n",
						   md->index,
						   (unsigned int) (ps->sfd ? ps->sfd->fd.localport : 0),
						   smart_ntop_p_buf(&ps->endpoint.ip46), ps->endpoint.port,
						   (!PS_ISSET(ps, RTP) && PS_ISSET(ps, RTCP)) ? " (RTCP)" : "",
								   atomic64_get(&ps->stats.packets),
								   atomic64_get(&ps->stats.bytes),
								   atomic64_get(&ps->stats.errors),
								   atomic64_get(&ps->last_packet));
               } else {
            	   printlen = snprintf(replybuffer,(outbufend-replybuffer), "------ Media #%u, port %5u <> %15s:%-5hu%s, "
			   ""UINT64F" p, "UINT64F" b, "UINT64F" e, "UINT64F" last_packet, %.9f delay_min, %.9f delay_avg, %.9f delay_max\n",
						   md->index,
						   (unsigned int) (ps->sfd ? ps->sfd->fd.localport : 0),
						   smart_ntop_p_buf(&ps->endpoint.ip46), ps->endpoint.port,
						   (!PS_ISSET(ps, RTP) && PS_ISSET(ps, RTCP)) ? " (RTCP)" : "",
								   atomic64_get(&ps->stats.packets),
								   atomic64_get(&ps->stats.bytes),
								   atomic64_get(&ps->stats.errors),
								   atomic64_get(&ps->last_packet),
								   (double) ps->stats.delay_min / 1000000,
								   (double) ps->stats.delay_avg / 1000000,
								   (double) ps->stats.delay_max / 1000000);
               }
#else
               printlen = snprintf(replybuffer,(outbufend-replybuffer), "------ Media #%u, port %5u <> %15s:%-5u%s, "
                    ""UINT64F" p, "UINT64F" b, "UINT64F" e, "UINT64F" last_packet\n",
                    md->index,
                    (unsigned int) (ps->selected_sfd ? ps->selected_sfd->socket.local.port : 0),
                    sockaddr_print_buf(&ps->endpoint.address), ps->endpoint.port,
                    (!PS_ISSET(ps, RTP) && PS_ISSET(ps, RTCP)) ? " (RTCP)" : "",
                         atomic64_get(&ps->stats.packets),
                         atomic64_get(&ps->stats.bytes),
                         atomic64_get(&ps->stats.errors),
                         atomic64_get(&ps->last_packet));
#endif
               ADJUSTLEN(printlen,outbufend,replybuffer);
           }
       }
   }
   printlen = snprintf(replybuffer,(outbufend-replybuffer), "\n");
   ADJUSTLEN(printlen,outbufend,replybuffer);

   rwlock_unlock_w(&c->master_lock); // because of call_get(..)
   obj_put(c);
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
		   gettimeofday(&(ml->terminated), NULL);
		   ml->term_reason = FORCED;
	   }
   }

   printlen = snprintf(replybuffer, outbufend-replybuffer, "\nCall Id (%s) successfully terminated by operator.\n\n",termparam.s);
   ADJUSTLEN(printlen,outbufend,replybuffer);
   ilog(LOG_WARN, "Call Id (%s) successfully terminated by operator.",termparam.s);

   rwlock_unlock_w(&c->master_lock);

   call_destroy(c);
   obj_put(c);
}

static void cli_incoming(int fd, void *p, uintptr_t u) {
   int nfd;
   struct sockaddr_in sin;
   struct cli *cli = (void *) p;
   socklen_t sinl;
   static const int BUFLENGTH = 4096*1024;
        char replybuffer[BUFLENGTH];
        char* outbuf = replybuffer;
        const char* outbufend = replybuffer+BUFLENGTH;
   static const int MAXINPUT = 1024;
   char inbuf[MAXINPUT];
   int inlen = 0, readbytes = 0;
   int rc=0;

   mutex_lock(&cli->lock);
next:
   sinl = sizeof(sin);
   nfd = accept(fd, (struct sockaddr *) &sin, &sinl);
   if (nfd == -1) {
       if (errno == EAGAIN || errno == EWOULDBLOCK) {
           ilog(LOG_INFO, "Could currently not accept CLI commands. Reason:%s", strerror(errno));
           goto cleanup;
       }
       ilog(LOG_INFO, "Accept error:%s", strerror(errno));
       goto next;
   }

   ilog(LOG_INFO, "New cli connection from " DF, DP(sin));

   do {
       readbytes = read(nfd, inbuf+inlen, MAXINPUT);
       if (readbytes == -1) {
           if (errno == EAGAIN || errno == EWOULDBLOCK) {
               ilog(LOG_INFO, "Could currently not read CLI commands. Reason:%s", strerror(errno));
               goto cleanup;
           }
           ilog(LOG_INFO, "Could currently not read CLI commands. Reason:%s", strerror(errno));
       }
       inlen += readbytes;
   } while (readbytes > 0 && inlen < sizeof(inbuf)-1);

   inbuf[inlen] = 0;
   ilog(LOG_INFO, "Got CLI command:%s",inbuf);

   static const char* LIST = "list";
   static const char* TERMINATE = "terminate";

   if (strncmp(inbuf,LIST,strlen(LIST)) == 0) {
       cli_incoming_list(inbuf+strlen(LIST), inlen-strlen(LIST), cli->callmaster, outbuf, outbufend);

   } else  if (strncmp(inbuf,TERMINATE,strlen(TERMINATE)) == 0) {
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

struct cli *cli_new(struct poller *p, const endpoint_t *ep, struct callmaster *m) {
   struct cli *c;
   socket_t sock;
   struct poller_item i;

   if (!p || !m)
       return NULL;

   if (open_socket(&sock, SOCK_STREAM, ep->port, &ep->address))
	   return NULL;

   if (listen(sock.fd, 5))
       goto fail;

   c = obj_alloc0("cli_udp", sizeof(*c), NULL);
   c->sock = sock;
   c->poller = p;
   c->callmaster = m;
   mutex_init(&c->lock);

   ZERO(i);
   i.fd = sock.fd;
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
   close_socket(&sock);
   return NULL;
}
