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
#include "log_funcs.h"
#include "call.h"
#include "cli.h"
#include "socket.h"
#include "redis.h"
#include "control_ng.h"
#include "media_socket.h"
#include "cdr.h"

#include "rtpengine_config.h"


static void destroy_own_foreign_calls(struct callmaster *m, unsigned int foreign_call, unsigned int uint_keyspace_db) {
	struct call *c = NULL;
	struct call_monologue *ml = NULL;
	GQueue call_list = G_QUEUE_INIT;
	GHashTableIter iter;
	gpointer key, value;
	GList *i;

	// lock read
	rwlock_lock_r(&m->hashlock);

	g_hash_table_iter_init(&iter, m->callhash);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		c = (struct call*)value;
		if (!c) {
			continue;
		}

		// match foreign_call flag
		if ((foreign_call != UNDEFINED) && !(foreign_call == IS_FOREIGN_CALL(c))) {
			continue;
		}

		// match uint_keyspace_db, if some given
		if ((uint_keyspace_db != UNDEFINED) && !(uint_keyspace_db == c->redis_hosted_db)) {
			continue;
		}
		
		// increase ref counter
		obj_get(c);

		// save call reference
		g_queue_push_tail(&call_list, c);
	}

	// unlock read
	rwlock_unlock_r(&m->hashlock);

	// destroy calls
	while ((c = g_queue_pop_head(&call_list))) {
		if (!c->ml_deleted) {
			for (i = c->monologues.head; i; i = i->next) {
				ml = i->data;
				gettimeofday(&(ml->terminated), NULL);
				ml->term_reason = FORCED;
			}
		}
		call_destroy(c);

		// decrease ref counter
		obj_put(c);
	}
}

static void destroy_all_foreign_calls(struct callmaster *m) {
	destroy_own_foreign_calls(m, CT_FOREIGN_CALL, UNDEFINED);
}

static void destroy_all_own_calls(struct callmaster *m) {
	destroy_own_foreign_calls(m, CT_OWN_CALL, UNDEFINED);
}

static void destroy_keyspace_foreign_calls(struct callmaster *m, unsigned int uint_keyspace_db) {
	destroy_own_foreign_calls(m, CT_FOREIGN_CALL, uint_keyspace_db);
}

static void cli_incoming_list_totals(char* buffer, int len, struct callmaster* m, char* replybuffer, const char* outbufend) {
	int printlen=0;
	struct timeval avg, calls_dur_iv;
	u_int64_t num_sessions, min_sess_iv, max_sess_iv;
	struct request_time offer_iv, answer_iv, delete_iv;

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
	printlen = snprintf(replybuffer,(outbufend-replybuffer), " Total timed-out sessions via FINAL_TIMEOUT      :"UINT64F"\n",atomic64_get(&m->totalstats.total_final_timeout_sess));
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

	mutex_lock(&m->totalstats_lastinterval_lock);
	calls_dur_iv = m->totalstats_lastinterval.total_calls_duration_interval;
	min_sess_iv = m->totalstats_lastinterval.managed_sess_min;
	max_sess_iv = m->totalstats_lastinterval.managed_sess_max;
	offer_iv = m->totalstats_lastinterval.offer;
	answer_iv = m->totalstats_lastinterval.answer;
	delete_iv = m->totalstats_lastinterval.delete;
	mutex_unlock(&m->totalstats_lastinterval_lock);

	// compute average offer/answer/delete time
	timeval_divide(&offer_iv.time_avg, &offer_iv.time_avg, offer_iv.count);
	timeval_divide(&answer_iv.time_avg, &answer_iv.time_avg, answer_iv.count);
	timeval_divide(&delete_iv.time_avg, &delete_iv.time_avg, delete_iv.count);

	printlen = snprintf(replybuffer,(outbufend-replybuffer), "\nGraphite interval statistics (last reported values to graphite):\n");
	ADJUSTLEN(printlen,outbufend,replybuffer);
	printlen = snprintf(replybuffer,(outbufend-replybuffer), " Total calls duration                            :%ld.%06ld\n\n",calls_dur_iv.tv_sec,calls_dur_iv.tv_usec);
	ADJUSTLEN(printlen,outbufend,replybuffer);
	printlen = snprintf(replybuffer,(outbufend-replybuffer), " Min managed sessions                            :"UINT64F"\n", min_sess_iv);
	ADJUSTLEN(printlen,outbufend,replybuffer);
	printlen = snprintf(replybuffer,(outbufend-replybuffer), " Max managed sessions                            :"UINT64F"\n", max_sess_iv);
	ADJUSTLEN(printlen,outbufend,replybuffer);
	printlen = snprintf(replybuffer,(outbufend-replybuffer), " Min/Max/Avg offer processing delay              :%llu.%06llu/%llu.%06llu/%llu.%06llu sec\n",
		(unsigned long long)offer_iv.time_min.tv_sec,(unsigned long long)offer_iv.time_min.tv_usec,
		(unsigned long long)offer_iv.time_max.tv_sec,(unsigned long long)offer_iv.time_max.tv_usec,
		(unsigned long long)offer_iv.time_avg.tv_sec,(unsigned long long)offer_iv.time_avg.tv_usec);
	ADJUSTLEN(printlen,outbufend,replybuffer);
	printlen = snprintf(replybuffer,(outbufend-replybuffer), " Min/Max/Avg answer processing delay             :%llu.%06llu/%llu.%06llu/%llu.%06llu sec\n",
		(unsigned long long)answer_iv.time_min.tv_sec,(unsigned long long)answer_iv.time_min.tv_usec,
		(unsigned long long)answer_iv.time_max.tv_sec,(unsigned long long)answer_iv.time_max.tv_usec,
		(unsigned long long)answer_iv.time_avg.tv_sec,(unsigned long long)answer_iv.time_avg.tv_usec);
	ADJUSTLEN(printlen,outbufend,replybuffer);
	printlen = snprintf(replybuffer,(outbufend-replybuffer), " Min/Max/Avg delete processing delay             :%llu.%06llu/%llu.%06llu/%llu.%06llu sec\n",
		(unsigned long long)delete_iv.time_min.tv_sec,(unsigned long long)delete_iv.time_min.tv_usec,
		(unsigned long long)delete_iv.time_max.tv_sec,(unsigned long long)delete_iv.time_max.tv_usec,
		(unsigned long long)delete_iv.time_avg.tv_sec,(unsigned long long)delete_iv.time_avg.tv_usec);
	ADJUSTLEN(printlen,outbufend,replybuffer);

	printlen = snprintf(replybuffer,(outbufend-replybuffer), "\n\n");
	ADJUSTLEN(printlen,outbufend,replybuffer);

	printlen = snprintf(replybuffer,(outbufend-replybuffer), "Control statistics:\n\n");
	ADJUSTLEN(printlen,outbufend,replybuffer);
	printlen = snprintf(replybuffer,(outbufend-replybuffer), " %20s | %10s | %10s | %10s | %10s | %10s | %10s | %10s | %10s \n",
			"Proxy", "Offer", "Answer", "Delete", "Ping", "List", "Query", "StartRec", "Errors");
	ADJUSTLEN(printlen,outbufend,replybuffer);

	mutex_lock(&m->cngs_lock);
	GList *list = g_hash_table_get_values(m->cngs_hash);

	if (!list) {
		printlen = snprintf(replybuffer,(outbufend-replybuffer), "\n                  No proxies have yet tried to send data.");
		ADJUSTLEN(printlen,outbufend,replybuffer);
	}
	for (GList *l = list; l; l = l->next) {
		struct control_ng_stats* cur = l->data;
		printlen = snprintf(replybuffer,(outbufend-replybuffer), " %20s | %10u | %10u | %10u | %10u | %10u | %10u | %10u | %10u \n",
				sockaddr_print_buf(&cur->proxy),
				cur->offer,
				cur->answer,
				cur->delete,
				cur->ping,
				cur->list,
				cur->query,
				cur->start_recording,
				cur->errors);
		ADJUSTLEN(printlen,outbufend,replybuffer);
	}
	printlen = snprintf(replybuffer,(outbufend-replybuffer), "\n\n");
	ADJUSTLEN(printlen,outbufend,replybuffer);
	mutex_unlock(&m->cngs_lock);
	g_list_free(list);
}

static void cli_incoming_list_maxsessions(char* buffer, int len, struct callmaster* m, char* replybuffer, const char* outbufend) {
	int printlen=0;

	/* don't lock anything while reading the value */
	printlen = snprintf(replybuffer,(outbufend-replybuffer), "Maximum sessions configured on rtpengine: %d\n", m->conf.max_sessions);
	ADJUSTLEN(printlen,outbufend,replybuffer);

	return ;
}

static void cli_incoming_list_maxopenfiles(char* buffer, int len, struct callmaster* m, char* replybuffer, const char* outbufend) {
	int printlen=0;
	struct rlimit rlim;
	pid_t pid = getpid();

	if (getrlimit(RLIMIT_NOFILE, &rlim) == -1) {
		printlen = snprintf(replybuffer,(outbufend-replybuffer), "Fail getting rtpengine configured limits; cat /proc/%u/limits\n", pid);
		ADJUSTLEN(printlen,outbufend,replybuffer);
		return ;
	}

	if (rlim.rlim_cur == RLIM_INFINITY) {
		printlen = snprintf(replybuffer,(outbufend-replybuffer), "Maximum open-files configured on rtpengine: infinite; cat /proc/%u/limits\n", pid);
		ADJUSTLEN(printlen,outbufend,replybuffer);
	} else {
		printlen = snprintf(replybuffer,(outbufend-replybuffer), "Maximum open-files configured on rtpengine: %lld; cat /proc/%u/limits\n", (long long) rlim.rlim_cur, pid);
		ADJUSTLEN(printlen,outbufend,replybuffer);
	}

	return ;
}

static void cli_incoming_list_timeout(char* buffer, int len, struct callmaster* m, char* replybuffer, const char* outbufend) {
	int printlen=0;

	rwlock_lock_r(&m->conf.config_lock);

	/* don't lock anything while reading the value */
	printlen = snprintf(replybuffer,(outbufend-replybuffer), "TIMEOUT=%u\n", m->conf.timeout);
	ADJUSTLEN(printlen,outbufend,replybuffer);
	printlen = snprintf(replybuffer,(outbufend-replybuffer), "SILENT_TIMEOUT=%u\n", m->conf.silent_timeout);
	ADJUSTLEN(printlen,outbufend,replybuffer);
	printlen = snprintf(replybuffer,(outbufend-replybuffer), "FINAL_TIMEOUT=%u\n", m->conf.final_timeout);
	ADJUSTLEN(printlen,outbufend,replybuffer);

	rwlock_unlock_r(&m->conf.config_lock);

	return ;
}

static void cli_incoming_list_callid(char* buffer, int len, struct callmaster* m, char* replybuffer, const char* outbufend) {
   str callid;
   struct call* c=0;
   struct call_monologue *ml;
   struct call_media *md;
   struct packet_stream *ps;
   GList *l;
   GList *k, *o;
   int printlen=0;
   struct timeval tim_result_duration;
   struct timeval now;
   char * local_addr;

   if (len<=1) {
       printlen = snprintf(replybuffer,(outbufend-replybuffer), "%s\n", "More parameters required.");
       ADJUSTLEN(printlen,outbufend,replybuffer);
       return;
   }
//   ++buffer; --len; // one space
   str_init_len(&callid,buffer,len);

   c = call_get(&callid, m);

   if (!c) {
       printlen = snprintf(replybuffer,(outbufend-replybuffer), "\nCall Id not found (%s).\n\n",callid.s);
       ADJUSTLEN(printlen,outbufend,replybuffer);
       return;
   }

   printlen = snprintf (replybuffer,(outbufend-replybuffer), "\ncallid: %60s | deletionmark:%4s | created:%12i  | proxy:%s | tos:%u | last_signal:%llu | redis_keyspace:%i | foreign:%s\n\n",
		   c->callid.s , c->ml_deleted?"yes":"no", (int)c->created.tv_sec, c->created_from, (unsigned int)c->tos, (unsigned long long)c->last_signal, c->redis_hosted_db, IS_FOREIGN_CALL(c)?"yes":"no");
   ADJUSTLEN(printlen,outbufend,replybuffer);

   for (l = c->monologues.head; l; l = l->next) {
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

               local_addr = ps->selected_sfd ? sockaddr_print_buf(&ps->selected_sfd->socket.local.address) : "0.0.0.0";
#if (RE_HAS_MEASUREDELAY)
               if (!PS_ISSET(ps, RTP) && PS_ISSET(ps, RTCP)) {
		   printlen = snprintf(replybuffer,(outbufend-replybuffer), "------ Media #%u, %15s:%-5hu <> %15s:%-5hu%s, "
            			   ""UINT64F" p, "UINT64F" b, "UINT64F" e, "UINT64F" last_packet\n",
						   md->index,
						   local_addr, (unsigned int) (ps->sfd ? ps->sfd->fd.localport : 0),
						   sockaddr_print_buf(&ps->endpoint.ip46), ps->endpoint.port,
						   (!PS_ISSET(ps, RTP) && PS_ISSET(ps, RTCP)) ? " (RTCP)" : "",
								   atomic64_get(&ps->stats.packets),
								   atomic64_get(&ps->stats.bytes),
								   atomic64_get(&ps->stats.errors),
								   atomic64_get(&ps->last_packet));
               } else {
		   printlen = snprintf(replybuffer,(outbufend-replybuffer), "------ Media #%u, %15s:%-5hu <> %15s:%-5hu%s, "
			   ""UINT64F" p, "UINT64F" b, "UINT64F" e, "UINT64F" last_packet, %.9f delay_min, %.9f delay_avg, %.9f delay_max\n",
						   md->index,
						   local_addr, (unsigned int) (ps->sfd ? ps->sfd->fd.localport : 0),
						   sockaddr_print_buf(&ps->endpoint.ip46), ps->endpoint.port,
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
               printlen = snprintf(replybuffer,(outbufend-replybuffer), "------ Media #%u, %15s:%-5u <> %15s:%-5u%s, "
                    ""UINT64F" p, "UINT64F" b, "UINT64F" e, "UINT64F" last_packet\n",
                    md->index,
                    local_addr, (unsigned int) (ps->selected_sfd ? ps->selected_sfd->socket.local.port : 0),
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

static void cli_incoming_list_sessions(char* buffer, int len, struct callmaster* m, char* replybuffer, const char* outbufend) {
	int printlen=0;
	GHashTableIter iter;
	gpointer key, value;
	str *ptrkey;
	struct call *call;
	int found_own = 0, found_foreign = 0;

	static const char* LIST_ALL = "all";
	static const char* LIST_OWN = "own";
	static const char* LIST_FOREIGN = "foreign";

	if (len<=1) {
		printlen = snprintf(replybuffer, outbufend-replybuffer, "%s\n", "More parameters required.");
		ADJUSTLEN(printlen,outbufend,replybuffer);
		return;
	}
	++buffer; --len; // one space

	rwlock_lock_r(&m->hashlock);

	if (g_hash_table_size(m->callhash)==0) {
		printlen = snprintf(replybuffer, outbufend-replybuffer, "No sessions on this media relay.\n");
		ADJUSTLEN(printlen,outbufend,replybuffer);
		rwlock_unlock_r(&m->hashlock);
		return;
	}

	g_hash_table_iter_init (&iter, m->callhash);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		ptrkey = (str*)key;
		call = (struct call*)value;

		if (len>=strlen(LIST_ALL) && strncmp(buffer,LIST_ALL,strlen(LIST_ALL)) == 0) {
			if (!call) {
				continue;
			}
		} else if (len>=strlen(LIST_OWN) && strncmp(buffer,LIST_OWN,strlen(LIST_OWN)) == 0) {
			if (!call || IS_FOREIGN_CALL(call)) {
				continue;
			} else {
				found_own = 1;
			}
		} else if (len>=strlen(LIST_FOREIGN) && strncmp(buffer,LIST_FOREIGN,strlen(LIST_FOREIGN)) == 0) {
			if (!call || !IS_FOREIGN_CALL(call)) {
				continue;
			} else {
				found_foreign = 1;
			}
		} else {
			// expect callid parameter
			break;
		}

		printlen = snprintf(replybuffer, outbufend-replybuffer, "callid: %60s | deletionmark:%4s | created:%12i | proxy:%s | redis_keyspace:%i | foreign:%s\n", ptrkey->s, call->ml_deleted?"yes":"no", (int)call->created.tv_sec, call->created_from, call->redis_hosted_db, IS_FOREIGN_CALL(call)?"yes":"no");
		ADJUSTLEN(printlen,outbufend,replybuffer);
	}
	rwlock_unlock_r(&m->hashlock);

	if (len>=strlen(LIST_ALL) && strncmp(buffer,LIST_ALL,strlen(LIST_ALL)) == 0) {
		;
	} else if (len>=strlen(LIST_OWN) && strncmp(buffer,LIST_OWN,strlen(LIST_OWN)) == 0) {
		if (!found_own) {
			printlen = snprintf(replybuffer, outbufend-replybuffer, "No own sessions on this media relay.\n");
			ADJUSTLEN(printlen,outbufend,replybuffer);
		}
	} else if (len>=strlen(LIST_FOREIGN) && strncmp(buffer,LIST_FOREIGN,strlen(LIST_FOREIGN)) == 0) {
		if (!found_foreign) {
			printlen = snprintf(replybuffer, outbufend-replybuffer, "No foreign sessions on this media relay.\n");
			ADJUSTLEN(printlen,outbufend,replybuffer);
		}
	} else {
		// list session for callid
		cli_incoming_list_callid(buffer, len, m, replybuffer, outbufend);
	}

	return;
}

static void cli_incoming_set_maxopenfiles(char* buffer, int len, struct callmaster* m, char* replybuffer, const char* outbufend) {
	int printlen = 0;
	unsigned long open_files_num;
	str open_files;
	pid_t pid;
	char *endptr;

	// limit the minimum number of open files to avoid rtpengine freeze for low open_files_num values
	unsigned long min_open_files_num = (1 << 16);

	if (len <= 1) {
		printlen = snprintf(replybuffer,(outbufend-replybuffer), "%s\n", "More parameters required.");
		ADJUSTLEN(printlen,outbufend,replybuffer);
		return;
	}

	++buffer; --len; // one space
	open_files.s = buffer;
	open_files.len = len;
	open_files_num = strtoul(open_files.s, &endptr, 10);

	if ((errno == ERANGE && (open_files_num == ULONG_MAX)) || (errno != 0 && open_files_num == 0)) {
		printlen = snprintf (replybuffer,(outbufend-replybuffer), "Fail setting open_files to %.*s; errno=%d\n", open_files.len, open_files.s, errno);
		ADJUSTLEN(printlen,outbufend,replybuffer);
		return;
	} else if (endptr == open_files.s) {
		printlen = snprintf (replybuffer,(outbufend-replybuffer), "Fail setting open_files to %.*s; no digists found\n", open_files.len, open_files.s);
		ADJUSTLEN(printlen,outbufend,replybuffer);
		return;
	} else if (open_files_num < min_open_files_num) {
		printlen = snprintf (replybuffer,(outbufend-replybuffer), "Fail setting open_files to %lu; can't set it under %lu\n", open_files_num, min_open_files_num);
		ADJUSTLEN(printlen,outbufend,replybuffer);
		return;
	} else if (rlim(RLIMIT_NOFILE, open_files_num) == -1){
		printlen = snprintf (replybuffer,(outbufend-replybuffer), "Fail setting open_files to %lu; errno = %d\n", open_files_num, errno);
		ADJUSTLEN(printlen,outbufend,replybuffer);
		return;
	} else {
		pid = getpid();
		printlen = snprintf (replybuffer,(outbufend-replybuffer), "Success setting open_files to %lu; cat /proc/%u/limits\n", open_files_num, pid);
		ADJUSTLEN(printlen,outbufend,replybuffer);
	}
}

static void cli_incoming_set_maxsessions(char* buffer, int len, struct callmaster* m, char* replybuffer, const char* outbufend) {
	int printlen = 0;
	long maxsessions_num;
	int disabled = -1;
	str maxsessions;
	char *endptr;

	if (len <= 1) {
		printlen = snprintf(replybuffer,(outbufend-replybuffer), "%s\n", "More parameters required.");
		ADJUSTLEN(printlen,outbufend,replybuffer);
		return;
	}

	++buffer; --len; // one space
	maxsessions.s = buffer;
	maxsessions.len = len;
	maxsessions_num = strtol(maxsessions.s, &endptr, 10);

	if ((errno == ERANGE && (maxsessions_num == LONG_MAX || maxsessions_num == LONG_MIN)) || (errno != 0 && maxsessions_num == 0)) {
		printlen = snprintf (replybuffer,(outbufend-replybuffer), "Fail setting maxsessions to %.*s; errno=%d\n", maxsessions.len, maxsessions.s, errno);
		ADJUSTLEN(printlen,outbufend,replybuffer);
		return;
	} else if (endptr == maxsessions.s) {
		printlen = snprintf (replybuffer,(outbufend-replybuffer), "Fail setting maxsessions to %.*s; no digists found\n", maxsessions.len, maxsessions.s);
		ADJUSTLEN(printlen,outbufend,replybuffer);
		return;
	} else if (maxsessions_num < disabled) {
		printlen = snprintf (replybuffer,(outbufend-replybuffer), "Fail setting maxsessions to %ld; either positive or -1 values allowed\n", maxsessions_num);
		ADJUSTLEN(printlen,outbufend,replybuffer);
	} else if (maxsessions_num == disabled) {
		rwlock_lock_w(&m->conf.config_lock);
		m->conf.max_sessions = maxsessions_num;
		rwlock_unlock_w(&m->conf.config_lock);
		printlen = snprintf (replybuffer,(outbufend-replybuffer), "Success setting maxsessions to %ld; disable feature\n", maxsessions_num);
		ADJUSTLEN(printlen,outbufend,replybuffer);
	} else {
		rwlock_lock_w(&m->conf.config_lock);
		m->conf.max_sessions = maxsessions_num;
		rwlock_unlock_w(&m->conf.config_lock);
		printlen = snprintf (replybuffer,(outbufend-replybuffer), "Success setting maxsessions to %ld\n", maxsessions_num);
		ADJUSTLEN(printlen,outbufend,replybuffer);
	}

	return;
}

static void cli_incoming_set_timeout(char* buffer, int len, struct callmaster* m, char* replybuffer, const char* outbufend, unsigned int *conf_timeout) {
	int printlen = 0;
	unsigned long timeout_num;
	str timeout;
	char *endptr;

	if (len <= 1) {
		printlen = snprintf(replybuffer,(outbufend-replybuffer), "%s\n", "More parameters required.");
		ADJUSTLEN(printlen,outbufend,replybuffer);
		return;
	}

	++buffer; --len; // one space
	timeout.s = buffer;
	timeout.len = len;
	timeout_num = strtoul(timeout.s, &endptr, 10);

	if ((errno == ERANGE && (timeout_num == ULONG_MAX)) || (errno != 0 && timeout_num == 0)) {
		printlen = snprintf (replybuffer,(outbufend-replybuffer), "Fail setting timeout to %.*s; errno=%d\n", timeout.len, timeout.s, errno);
		ADJUSTLEN(printlen,outbufend,replybuffer);
		return;
	} else if (endptr == timeout.s) {
		printlen = snprintf (replybuffer,(outbufend-replybuffer), "Fail setting timeout to %.*s; no digists found\n", timeout.len, timeout.s);
		ADJUSTLEN(printlen,outbufend,replybuffer);
		return;
	} else {
		/* don't lock anything while writing the value - only this command modifies its value */
		rwlock_lock_w(&m->conf.config_lock);
		*conf_timeout = timeout_num;
		rwlock_unlock_w(&m->conf.config_lock);
		printlen = snprintf (replybuffer,(outbufend-replybuffer), "Success setting timeout to %lu\n", timeout_num);
		ADJUSTLEN(printlen,outbufend,replybuffer);
	}
}

static void cli_incoming_list(char* buffer, int len, struct callmaster* m, char* replybuffer, const char* outbufend) {
   int printlen=0;

   static const char* LIST_NUMSESSIONS = "numsessions";
   static const char* LIST_SESSIONS = "sessions";
   static const char* LIST_TOTALS = "totals";
   static const char* LIST_MAX_OPEN_FILES = "maxopenfiles";
   static const char* LIST_MAX_SESSIONS = "maxsessions";
   static const char* LIST_TIMEOUT = "timeout";

   if (len<=1) {
       printlen = snprintf(replybuffer, outbufend-replybuffer, "%s\n", "More parameters required.");
       ADJUSTLEN(printlen,outbufend,replybuffer);
       return;
   }
   ++buffer; --len; // one space

   if (len>=strlen(LIST_NUMSESSIONS) && strncmp(buffer,LIST_NUMSESSIONS,strlen(LIST_NUMSESSIONS)) == 0) {
       rwlock_lock_r(&m->hashlock);
       printlen = snprintf(replybuffer, outbufend-replybuffer, "Current sessions own: "UINT64F"\n", g_hash_table_size(m->callhash) - atomic64_get(&m->stats.foreign_sessions));
       ADJUSTLEN(printlen,outbufend,replybuffer);
       printlen = snprintf(replybuffer, outbufend-replybuffer, "Current sessions foreign: "UINT64F"\n", atomic64_get(&m->stats.foreign_sessions));
       ADJUSTLEN(printlen,outbufend,replybuffer);
       printlen = snprintf(replybuffer, outbufend-replybuffer, "Current sessions total: %i\n", g_hash_table_size(m->callhash));
       ADJUSTLEN(printlen,outbufend,replybuffer);
       rwlock_unlock_r(&m->hashlock);
   } else if (len>=strlen(LIST_SESSIONS) && strncmp(buffer,LIST_SESSIONS,strlen(LIST_SESSIONS)) == 0) {
       cli_incoming_list_sessions(buffer+strlen(LIST_SESSIONS), len-strlen(LIST_SESSIONS), m, replybuffer, outbufend);
   } else if (len>=strlen(LIST_TOTALS) && strncmp(buffer,LIST_TOTALS,strlen(LIST_TOTALS)) == 0) {
       cli_incoming_list_totals(buffer+strlen(LIST_TOTALS), len-strlen(LIST_TOTALS), m, replybuffer, outbufend);
   } else if (len>=strlen(LIST_MAX_SESSIONS) && strncmp(buffer,LIST_MAX_SESSIONS,strlen(LIST_MAX_SESSIONS)) == 0) {
       cli_incoming_list_maxsessions(buffer+strlen(LIST_MAX_SESSIONS), len-strlen(LIST_MAX_SESSIONS), m, replybuffer, outbufend);
   } else if (len>=strlen(LIST_MAX_OPEN_FILES) && strncmp(buffer,LIST_MAX_OPEN_FILES,strlen(LIST_MAX_OPEN_FILES)) == 0) {
       cli_incoming_list_maxopenfiles(buffer+strlen(LIST_MAX_OPEN_FILES), len-strlen(LIST_MAX_OPEN_FILES), m, replybuffer, outbufend);
   } else if (len>=strlen(LIST_TIMEOUT) && strncmp(buffer,LIST_TIMEOUT,strlen(LIST_TIMEOUT)) == 0) {
       cli_incoming_list_timeout(buffer+strlen(LIST_TIMEOUT), len-strlen(LIST_TIMEOUT), m, replybuffer, outbufend);
   } else {
       printlen = snprintf(replybuffer, outbufend-replybuffer, "%s:%s\n", "Unknown 'list' command", buffer);
       ADJUSTLEN(printlen,outbufend,replybuffer);
   }
}

static void cli_incoming_set(char* buffer, int len, struct callmaster* m, char* replybuffer, const char* outbufend) {
	int printlen=0;

	static const char* SET_MAX_OPEN_FILES = "maxopenfiles";
	static const char* SET_MAX_SESSIONS = "maxsessions";
	static const char* SET_TIMEOUT = "timeout";
	static const char* SET_SILENT_TIMEOUT = "silenttimeout";
	static const char* SET_FINAL_TIMEOUT = "finaltimeout";

	if (len<=1) {
		printlen = snprintf(replybuffer, outbufend-replybuffer, "%s\n", "More parameters required.");
		ADJUSTLEN(printlen,outbufend,replybuffer);
		return;
	}
	++buffer; --len; // one space

	if (len>=strlen(SET_MAX_OPEN_FILES) && strncmp(buffer,SET_MAX_OPEN_FILES,strlen(SET_MAX_OPEN_FILES)) == 0) {
		cli_incoming_set_maxopenfiles(buffer+strlen(SET_MAX_OPEN_FILES), len-strlen(SET_MAX_OPEN_FILES), m, replybuffer, outbufend);
	} else if (len>=strlen(SET_MAX_SESSIONS) && strncmp(buffer,SET_MAX_SESSIONS,strlen(SET_MAX_SESSIONS)) == 0) {
		cli_incoming_set_maxsessions(buffer+strlen(SET_MAX_SESSIONS), len-strlen(SET_MAX_SESSIONS), m, replybuffer, outbufend);
	} else if (len>=strlen(SET_TIMEOUT) && strncmp(buffer,SET_TIMEOUT,strlen(SET_TIMEOUT)) == 0) {
		cli_incoming_set_timeout(buffer+strlen(SET_TIMEOUT), len-strlen(SET_TIMEOUT), m, replybuffer, outbufend, &m->conf.timeout);
	} else if (len>=strlen(SET_SILENT_TIMEOUT) && strncmp(buffer,SET_SILENT_TIMEOUT,strlen(SET_SILENT_TIMEOUT)) == 0) {
		cli_incoming_set_timeout(buffer+strlen(SET_SILENT_TIMEOUT), len-strlen(SET_SILENT_TIMEOUT), m, replybuffer, outbufend, &m->conf.silent_timeout);
	} else if (len>=strlen(SET_FINAL_TIMEOUT) && strncmp(buffer,SET_FINAL_TIMEOUT,strlen(SET_FINAL_TIMEOUT)) == 0) {
		cli_incoming_set_timeout(buffer+strlen(SET_FINAL_TIMEOUT), len-strlen(SET_FINAL_TIMEOUT), m, replybuffer, outbufend, &m->conf.final_timeout);
	} else {
		printlen = snprintf(replybuffer, outbufend-replybuffer, "%s:%s\n", "Unknown 'set' command", buffer);
		ADJUSTLEN(printlen,outbufend,replybuffer);
	}
}

static void cli_incoming_terminate(char* buffer, int len, struct callmaster* m, char* replybuffer, const char* outbufend) {
   str termparam;
   struct call* c=0;
   int printlen=0;
   struct call_monologue *ml;
   GList *i;

   if (len<=1) {
       printlen = snprintf(replybuffer, outbufend-replybuffer, "%s\n", "More parameters required.");
       ADJUSTLEN(printlen,outbufend,replybuffer);
       return;
   }
   ++buffer; --len; // one space
   str_init_len(&termparam,buffer,len);

	// --- terminate all calls
	if (!str_memcmp(&termparam,"all")) {
		// destroy own calls
		destroy_all_own_calls(m);

		// destroy foreign calls
		destroy_all_foreign_calls(m);

		// update cli
		ilog(LOG_INFO,"All calls terminated by operator.");
		printlen = snprintf(replybuffer, outbufend-replybuffer, "%s\n", "All calls terminated by operator.");
		ADJUSTLEN(printlen,outbufend,replybuffer);

		return;

	// --- terminate own calls
	} else if (!str_memcmp(&termparam,"own")) {
		// destroy own calls
		destroy_all_own_calls(m);

		// update cli
		ilog(LOG_INFO,"All own calls terminated by operator.");
		printlen = snprintf(replybuffer, outbufend-replybuffer, "%s\n", "All own calls terminated by operator.");
		ADJUSTLEN(printlen,outbufend,replybuffer);

		return;

	// --- terminate foreign calls
	} else if (!str_memcmp(&termparam,"foreign")) {
		// destroy foreign calls
		destroy_all_foreign_calls(m);

		// update cli
		ilog(LOG_INFO,"All foreign calls terminated by operator.");
		printlen = snprintf(replybuffer, outbufend-replybuffer, "%s\n", "All foreign calls terminated by operator.");
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
	   for (i = c->monologues.head; i; i = i->next) {
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

static void cli_incoming_ksadd(char* buffer, int len, struct callmaster* m, char* replybuffer, const char* outbufend) {
	int printlen=0;
	unsigned long uint_keyspace_db;
	str str_keyspace_db;
	char *endptr;

	if (len<=1) {
		printlen = snprintf(replybuffer, outbufend-replybuffer, "%s\n", "More parameters required.");
		ADJUSTLEN(printlen,outbufend,replybuffer);
		return;
	}
	++buffer; --len; // one space

	str_keyspace_db.s = buffer;
	str_keyspace_db.len = len;
	uint_keyspace_db = strtoul(str_keyspace_db.s, &endptr, 10);

	if ((errno == ERANGE && (uint_keyspace_db == ULONG_MAX)) || (errno != 0 && uint_keyspace_db == 0)) {
		printlen = snprintf(replybuffer, outbufend-replybuffer, "Fail adding keyspace %.*s to redis notifications; errono=%d\n", str_keyspace_db.len, str_keyspace_db.s, errno);
	} else if (endptr == str_keyspace_db.s) {
		printlen = snprintf(replybuffer, outbufend-replybuffer, "Fail adding keyspace %.*s to redis notifications; no digists found\n", str_keyspace_db.len, str_keyspace_db.s);
	} else {
		rwlock_lock_w(&m->conf.config_lock);
		if (!g_queue_find(m->conf.redis_subscribed_keyspaces, GUINT_TO_POINTER(uint_keyspace_db))) {
			g_queue_push_tail(m->conf.redis_subscribed_keyspaces, GUINT_TO_POINTER(uint_keyspace_db));
			redis_notify_subscribe_action(m, SUBSCRIBE_KEYSPACE, uint_keyspace_db);
			printlen = snprintf(replybuffer, outbufend-replybuffer, "Success adding keyspace %lu to redis notifications.\n", uint_keyspace_db);
		} else {
			printlen = snprintf(replybuffer, outbufend-replybuffer, "Keyspace %lu is already among redis notifications.\n", uint_keyspace_db);
		}
		rwlock_unlock_w(&m->conf.config_lock);
	}
	ADJUSTLEN(printlen,outbufend,replybuffer);
}

static void cli_incoming_ksrm(char* buffer, int len, struct callmaster* m, char* replybuffer, const char* outbufend) {
	int printlen = 0;
	GList *l; 
	unsigned long uint_keyspace_db;
	str str_keyspace_db;
	char *endptr;

	if (len <= 1) {
		printlen = snprintf(replybuffer, outbufend-replybuffer, "%s\n", "More parameters required.");
		ADJUSTLEN(printlen,outbufend,replybuffer);
		return;
	}
	++buffer; --len; // one space

	str_keyspace_db.s = buffer;
	str_keyspace_db.len = len;
	uint_keyspace_db = strtoul(str_keyspace_db.s, &endptr, 10);

	rwlock_lock_w(&m->conf.config_lock);
	if ((errno == ERANGE && (uint_keyspace_db == ULONG_MAX)) || (errno != 0 && uint_keyspace_db == 0)) {
		printlen = snprintf(replybuffer, outbufend-replybuffer, "Fail removing keyspace %.*s to redis notifications; errono=%d\n", str_keyspace_db.len, str_keyspace_db.s, errno);
        } else if (endptr == str_keyspace_db.s) {
                printlen = snprintf(replybuffer, outbufend-replybuffer, "Fail removing keyspace %.*s to redis notifications; no digists found\n", str_keyspace_db.len, str_keyspace_db.s);
	} else if ((l = g_queue_find(m->conf.redis_subscribed_keyspaces, GUINT_TO_POINTER(uint_keyspace_db)))) {
		// remove this keyspace
		redis_notify_subscribe_action(m, UNSUBSCRIBE_KEYSPACE, uint_keyspace_db);
		g_queue_remove(m->conf.redis_subscribed_keyspaces, l->data);
		printlen = snprintf(replybuffer, outbufend-replybuffer, "Successfully unsubscribed from keyspace %lu.\n", uint_keyspace_db);

		// destroy foreign calls for this keyspace
		destroy_keyspace_foreign_calls(m, uint_keyspace_db);

		// update cli
		printlen = snprintf(replybuffer, outbufend-replybuffer, "Successfully removed all foreign calls for keyspace %lu.\n", uint_keyspace_db);
	} else {
		printlen = snprintf(replybuffer, outbufend-replybuffer, "Keyspace %lu is not among redis notifications.\n", uint_keyspace_db);
	}
	rwlock_unlock_w(&m->conf.config_lock);

	ADJUSTLEN(printlen,outbufend,replybuffer);
}

static void cli_incoming_kslist(char* buffer, int len, struct callmaster* m, char* replybuffer, const char* outbufend) {
	int printlen=0;
	GList *l;

	printlen = snprintf(replybuffer,(outbufend-replybuffer), "\nSubscribed-on keyspaces:\n");
	ADJUSTLEN(printlen,outbufend,replybuffer); 
    
	rwlock_lock_r(&m->conf.config_lock);
	for (l = m->conf.redis_subscribed_keyspaces->head; l; l = l->next) {
		printlen = snprintf(replybuffer,(outbufend-replybuffer), "%u ", GPOINTER_TO_UINT(l->data));
		ADJUSTLEN(printlen,outbufend,replybuffer);
	}
	rwlock_unlock_r(&m->conf.config_lock);

	printlen = snprintf(replybuffer, outbufend-replybuffer, "\n");
	ADJUSTLEN(printlen,outbufend,replybuffer);
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
   char inbuf[MAXINPUT+1];
   int inlen = 0, readbytes = 0;
   int rc=0;

   memset(replybuffer, 0, BUFLENGTH);

   mutex_lock(&cli->lock);
next:
   sinl = sizeof(sin);
   nfd = accept(fd, (struct sockaddr *) &sin, &sinl);
   if (nfd == -1) {
       if (errno == EAGAIN || errno == EWOULDBLOCK) {
           goto cleanup2;
       }
       ilog(LOG_INFO, "Accept error:%s", strerror(errno));
       goto next;
   }

   ilog(LOG_INFO, "New cli connection from " DF, DP(sin));

   do {
       readbytes = read(nfd, inbuf+inlen, MAXINPUT-inlen);
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
   static const char* SET = "set";
   static const char* KSADD = "ksadd";
   static const char* KSRM = "ksrm";
   static const char* KSLIST = "kslist";

   if (strncmp(inbuf,LIST,strlen(LIST)) == 0) {
       cli_incoming_list(inbuf+strlen(LIST), inlen-strlen(LIST), cli->callmaster, outbuf, outbufend);
   } else  if (strncmp(inbuf,TERMINATE,strlen(TERMINATE)) == 0) {
       cli_incoming_terminate(inbuf+strlen(TERMINATE), inlen-strlen(TERMINATE), cli->callmaster, outbuf, outbufend);
   } else  if (strncmp(inbuf,SET,strlen(SET)) == 0) {
       cli_incoming_set(inbuf+strlen(SET), inlen-strlen(SET), cli->callmaster, outbuf, outbufend);
   } else  if (strncmp(inbuf,KSADD,strlen(KSADD)) == 0) {
       cli_incoming_ksadd(inbuf+strlen(KSADD), inlen-strlen(KSADD), cli->callmaster, outbuf, outbufend);
   } else  if (strncmp(inbuf,KSRM,strlen(KSRM)) == 0) {
       cli_incoming_ksrm(inbuf+strlen(KSRM), inlen-strlen(KSRM), cli->callmaster, outbuf, outbufend);
   } else  if (strncmp(inbuf,KSLIST,strlen(KSLIST)) == 0) {
       cli_incoming_kslist(inbuf+strlen(KSLIST), inlen-strlen(KSLIST), cli->callmaster, outbuf, outbufend);
   } else {
       sprintf(replybuffer, "%s:%s\n", "Unknown or incomplete command:", inbuf);
   }

   do {
       rc += write( nfd, (char *)&replybuffer, strlen(replybuffer) );
   } while (rc < strlen(replybuffer));

cleanup:
   close(nfd);
   /* in case multiple incoming connections exist, read all of them */
   goto next;
cleanup2:
   mutex_unlock(&cli->lock);
   log_info_clear();
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
