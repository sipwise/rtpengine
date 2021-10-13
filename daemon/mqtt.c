#ifdef HAVE_MQTT

#include "mqtt.h"
#include <mosquitto.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <glib.h>
#include <glib-object.h>
#include <json-glib/json-glib.h>
#include "main.h"
#include "log.h"
#include "log_funcs.h"
#include "call.h"
#include "ssrc.h"
#include "rtplib.h"



static struct mosquitto *mosq;
static bool is_connected = false;


int mqtt_init(void) {
	mosq = mosquitto_new(rtpe_config.mqtt_id, true, NULL);
	if (!mosq) {
		ilog(LOG_ERR, "Failed to create mosquitto client instance: %s", strerror(errno));
		return -1;
	}
	return 0;
}


static int mqtt_connect(void) {
	ilog(LOG_DEBUG, "Connecting to mosquitto...");

	mosquitto_disconnect(mosq);

	int ret = mosquitto_reinitialise(mosq, rtpe_config.mqtt_id, true, NULL);
	if (ret) {
		ilog(LOG_ERR, "Failed to initialise mosquitto client instance: %s", mosquitto_strerror(ret));
		return -1;
	}

	mosquitto_threaded_set(mosq, true);

	if (rtpe_config.mqtt_user) {
		int ret = mosquitto_username_pw_set(mosq, rtpe_config.mqtt_user, rtpe_config.mqtt_pass);
		if (ret != MOSQ_ERR_SUCCESS) {
			ilog(LOG_ERR, "Failed to set mosquitto user/pass auth: %s", mosquitto_strerror(errno));
			return -1;
		}
	}

	if (rtpe_config.mqtt_cafile || rtpe_config.mqtt_capath) {
		int ret = mosquitto_tls_set(mosq, rtpe_config.mqtt_cafile, rtpe_config.mqtt_capath,
				rtpe_config.mqtt_certfile, rtpe_config.mqtt_keyfile, NULL);
		if (ret != MOSQ_ERR_SUCCESS) {
			ilog(LOG_ERR, "Failed to set mosquitto TLS options: %s", mosquitto_strerror(errno));
			return -1;
		}
	}

	ret = mosquitto_connect(mosq, rtpe_config.mqtt_host, rtpe_config.mqtt_port,
			rtpe_config.mqtt_keepalive);
	if (ret != MOSQ_ERR_SUCCESS) {
		ilog(LOG_ERR, "Failed to connect to mosquitto broker: %s", mosquitto_strerror(ret));
		return -1;
	}

	ilog(LOG_DEBUG, "Successfully connected to mosquitto");

	return 0;
}


void mqtt_loop(void *dummy) {
	while (!rtpe_shutdown) {
		while (!is_connected && !rtpe_shutdown) {
			if (!mqtt_connect()) {
				is_connected = true;
				break;
			}
			usleep(1000000);
		}

		unsigned int errors = 0;
		while (!rtpe_shutdown) {
			int ret = mosquitto_loop(mosq, 100, 1);
			if (ret == MOSQ_ERR_SUCCESS) {
				errors = 0;
				continue;
			}
			if (ret == MOSQ_ERR_ERRNO)
				ilog(LOG_ERR, "Error from mosquitto: %s", strerror(errno));
			else
				ilog(LOG_ERR, "Error from mosquitto: %s", mosquitto_strerror(ret));
			errors++;
			if (errors >= 5) {
				ilog(LOG_WARN, "Reconnecting to mosquitto");
				break;
			}
		}

		mosquitto_disconnect(mosq);
		is_connected = false;
	}

	mosquitto_destroy(mosq);
	mosq = NULL;
}


int mqtt_publish_scope(void) {
	if (!mosq)
		return MPS_NONE;
	return rtpe_config.mqtt_publish_scope;
}


void mqtt_publish(char *s) {
	ilog(LOG_DEBUG, "Publishing to mosquitto: %s%s%s", FMT_M(s));

	int ret = mosquitto_publish(mosq, NULL, rtpe_config.mqtt_publish_topic, strlen(s), s,
			rtpe_config.mqtt_publish_qos,
			false);
	if (ret != MOSQ_ERR_SUCCESS)
		ilog(LOG_WARN | LOG_FLAG_LIMIT, "Error publishing message to mosquitto: %s",
				mosquitto_strerror(ret));
	g_free(s);
}


static void mqtt_call_stats(struct call *call, JsonBuilder *json) {
	json_builder_set_member_name(json, "call_id");
	json_builder_add_string_value(json, call->callid.s);
}


static void mqtt_monologue_stats(struct call_monologue *ml, JsonBuilder *json) {
	json_builder_set_member_name(json, "tag");
	json_builder_add_string_value(json, ml->tag.s);

	if (ml->label.len) {
		json_builder_set_member_name(json, "label");
		json_builder_add_string_value(json, ml->label.s);
	}
}


static void mqtt_ssrc_stats(struct ssrc_ctx *ssrc, JsonBuilder *json, struct call_media *media) {
	struct ssrc_entry_call *sc = ssrc->parent;

	json_builder_set_member_name(json, "SSRC");
	json_builder_add_int_value(json, sc->h.ssrc);

	unsigned char prim_pt = 255;
	mutex_lock(&ssrc->tracker.lock);
	if (ssrc->tracker.most_len > 0)
		prim_pt = ssrc->tracker.most[0];
	mutex_unlock(&ssrc->tracker.lock);

	unsigned int clockrate = 0;
	//struct codec_handler *h = codec_handler_get(ps->media, prim_pt);
	struct rtp_payload_type *pt = g_hash_table_lookup(media->codecs.codecs, GUINT_TO_POINTER(prim_pt));
	if (pt) {
		json_builder_set_member_name(json, "codec");
		json_builder_add_string_value(json, pt->encoding.s);

		json_builder_set_member_name(json, "clock_rate");
		json_builder_add_int_value(json, pt->clock_rate);
		clockrate = pt->clock_rate;

		if (pt->encoding_parameters.s) {
			json_builder_set_member_name(json, "codec_params");
			json_builder_add_string_value(json, pt->encoding_parameters.s);
		}

		if (pt->format_parameters.s) {
			json_builder_set_member_name(json, "codec_format");
			json_builder_add_string_value(json, pt->format_parameters.s);
		}
	}

	json_builder_set_member_name(json, "metrics");
	json_builder_begin_object(json);

	// copy out values
	uint64_t packets, octets, packets_lost, duplicates;
	packets = atomic64_get(&ssrc->packets);
	octets = atomic64_get(&ssrc->octets);
	packets_lost = sc->packets_lost;
	duplicates = sc->duplicates;

	// process per-second stats
	uint64_t cur_ts = ssrc_timeval_to_ts(&rtpe_now);
	uint64_t last_sample, sample_packets, sample_octets, sample_packets_lost, sample_duplicates;

	// sample values
	last_sample = atomic64_get_set(&ssrc->last_sample, cur_ts);
	sample_packets = atomic64_get_set(&ssrc->sample_packets, packets);
	sample_octets = atomic64_get_set(&ssrc->sample_octets, octets);
	sample_packets_lost = atomic64_get_set(&ssrc->sample_packets_lost, packets_lost);
	sample_duplicates = atomic64_get_set(&ssrc->sample_duplicates, duplicates);

	json_builder_set_member_name(json, "packets");
	json_builder_add_int_value(json, packets);

	json_builder_set_member_name(json, "bytes");
	json_builder_add_int_value(json, octets);

	json_builder_set_member_name(json, "lost");
	json_builder_add_int_value(json, packets_lost);

	json_builder_set_member_name(json, "duplicates");
	json_builder_add_int_value(json, duplicates);

	if (last_sample && last_sample != cur_ts) {
		// calc sample rates with primitive math
		struct timeval last_sample_ts = ssrc_ts_to_timeval(last_sample);
		uint64_t usecs_diff = timeval_diff(&rtpe_now, &last_sample_ts);

		// adjust samples
		packets -= sample_packets;
		octets -= sample_octets;
		packets_lost -= sample_packets_lost;
		duplicates -= sample_duplicates;

		json_builder_set_member_name(json, "packets_per_second");
		json_builder_add_double_value(json, (double) packets * 1000000.0 / (double) usecs_diff);

		json_builder_set_member_name(json, "bytes_per_second");
		json_builder_add_double_value(json, (double) octets * 1000000.0 / (double) usecs_diff);

		json_builder_set_member_name(json, "lost_per_second");
		json_builder_add_double_value(json, (double) packets_lost * 1000000.0 / (double) usecs_diff);

		json_builder_set_member_name(json, "duplicates_per_second");
		json_builder_add_double_value(json, (double) duplicates * 1000000.0 / (double) usecs_diff);
	}

	mutex_lock(&sc->h.lock);
	uint32_t jitter = sc->jitter;
	int64_t mos = -1, rtt = -1, rtt_leg = -1;
	if (sc->stats_blocks.length) {
		struct ssrc_stats_block *sb = sc->stats_blocks.tail->data;
		mos = sb->mos;
		rtt = sb->rtt;
		rtt_leg = sb->rtt_leg;
	}
	mutex_unlock(&sc->h.lock);

	if (clockrate) {
		json_builder_set_member_name(json, "jitter");
		json_builder_add_double_value(json, (double) jitter * 1000.0 / (double) clockrate);
	}

	if (mos != -1 && mos != 0) {
		json_builder_set_member_name(json, "MOS");
		json_builder_add_double_value(json, (double) mos / 10.0);
	}
	if (rtt != -1) {
		json_builder_set_member_name(json, "RTT");
		json_builder_add_double_value(json, (double) rtt / 1000.0);
	}
	if (rtt_leg != -1) {
		json_builder_set_member_name(json, "RTT_leg");
		json_builder_add_double_value(json, (double) rtt_leg / 1000.0);
	}

	json_builder_end_object(json);
}


static void mqtt_stream_stats(struct packet_stream *ps, JsonBuilder *json) {
	mutex_lock(&ps->in_lock);

	struct stream_fd *sfd = ps->selected_sfd;
	if (sfd) {
		json_builder_set_member_name(json, "address");
		json_builder_add_string_value(json, sockaddr_print_buf(&sfd->socket.local.address));

		json_builder_set_member_name(json, "port");
		json_builder_add_int_value(json, sfd->socket.local.port);
	}

	if (ps->ssrc_in[0]) {
		json_builder_set_member_name(json, "ingress");
		json_builder_begin_object(json);
		mqtt_ssrc_stats(ps->ssrc_in[0], json, ps->media);
		json_builder_end_object(json);
	}

	mutex_unlock(&ps->in_lock);

	mutex_lock(&ps->out_lock);

	if (ps->ssrc_out[0]) {
		json_builder_set_member_name(json, "egress");
		json_builder_begin_object(json);
		mqtt_ssrc_stats(ps->ssrc_out[0], json, ps->media);
		json_builder_end_object(json);
	}

	mutex_unlock(&ps->out_lock);
}


static void mqtt_media_stats(struct call_media *media, JsonBuilder *json) {
	media_update_stats(media);

	json_builder_set_member_name(json, "media_index");
	json_builder_add_int_value(json, media->index);

	json_builder_set_member_name(json, "type");
	json_builder_add_string_value(json, media->type.s);

	json_builder_set_member_name(json, "interface");
	json_builder_add_string_value(json, media->logical_intf->name.s);

	if (media->protocol) {
		json_builder_set_member_name(json, "protocol");
		json_builder_add_string_value(json, media->protocol->name);
	}

	json_builder_set_member_name(json, "status");
	if (MEDIA_ISSET(media, SEND)) {
		if (MEDIA_ISSET(media, RECV))
			json_builder_add_string_value(json, "sendrecv");
		else
			json_builder_add_string_value(json, "sendonly");
	}
	else {
		if (MEDIA_ISSET(media, RECV))
			json_builder_add_string_value(json, "recvonly");
		else
			json_builder_add_string_value(json, "inactive");
	}

	struct packet_stream *ps = media->streams.head ? media->streams.head->data : NULL;
	if (ps)
		mqtt_stream_stats(ps, json);
}


static void mqtt_full_call(struct call *call, JsonBuilder *json) {
	rwlock_lock_r(&call->master_lock);

	log_info_call(call);

	mqtt_call_stats(call, json);

	json_builder_set_member_name(json, "legs");
	json_builder_begin_array(json);

	for (GList *l = call->monologues.head; l; l = l->next) {
		struct call_monologue *ml = l->data;

		json_builder_begin_object(json);

		mqtt_monologue_stats(ml, json);

		json_builder_set_member_name(json, "medias");
		json_builder_begin_array(json);

		for (GList *k = ml->medias.head; k; k = k->next) {
			struct call_media *media = k->data;
			json_builder_begin_object(json);
			mqtt_media_stats(media, json);
			json_builder_end_object(json);
		}

		json_builder_end_array(json);
		json_builder_end_object(json);
	}

	json_builder_end_array(json);

	rwlock_unlock_r(&call->master_lock);
}


static void mqtt_global_stats(JsonBuilder *json) {
	AUTO_CLEANUP_INIT(GQueue *metrics, statistics_free_metrics, statistics_gather_metrics());

	for (GList *l = metrics->head; l; l = l->next) {
		struct stats_metric *m = l->data;
		if (!m->label)
			continue;

		if (m->is_bracket && l == metrics->head) // skip initial {
			continue;
		if (m->is_bracket && l == metrics->tail) // skip final }
			continue;


		if (m->value_short) {
			json_builder_set_member_name(json, m->label);
			if (m->is_int)
				json_builder_add_int_value(json, m->int_value);
			else
				json_builder_add_string_value(json, m->value_short);
		}
		else if (m->is_bracket) {
			if (m->is_close_bracket) {
				if (m->is_brace)
					json_builder_end_object(json);
				else
					json_builder_end_array(json);
			}
			else {
				if (m->is_brace)
					json_builder_begin_object(json);
				else
					json_builder_begin_array(json);
			}
		}
		else
			json_builder_set_member_name(json, m->label);
	}
}


void mqtt_timer_run(struct call *call, struct call_media *media) {
	JsonBuilder *json = json_builder_new();

	json_builder_begin_object(json);

	json_builder_set_member_name(json, "timestamp");
	json_builder_add_double_value(json, (double) rtpe_now.tv_sec + (double) rtpe_now.tv_usec / 1000000.0);

	if (!call) {
		mqtt_global_stats(json);

		if (mqtt_publish_scope() == MPS_GLOBAL) {
			json_builder_set_member_name(json, "calls");

			json_builder_begin_array(json);

			ITERATE_CALL_LIST_START(CALL_ITERATOR_MQTT, call);
				json_builder_begin_object(json);
				mqtt_full_call(call, json);
				json_builder_end_object(json);
			ITERATE_CALL_LIST_NEXT_END(call);

			json_builder_end_array(json);
		}
	}
	else if (!media)
		mqtt_full_call(call, json);
	else {
		rwlock_lock_r(&call->master_lock);

		log_info_call(call);

		mqtt_call_stats(call, json);
		mqtt_monologue_stats(media->monologue, json);
		mqtt_media_stats(media, json);

		rwlock_unlock_r(&call->master_lock);
	}

	json_builder_end_object(json);

	JsonGenerator *gen = json_generator_new();
	JsonNode *root = json_builder_get_root(json);
	json_generator_set_root(gen, root);
	char *result = json_generator_to_data(gen, NULL);

	mqtt_publish(result);

	json_node_free(root);
	g_object_unref(gen);
	g_object_unref(json);
}



#endif
