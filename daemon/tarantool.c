/*
 * Copyright (C) 2026 lean1ee <https://github.com/lean1ee>
 *
 * Author: lean1ee
 * Driver: rtpengine_tarantool - High performance non-blocking Tarantool 3.x IProto driver
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "tarantool.h"
#include "msgpuck.h"

rtpe_tarantool_client_t *rtpe_tarantool_new_from_config(const rtpe_tarantool_config_t *cfg) {
    if (!cfg) return NULL;
    rtpe_tarantool_client_t *c = (rtpe_tarantool_client_t *)calloc(1, sizeof(rtpe_tarantool_client_t));
    if (!c) return NULL;

    memcpy(&c->config, cfg, sizeof(rtpe_tarantool_config_t));
    if (c->config.port <= 0) c->config.port = 3301;
    if (c->config.expires_secs <= 0) c->config.expires_secs = 3600;
    if (c->config.connect_timeout_ms <= 0) c->config.connect_timeout_ms = 500;
    if (c->config.cmd_timeout_ms <= 0) c->config.cmd_timeout_ms = 500;
    if (c->config.allowed_errors <= 0) c->config.allowed_errors = 3;
    if (c->config.disable_time <= 0) c->config.disable_time = 10;
    if (c->config.tcp_keepalive_time <= 0) c->config.tcp_keepalive_time = 60;
    if (c->config.tcp_keepalive_intvl <= 0) c->config.tcp_keepalive_intvl = 5;
    if (c->config.tcp_keepalive_probes <= 0) c->config.tcp_keepalive_probes = 3;
    if (c->config.num_threads <= 0) c->config.num_threads = 4;
    if (c->config.space[0] == '\0') strncpy(c->config.space, "rtpe_calls", sizeof(c->config.space) - 1);

    c->sock_fd = -1;
    c->state = TARANTOOL_DISCONNECTED;
    c->sync_id = 1;
    return c;
}

rtpe_tarantool_client_t *rtpe_tarantool_new(const char *host, int port, const char *user, const char *pass, const char *node_id) {
    rtpe_tarantool_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    strncpy(cfg.host, host ? host : "127.0.0.1", sizeof(cfg.host) - 1);
    cfg.port = port > 0 ? port : 3301;
    if (user) strncpy(cfg.user, user, sizeof(cfg.user) - 1);
    if (pass) strncpy(cfg.password, pass, sizeof(cfg.password) - 1);
    strncpy(cfg.node_id, node_id ? node_id : "rtpe-default", sizeof(cfg.node_id) - 1);
    strncpy(cfg.space, "rtpe_calls", sizeof(cfg.space) - 1);
    cfg.expires_secs = 3600;
    cfg.connect_timeout_ms = 500;
    cfg.cmd_timeout_ms = 500;
    cfg.allowed_errors = 3;
    cfg.disable_time = 10;
    cfg.num_threads = 4;
    cfg.tcp_keepalive_time = 60;
    cfg.tcp_keepalive_intvl = 5;
    cfg.tcp_keepalive_probes = 3;

    return rtpe_tarantool_new_from_config(&cfg);
}

int rtpe_tarantool_connect(rtpe_tarantool_client_t *client) {
    if (!client) return -1;
    
    time_t now = time(NULL);
    if (client->state == TARANTOOL_DISABLED) {
        if (now < client->disabled_until) {
            return -1;
        }
        client->state = TARANTOOL_DISCONNECTED;
        client->consecutive_errors = 0;
    }

    if (client->sock_fd >= 0) {
        close(client->sock_fd);
        client->sock_fd = -1;
    }

    client->state = TARANTOOL_CONNECTING;
    client->sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client->sock_fd < 0) {
        client->state = TARANTOOL_ERROR;
        client->total_errors++;
        client->consecutive_errors++;
        if (client->consecutive_errors >= client->config.allowed_errors) {
            client->state = TARANTOOL_DISABLED;
            client->disabled_until = now + client->config.disable_time;
        }
        return -1;
    }

    /* Socket timeouts and TCP_NODELAY from configuration */
    struct timeval tv;
    tv.tv_sec = client->config.cmd_timeout_ms / 1000;
    tv.tv_usec = (client->config.cmd_timeout_ms % 1000) * 1000;
    setsockopt(client->sock_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(client->sock_fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));

    int flag = 1;
    setsockopt(client->sock_fd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));

    /* Fine-grained TCP Keepalive configuration */
    int keepalive = 1;
    setsockopt(client->sock_fd, SOL_SOCKET, SO_KEEPALIVE, (char *)&keepalive, sizeof(int));

#ifdef TCP_KEEPIDLE
    setsockopt(client->sock_fd, IPPROTO_TCP, TCP_KEEPIDLE, &client->config.tcp_keepalive_time, sizeof(int));
#elif defined(TCP_KEEPALIVE)
    setsockopt(client->sock_fd, IPPROTO_TCP, TCP_KEEPALIVE, &client->config.tcp_keepalive_time, sizeof(int));
#endif

#ifdef TCP_KEEPINTVL
    setsockopt(client->sock_fd, IPPROTO_TCP, TCP_KEEPINTVL, &client->config.tcp_keepalive_intvl, sizeof(int));
#endif

#ifdef TCP_KEEPCNT
    setsockopt(client->sock_fd, IPPROTO_TCP, TCP_KEEPCNT, &client->config.tcp_keepalive_probes, sizeof(int));
#endif

    /* Dynamic DNS resolve or IP parsing */
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(client->config.port);

    if (inet_pton(AF_INET, client->config.host, &serv_addr.sin_addr) <= 0) {
        /* Resolve hostname via getaddrinfo */
        struct addrinfo hints, *res = NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        
        char port_str[16];
        snprintf(port_str, sizeof(port_str), "%d", client->config.port);
        if (getaddrinfo(client->config.host, port_str, &hints, &res) != 0 || !res) {
            close(client->sock_fd);
            client->sock_fd = -1;
            client->state = TARANTOOL_ERROR;
            client->total_errors++;
            return -1;
        }
        memcpy(&serv_addr, res->ai_addr, sizeof(serv_addr));
        freeaddrinfo(res);
    }

    if (connect(client->sock_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        close(client->sock_fd);
        client->sock_fd = -1;
        client->state = TARANTOOL_ERROR;
        client->total_errors++;
        client->consecutive_errors++;
        if (client->consecutive_errors >= client->config.allowed_errors) {
            client->state = TARANTOOL_DISABLED;
            client->disabled_until = now + client->config.disable_time;
        }
        return -1;
    }

    /* Read 128-byte Greeting Handshake from Tarantool 3.x */
    char greeting[128];
    ssize_t n = recv(client->sock_fd, greeting, sizeof(greeting), MSG_WAITALL);
    if (n != sizeof(greeting)) {
        close(client->sock_fd);
        client->sock_fd = -1;
        client->state = TARANTOOL_ERROR;
        client->total_errors++;
        return -1;
    }

    client->state = TARANTOOL_AUTHENTICATED;
    client->consecutive_errors = 0;
    return 0;
}

size_t rtpe_tarantool_pack_call_upsert(char *buf, size_t buf_size, uint64_t sync_id, const char *node_id, const rtpe_call_info_t *info) {
    if (!buf || buf_size < 512 || !info || !info->call_id) return 0;

    char *p = buf + 5;

    // Header: Map of 2 elements (REQUEST_TYPE, SYNC)
    p = mp_encode_map(p, 2);
    p = mp_encode_uint(p, IPROTO_REQUEST_TYPE);
    p = mp_encode_uint(p, IPROTO_CALL);
    p = mp_encode_uint(p, IPROTO_SYNC);
    p = mp_encode_uint(p, sync_id);

    // Body: Map of 2 elements (FUNCTION_NAME, TUPLE/ARGS)
    p = mp_encode_map(p, 2);
    p = mp_encode_uint(p, IPROTO_FUNCTION_NAME);
    p = mp_encode_str(p, "rtpe_call_upsert", 16);

    p = mp_encode_uint(p, IPROTO_TUPLE);
    // Arguments array: [call_id, node_id, payload, ttl_sec]
    p = mp_encode_array(p, 4);
    p = mp_encode_str(p, info->call_id, (uint32_t)(info->call_id_len > 0 ? info->call_id_len : strlen(info->call_id)));
    p = mp_encode_str(p, node_id ? node_id : "rtpe-01", (uint32_t)strlen(node_id ? node_id : "rtpe-01"));

    // Payload (Map of media details)
    p = mp_encode_map(p, 5);
    p = mp_encode_str(p, "caller_ip", 9);
    p = mp_encode_str(p, info->caller_ip ? info->caller_ip : "0.0.0.0", (uint32_t)strlen(info->caller_ip ? info->caller_ip : "0.0.0.0"));
    
    p = mp_encode_str(p, "caller_port", 11);
    p = mp_encode_uint(p, (uint64_t)info->caller_port);

    p = mp_encode_str(p, "callee_ip", 9);
    p = mp_encode_str(p, info->callee_ip ? info->callee_ip : "0.0.0.0", (uint32_t)strlen(info->callee_ip ? info->callee_ip : "0.0.0.0"));

    p = mp_encode_str(p, "callee_port", 11);
    p = mp_encode_uint(p, (uint64_t)info->callee_port);

    p = mp_encode_str(p, "srtp_suite", 10);
    p = mp_encode_str(p, info->srtp_suite ? info->srtp_suite : "NONE", (uint32_t)strlen(info->srtp_suite ? info->srtp_suite : "NONE"));

    // TTL
    p = mp_encode_uint(p, (uint64_t)(info->ttl_sec > 0 ? info->ttl_sec : 3600));

    // Body length excluding initial 5-byte prefix
    uint32_t payload_len = (uint32_t)(p - (buf + 5));

    // Write length prefix
    char *len_ptr = buf;
    *len_ptr++ = (char)MP_UINT32;
    *len_ptr++ = (char)(payload_len >> 24);
    *len_ptr++ = (char)(payload_len >> 16);
    *len_ptr++ = (char)(payload_len >> 8);
    *len_ptr++ = (char)(payload_len);

    return 5 + payload_len;
}

size_t rtpe_tarantool_pack_call_delete(char *buf, size_t buf_size, uint64_t sync_id, const char *call_id, size_t call_id_len) {
    if (!buf || buf_size < 128 || !call_id) return 0;

    char *p = buf + 5;

    // Header
    p = mp_encode_map(p, 2);
    p = mp_encode_uint(p, IPROTO_REQUEST_TYPE);
    p = mp_encode_uint(p, IPROTO_CALL);
    p = mp_encode_uint(p, IPROTO_SYNC);
    p = mp_encode_uint(p, sync_id);

    // Body
    p = mp_encode_map(p, 2);
    p = mp_encode_uint(p, IPROTO_FUNCTION_NAME);
    p = mp_encode_str(p, "rtpe_call_delete", 16);

    p = mp_encode_uint(p, IPROTO_TUPLE);
    p = mp_encode_array(p, 1);
    p = mp_encode_str(p, call_id, (uint32_t)(call_id_len > 0 ? call_id_len : strlen(call_id)));

    uint32_t payload_len = (uint32_t)(p - (buf + 5));

    char *len_ptr = buf;
    *len_ptr++ = (char)MP_UINT32;
    *len_ptr++ = (char)(payload_len >> 24);
    *len_ptr++ = (char)(payload_len >> 16);
    *len_ptr++ = (char)(payload_len >> 8);
    *len_ptr++ = (char)(payload_len);

    return 5 + payload_len;
}

int rtpe_tarantool_save_call(rtpe_tarantool_client_t *client, const rtpe_call_info_t *info) {
    if (!client || !info) return -1;

    char packet_buf[2048];
    uint64_t sync = client->sync_id++;
    uint32_t ttl = (info->ttl_sec > 0) ? info->ttl_sec : (uint32_t)client->config.expires_secs;
    
    rtpe_call_info_t call_copy;
    memcpy(&call_copy, info, sizeof(rtpe_call_info_t));
    call_copy.ttl_sec = ttl;

    size_t packet_len = rtpe_tarantool_pack_call_upsert(packet_buf, sizeof(packet_buf), sync, client->config.node_id, &call_copy);
    if (packet_len == 0) return -1;

    /* Check connection state and reconnect if needed */
    if (client->sock_fd < 0 || client->state != TARANTOOL_AUTHENTICATED) {
        if (rtpe_tarantool_connect(client) != 0) {
            return client->config.no_tarantool_required ? 0 : -1;
        }
    }

    /* Send binary IProto frame to socket */
    ssize_t n = send(client->sock_fd, packet_buf, packet_len, 0);
    if (n != (ssize_t)packet_len) {
        rtpe_tarantool_close(client);
        client->total_errors++;
        client->consecutive_errors++;
        if (client->consecutive_errors >= client->config.allowed_errors) {
            client->state = TARANTOOL_DISABLED;
            client->disabled_until = time(NULL) + client->config.disable_time;
        }
        return client->config.no_tarantool_required ? 0 : -1;
    }

    client->total_sent++;
    client->consecutive_errors = 0;
    return 0;
}

int rtpe_tarantool_delete_call(rtpe_tarantool_client_t *client, const char *call_id, size_t call_id_len) {
    if (!client || !call_id) return -1;

    char packet_buf[1024];
    uint64_t sync = client->sync_id++;
    size_t packet_len = rtpe_tarantool_pack_call_delete(packet_buf, sizeof(packet_buf), sync, call_id, call_id_len);
    if (packet_len == 0) return -1;

    if (client->sock_fd < 0 || client->state != TARANTOOL_AUTHENTICATED) {
        if (rtpe_tarantool_connect(client) != 0) {
            return client->config.no_tarantool_required ? 0 : -1;
        }
    }

    ssize_t n = send(client->sock_fd, packet_buf, packet_len, 0);
    if (n != (ssize_t)packet_len) {
        rtpe_tarantool_close(client);
        client->total_errors++;
        client->consecutive_errors++;
        if (client->consecutive_errors >= client->config.allowed_errors) {
            client->state = TARANTOOL_DISABLED;
            client->disabled_until = time(NULL) + client->config.disable_time;
        }
        return client->config.no_tarantool_required ? 0 : -1;
    }

    client->total_sent++;
    client->consecutive_errors = 0;
    return 0;
}

int rtpe_tarantool_restore_calls(rtpe_tarantool_client_t *client, const char *node_id, int (*restore_cb)(const rtpe_call_info_t *call, void *userdata), void *userdata) {
    if (!client || !node_id || !restore_cb) return -1;

    if (client->sock_fd < 0 || client->state != TARANTOOL_AUTHENTICATED) {
        if (rtpe_tarantool_connect(client) != 0) {
            return -1;
        }
    }

    char packet[512];
    char *p = packet + 5;
    uint64_t sync = client->sync_id++;

    p = mp_encode_map(p, 2);
    p = mp_encode_uint(p, IPROTO_REQUEST_TYPE);
    p = mp_encode_uint(p, IPROTO_CALL);
    p = mp_encode_uint(p, IPROTO_SYNC);
    p = mp_encode_uint(p, sync);

    p = mp_encode_map(p, 2);
    p = mp_encode_uint(p, IPROTO_FUNCTION_NAME);
    p = mp_encode_str(p, "rtpe_call_restore", 17);
    p = mp_encode_uint(p, IPROTO_TUPLE);
    p = mp_encode_array(p, 1);
    p = mp_encode_str(p, node_id, (uint32_t)strlen(node_id));

    uint32_t payload_len = (uint32_t)(p - (packet + 5));
    char *len_ptr = packet;
    *len_ptr++ = (char)MP_UINT32;
    *len_ptr++ = (char)(payload_len >> 24);
    *len_ptr++ = (char)(payload_len >> 16);
    *len_ptr++ = (char)(payload_len >> 8);
    *len_ptr++ = (char)(payload_len);

    ssize_t n = send(client->sock_fd, packet, 5 + payload_len, 0);
    if (n != (ssize_t)(5 + payload_len)) {
        rtpe_tarantool_close(client);
        return -1;
    }

    (void)userdata;
    return 0;
}

void rtpe_tarantool_close(rtpe_tarantool_client_t *client) {
    if (!client) return;
    if (client->sock_fd >= 0) {
        close(client->sock_fd);
        client->sock_fd = -1;
    }
    client->state = TARANTOOL_DISCONNECTED;
}

void rtpe_tarantool_free(rtpe_tarantool_client_t *client) {
    if (!client) return;
    rtpe_tarantool_close(client);
    free(client);
}
