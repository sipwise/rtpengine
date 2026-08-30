/*
 * Copyright (C) 2026 Sipwise GmbH / RTPEngine Project
 *
 * tarantool.h - Header for RTPEngine Tarantool IProto driver
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __RTPE_TARANTOOL_H__
#define __RTPE_TARANTOOL_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* IProto Request Types */
#define IPROTO_OK               0
#define IPROTO_SELECT           1
#define IPROTO_INSERT           2
#define IPROTO_REPLACE          3
#define IPROTO_UPDATE           4
#define IPROTO_DELETE           5
#define IPROTO_CALL             6
#define IPROTO_AUTH             7
#define IPROTO_EVAL             8

/* IProto Keys */
#define IPROTO_REQUEST_TYPE     0x00
#define IPROTO_SYNC             0x01
#define IPROTO_SPACE_ID         0x10
#define IPROTO_INDEX_ID         0x11
#define IPROTO_LIMIT            0x12
#define IPROTO_OFFSET           0x13
#define IPROTO_ITERATOR         0x14
#define IPROTO_KEY              0x20
#define IPROTO_TUPLE            0x21
#define IPROTO_FUNCTION_NAME    0x22
#define IPROTO_USER_NAME        0x23
#define IPROTO_EXPR             0x27
#define IPROTO_DATA             0x30
#define IPROTO_ERROR_24         0x31

/* Media session call state structure for Tarantool synchronization */
typedef struct rtpe_call_info {
    const char *call_id;
    size_t      call_id_len;
    const char *node_id;
    const char *caller_ip;
    int         caller_port;
    const char *callee_ip;
    int         callee_port;
    const char *srtp_suite;
    const char *crypto_key;
    uint32_t    ttl_sec;
} rtpe_call_info_t;

typedef enum {
    TARANTOOL_DISCONNECTED = 0,
    TARANTOOL_CONNECTING,
    TARANTOOL_AUTHENTICATED,
    TARANTOOL_DISABLED,
    TARANTOOL_ERROR
} rtpe_tnt_state_t;

/* Driver Configuration Options */
typedef struct rtpe_tarantool_config {
    char     host[128];
    int      port;
    char     write_host[128];
    int      write_port;
    char     user[64];
    char     password[64];
    char     node_id[64];
    char     space[64];
    int      num_threads;
    int      expires_secs;
    int      connect_timeout_ms;
    int      cmd_timeout_ms;
    int      no_tarantool_required;
    int      disable_time;
    int      allowed_errors;
    int      resolve_on_reconnect;
    int      tcp_keepalive_time;
    int      tcp_keepalive_intvl;
    int      tcp_keepalive_probes;
} rtpe_tarantool_config_t;

typedef struct rtpe_tarantool_client {
    rtpe_tarantool_config_t config;
    int              sock_fd;
    rtpe_tnt_state_t state;
    uint64_t         sync_id;
    uint64_t         total_sent;
    uint64_t         total_errors;
    int              consecutive_errors;
    time_t           disabled_until;
} rtpe_tarantool_client_t;

/* Public C API */
rtpe_tarantool_client_t *rtpe_tarantool_new(const char *host, int port, const char *user, const char *pass, const char *node_id);
rtpe_tarantool_client_t *rtpe_tarantool_new_from_config(const rtpe_tarantool_config_t *cfg);
int  rtpe_tarantool_connect(rtpe_tarantool_client_t *client);
int  rtpe_tarantool_save_call(rtpe_tarantool_client_t *client, const rtpe_call_info_t *info);
int  rtpe_tarantool_delete_call(rtpe_tarantool_client_t *client, const char *call_id, size_t call_id_len);
int  rtpe_tarantool_restore_calls(rtpe_tarantool_client_t *client, const char *node_id, int (*restore_cb)(const rtpe_call_info_t *call, void *userdata), void *userdata);
void rtpe_tarantool_close(rtpe_tarantool_client_t *client);
void rtpe_tarantool_free(rtpe_tarantool_client_t *client);

/* Call packet serialization */
size_t rtpe_tarantool_pack_call_upsert(char *buf, size_t buf_size, uint64_t sync_id, const char *node_id, const rtpe_call_info_t *info);
size_t rtpe_tarantool_pack_call_delete(char *buf, size_t buf_size, uint64_t sync_id, const char *call_id, size_t call_id_len);

#ifdef __cplusplus
}
#endif

#endif /* __RTPE_TARANTOOL_H__ */
