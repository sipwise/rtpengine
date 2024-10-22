#include "kernel.h"

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <glib.h>
#include <errno.h>
#include <sys/mman.h>

#include "helpers.h"
#include "log.h"
#include "bufferpool.h"
#include "main.h"
#include "statistics.h"

#include "xt_RTPENGINE.h"

#define PREFIX "/proc/rtpengine"
#define MMAP_PAGE_SIZE (4096 * 16)

struct kernel_interface kernel;

static bool kernel_action_table(const char *action, unsigned int id) {
	char s[64];
	int saved_errno;
	int fd;
	int i;
	ssize_t ret;

	fd = open(PREFIX "/control", O_WRONLY | O_TRUNC);
	if (fd == -1)
		return false;
	i = snprintf(s, sizeof(s), "%s %u\n", action, id);
	if (i >= sizeof(s))
		goto fail;
	ret = write(fd, s, strlen(s));
	if (ret == -1)
		goto fail;
	close(fd);

	return true;

fail:
	saved_errno = errno;
	close(fd);
	errno = saved_errno;
	return false;
}

static bool kernel_create_table(unsigned int id) {
	return kernel_action_table("add", id);
}

static bool kernel_delete_table(unsigned int id) {
	return kernel_action_table("del", id);
}

static void *kernel_alloc(size_t len) {
	void *b = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, kernel.fd, 0);
	assert(b != NULL && b != MAP_FAILED);
	return b;
}
static void kernel_free(void *p, size_t len) {
	munmap(p, len);
}

static int kernel_open_table(unsigned int id) {
	char s[64];
	int fd;

	sprintf(s, PREFIX "/%u/control", id);
	fd = open(s, O_RDWR | O_TRUNC);
	if (fd == -1)
		return -1;

	return fd;
}

bool kernel_init_table(void) {
	if (!kernel.is_open)
		return true;

	ssize_t ret;

	struct rtpengine_command_init cmd = {
		.cmd = REMG_INIT,
		.init = {
			.last_cmd = __REMG_LAST,
			.msg_size = {
				[REMG_INIT] = sizeof(struct rtpengine_command_init),
				[REMG_ADD_TARGET] = sizeof(struct rtpengine_command_add_target),
				[REMG_DEL_TARGET] = sizeof(struct rtpengine_command_del_target),
				[REMG_ADD_DESTINATION] = sizeof(struct rtpengine_command_destination),
				[REMG_ADD_CALL] = sizeof(struct rtpengine_command_add_call),
				[REMG_DEL_CALL] = sizeof(struct rtpengine_command_del_call),
				[REMG_ADD_STREAM] = sizeof(struct rtpengine_command_add_stream),
				[REMG_DEL_STREAM] = sizeof(struct rtpengine_command_del_stream),
				[REMG_PACKET] = sizeof(struct rtpengine_command_packet),
				[REMG_INIT_PLAY_STREAMS] = sizeof(struct rtpengine_command_init_play_streams),
				[REMG_GET_PACKET_STREAM] = sizeof(struct rtpengine_command_get_packet_stream),
				[REMG_PLAY_STREAM_PACKET] = sizeof(struct rtpengine_command_play_stream_packet),
				[REMG_PLAY_STREAM] = sizeof(struct rtpengine_command_play_stream),
				[REMG_STOP_STREAM] = sizeof(struct rtpengine_command_stop_stream),
				[REMG_FREE_PACKET_STREAM] = sizeof(struct rtpengine_command_free_packet_stream),
			},
			.rtpe_stats = rtpe_stats,
		},
	};

	ret = write(kernel.fd, &cmd, sizeof(cmd));
	if (ret <= 0)
		return false;

	return true;
}

bool kernel_setup_table(unsigned int id) {
	if (kernel.is_wanted)
		abort();

	kernel.is_wanted = true;

	if (!kernel_delete_table(id) && errno != ENOENT) {
		ilog(LOG_ERR, "FAILED TO DELETE KERNEL TABLE %i (%s), KERNEL FORWARDING DISABLED",
				id, strerror(errno));
		return false;
	}
	if (!kernel_create_table(id)) {
		ilog(LOG_ERR, "FAILED TO CREATE KERNEL TABLE %i (%s), KERNEL FORWARDING DISABLED",
				id, strerror(errno));
		return false;
	}
	int fd = kernel_open_table(id);
	if (fd == -1) {
		ilog(LOG_ERR, "FAILED TO OPEN KERNEL TABLE %i (%s), KERNEL FORWARDING DISABLED",
				id, strerror(errno));
		return false;
	}

	kernel.fd = fd;
	kernel.table = id;
	kernel.is_open = true;

	shm_bufferpool = bufferpool_new2(kernel_alloc, kernel_free, MMAP_PAGE_SIZE);

	return true;
}

void kernel_shutdown_table(void) {
	if (!kernel.is_open)
		return;
	// ignore errors
	close(kernel.fd);
	kernel_delete_table(kernel.table);
}


void kernel_add_stream(struct rtpengine_target_info *mti) {
	ssize_t ret;

	if (!kernel.is_open)
		return;

	struct rtpengine_command_add_target cmd = {
		.cmd = REMG_ADD_TARGET,
		.target = *mti,
	};

	ret = write(kernel.fd, &cmd, sizeof(cmd));
	if (ret == sizeof(cmd))
		return;

	ilog(LOG_ERROR, "Failed to push relay stream to kernel: %s", strerror(errno));
}

void kernel_add_destination(struct rtpengine_destination_info *mdi) {
	ssize_t ret;

	if (!kernel.is_open)
		return;

	struct rtpengine_command_destination cmd = {
		.cmd = REMG_ADD_DESTINATION,
		.destination = *mdi,
	};

	ret = write(kernel.fd, &cmd, sizeof(cmd));
	if (ret == sizeof(cmd))
		return;

	ilog(LOG_ERROR, "Failed to push relay stream destination to kernel: %s", strerror(errno));
}


bool kernel_del_stream(struct rtpengine_command_del_target *cmd) {
	ssize_t ret;

	if (!kernel.is_open)
		return false;

	cmd->cmd = REMG_DEL_TARGET;

	ret = write(kernel.fd, cmd, sizeof(*cmd));
	if (ret == sizeof(*cmd))
		return true;

	ilog(LOG_ERROR, "Failed to delete relay stream from kernel: %s", strerror(errno));
	return false;
}

unsigned int kernel_add_call(const char *id) {
	ssize_t ret;

	if (!kernel.is_open)
		return UNINIT_IDX;

	struct rtpengine_command_add_call cmd = {
		.cmd = REMG_ADD_CALL,
	};
	snprintf(cmd.call.call_id, sizeof(cmd.call.call_id), "%s", id);

	ret = read(kernel.fd, &cmd, sizeof(cmd));
	if (ret != sizeof(cmd))
		return UNINIT_IDX;
	return cmd.call.call_idx;
}

void kernel_del_call(unsigned int idx) {
	ssize_t ret;

	if (!kernel.is_open)
		return;

	struct rtpengine_command_del_call cmd = {
		.cmd = REMG_DEL_CALL,
		.call_idx = idx,
	};

	ret = write(kernel.fd, &cmd, sizeof(cmd));
	if (ret == sizeof(cmd))
		return;

	ilog(LOG_ERROR, "Failed to delete intercept call from kernel: %s", strerror(errno));
}

unsigned int kernel_add_intercept_stream(unsigned int call_idx, const char *id) {
	ssize_t ret;

	if (!kernel.is_open)
		return UNINIT_IDX;

	struct rtpengine_command_add_stream cmd = {
		.cmd = REMG_ADD_STREAM,
		.stream.idx.call_idx = call_idx,
	};
	snprintf(cmd.stream.stream_name, sizeof(cmd.stream.stream_name), "%s", id);

	ret = read(kernel.fd, &cmd, sizeof(cmd));
	if (ret != sizeof(cmd))
		return UNINIT_IDX;
	return cmd.stream.idx.stream_idx;
}

bool kernel_init_player(int num_media, int num_sessions) {
	if (num_media <= 0 || num_sessions <= 0)
		return false;
	if (!kernel.is_open)
		return false;

	struct rtpengine_command_init_play_streams ips = {
		.cmd = REMG_INIT_PLAY_STREAMS,
		.num_packet_streams = num_media,
		.num_play_streams = num_sessions,
	};
	ssize_t ret = write(kernel.fd, &ips, sizeof(ips));
	if (ret != sizeof(ips))
		return false;

	kernel.use_player = true;

	return true;
}

unsigned int kernel_get_packet_stream(void) {
	if (!kernel.use_player)
		return -1;

	struct rtpengine_command_get_packet_stream gps = { .cmd = REMG_GET_PACKET_STREAM };
	ssize_t ret = read(kernel.fd, &gps, sizeof(gps));
	if (ret != sizeof(gps))
		return -1;
	return gps.packet_stream_idx;
}

bool kernel_add_stream_packet(unsigned int idx, const char *buf, size_t len, unsigned long delay_ms,
		uint32_t ts, uint32_t dur)
{
	if (!kernel.use_player)
		return false;

	size_t total_len = len + sizeof(struct rtpengine_command_play_stream_packet);
	struct rtpengine_command_play_stream_packet *cmd = alloca(total_len);

	*cmd = (__typeof__(*cmd)) {
		.cmd = REMG_PLAY_STREAM_PACKET,
		.play_stream_packet.packet_stream_idx = idx,
		.play_stream_packet.delay_ms = delay_ms,
		.play_stream_packet.delay_ts = ts,
		.play_stream_packet.duration_ts = dur,
	};

	memcpy(&cmd->play_stream_packet.data, buf, len);

	ssize_t ret = write(kernel.fd, cmd, total_len);
	if (ret != total_len)
		return false;
	return true;
}

unsigned int kernel_start_stream_player(struct rtpengine_play_stream_info *info) {
	if (!kernel.use_player)
		return -1;

	struct rtpengine_command_play_stream ps = {
		.cmd = REMG_PLAY_STREAM,
		.info = *info,
	};
	ssize_t ret = read(kernel.fd, &ps, sizeof(ps));
	if (ret == sizeof(ps))
		return ps.play_idx;
	return -1;
}

bool kernel_stop_stream_player(unsigned int idx) {
	if (!kernel.use_player)
		return false;

	struct rtpengine_command_stop_stream ss = {
		.cmd = REMG_STOP_STREAM,
		.play_idx = idx,
	};
	ssize_t ret = write(kernel.fd, &ss, sizeof(ss));
	if (ret == sizeof(ss))
		return true;
	return false;
}

bool kernel_free_packet_stream(unsigned int idx) {
	if (!kernel.use_player)
		return false;

	struct rtpengine_command_free_packet_stream fps = {
		.cmd = REMG_FREE_PACKET_STREAM,
		.packet_stream_idx = idx,
	};
	ssize_t ret = write(kernel.fd, &fps, sizeof(fps));
	if (ret == sizeof(fps))
		return true;
	return false;
}
