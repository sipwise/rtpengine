#include "kernel.h"

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <glib.h>
#include <errno.h>

#include "xt_RTPENGINE.h"

#include "aux.h"
#include "log.h"




#define PREFIX "/proc/rtpengine"




struct kernel_interface kernel;





static int kernel_action_table(const char *action, unsigned int id) {
	char str[64];
	int saved_errno;
	int fd;
	int i;
	ssize_t ret;

	fd = open(PREFIX "/control", O_WRONLY | O_TRUNC);
	if (fd == -1)
		return -1;
	i = snprintf(str, sizeof(str), "%s %u\n", action, id);
	if (i >= sizeof(str))
		goto fail;
	ret = write(fd, str, strlen(str));
	if (ret == -1)
		goto fail;
	close(fd);

	return 0;

fail:
	saved_errno = errno;
	close(fd);
	errno = saved_errno;
	return -1;
}

static int kernel_create_table(unsigned int id) {
	return kernel_action_table("add", id);
}

static int kernel_delete_table(unsigned int id) {
	return kernel_action_table("del", id);
}

static int kernel_open_table(unsigned int id) {
	char str[64];
	int saved_errno;
	int fd;
	struct rtpengine_command_noop cmd;
	ssize_t ret;

	sprintf(str, PREFIX "/%u/control", id);
	fd = open(str, O_RDWR | O_TRUNC);
	if (fd == -1)
		return -1;

	cmd.cmd = REMG_NOOP;

	cmd.noop = (struct rtpengine_noop_info) {
		.last_cmd = __REMG_LAST,
		.msg_size = {
			[REMG_NOOP] = sizeof(struct rtpengine_command_noop),
			[REMG_ADD_TARGET] = sizeof(struct rtpengine_command_add_target),
			[REMG_DEL_TARGET] = sizeof(struct rtpengine_command_del_target),
			[REMG_ADD_DESTINATION] = sizeof(struct rtpengine_command_destination),
			[REMG_ADD_CALL] = sizeof(struct rtpengine_command_add_call),
			[REMG_DEL_CALL] = sizeof(struct rtpengine_command_del_call),
			[REMG_ADD_STREAM] = sizeof(struct rtpengine_command_add_stream),
			[REMG_DEL_STREAM] = sizeof(struct rtpengine_command_del_stream),
			[REMG_PACKET] = sizeof(struct rtpengine_command_packet),
			[REMG_GET_STATS] = sizeof(struct rtpengine_command_stats),
			[REMG_GET_RESET_STATS] = sizeof(struct rtpengine_command_stats),
		},
	};

	ret = write(fd, &cmd, sizeof(cmd));
	if (ret <= 0)
		goto fail;

	return fd;

fail:
	saved_errno = errno;
	close(fd);
	errno = saved_errno;
	return -1;
}

int kernel_setup_table(unsigned int id) {
	if (kernel.is_wanted)
		abort();

	kernel.is_wanted = 1;

	if (kernel_delete_table(id) && errno != ENOENT) {
		ilog(LOG_ERR, "FAILED TO DELETE KERNEL TABLE %i (%s), KERNEL FORWARDING DISABLED",
				id, strerror(errno));
		return -1;
	}
	if (kernel_create_table(id)) {
		ilog(LOG_ERR, "FAILED TO CREATE KERNEL TABLE %i (%s), KERNEL FORWARDING DISABLED",
				id, strerror(errno));
		return -1;
	}
	int fd = kernel_open_table(id);
	if (fd == -1) {
		ilog(LOG_ERR, "FAILED TO OPEN KERNEL TABLE %i (%s), KERNEL FORWARDING DISABLED",
				id, strerror(errno));
		return -1;
	}

	kernel.fd = fd;
	kernel.table = id;
	kernel.is_open = 1;

	return 0;
}


int kernel_add_stream(struct rtpengine_target_info *mti) {
	struct rtpengine_command_add_target cmd;
	ssize_t ret;

	if (!kernel.is_open)
		return -1;

	cmd.cmd = REMG_ADD_TARGET;
	cmd.target = *mti;

	ret = write(kernel.fd, &cmd, sizeof(cmd));
	if (ret > 0)
		return 0;

	ilog(LOG_ERROR, "Failed to push relay stream to kernel: %s", strerror(errno));
	return -1;
}

int kernel_add_destination(struct rtpengine_destination_info *mdi) {
	struct rtpengine_command_destination cmd;
	ssize_t ret;

	if (!kernel.is_open)
		return -1;

	cmd.cmd = REMG_ADD_DESTINATION;
	cmd.destination = *mdi;

	ret = write(kernel.fd, &cmd, sizeof(cmd));
	if (ret > 0)
		return 0;

	ilog(LOG_ERROR, "Failed to push relay stream destination to kernel: %s", strerror(errno));
	return -1;
}


int kernel_del_stream(const struct re_address *a) {
	struct rtpengine_command_del_target cmd;
	ssize_t ret;

	if (!kernel.is_open)
		return -1;

	cmd.cmd = REMG_DEL_TARGET;
	cmd.local = *a;

	ret = write(kernel.fd, &cmd, sizeof(cmd));
	if (ret > 0)
		return 0;

	ilog(LOG_ERROR, "Failed to delete relay stream from kernel: %s", strerror(errno));
	return -1;
}

GList *kernel_list() {
	char str[64];
	int fd;
	struct rtpengine_list_entry *buf;
	GList *li = NULL;
	ssize_t ret;

	if (!kernel.is_open)
		return NULL;

	sprintf(str, PREFIX "/%u/blist", kernel.table);
	fd = open(str, O_RDONLY);
	if (fd == -1)
		return NULL;


	for (;;) {
		buf = g_slice_alloc(sizeof(*buf));
		ret = read(fd, buf, sizeof(*buf));
		if (ret != sizeof(*buf))
			break;
		li = g_list_prepend(li, buf);
	}

	g_slice_free1(sizeof(*buf), buf);
	close(fd);

	return li;
}

unsigned int kernel_add_call(const char *id) {
	struct rtpengine_command_add_call cmd;
	ssize_t ret;

	if (!kernel.is_open)
		return UNINIT_IDX;

	cmd.cmd = REMG_ADD_CALL;
	snprintf(cmd.call.call_id, sizeof(cmd.call.call_id), "%s", id);

	ret = read(kernel.fd, &cmd, sizeof(cmd));
	if (ret != sizeof(cmd))
		return UNINIT_IDX;
	return cmd.call.call_idx;
}

int kernel_del_call(unsigned int idx) {
	struct rtpengine_command_del_call cmd;
	ssize_t ret;

	if (!kernel.is_open)
		return -1;

	cmd.cmd = REMG_DEL_CALL;
	cmd.call_idx = idx;

	ret = write(kernel.fd, &cmd, sizeof(cmd));
	if (ret != sizeof(cmd))
		return -1;
	return 0;
}

unsigned int kernel_add_intercept_stream(unsigned int call_idx, const char *id) {
	struct rtpengine_command_add_stream cmd;
	ssize_t ret;

	if (!kernel.is_open)
		return UNINIT_IDX;

	cmd.cmd = REMG_ADD_STREAM;
	cmd.stream.idx.call_idx = call_idx;
	snprintf(cmd.stream.stream_name, sizeof(cmd.stream.stream_name), "%s", id);

	ret = read(kernel.fd, &cmd, sizeof(cmd));
	if (ret != sizeof(cmd))
		return UNINIT_IDX;
	return cmd.stream.idx.stream_idx;
}

// cmd->local must be filled in
int kernel_update_stats(struct rtpengine_command_stats *cmd) {
	ssize_t ret;

	if (!kernel.is_open)
		return -1;

	cmd->cmd = REMG_GET_RESET_STATS;

	ret = read(kernel.fd, cmd, sizeof(*cmd));
	if (ret <= 0) {
		ilog(LOG_ERROR, "Failed to get stream stats from kernel: %s", strerror(errno));
		return -1;
	}

	return 0;
}
