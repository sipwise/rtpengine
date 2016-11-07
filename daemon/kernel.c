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





static int kernel_create_table(unsigned int id) {
	char str[64];
	int fd;
	int i;

	fd = open(PREFIX "/control", O_WRONLY | O_TRUNC);
	if (fd == -1)
		return -1;
	sprintf(str, "add %u\n", id);
	i = write(fd, str, strlen(str));
	if (i == -1)
		goto fail;
	close(fd);

	return 0;

fail:
	close(fd);
	return -1;
}

static int kernel_open_table(unsigned int id) {
	char str[64];
	int fd;
	struct rtpengine_message msg;
	int i;

	sprintf(str, PREFIX "/%u/control", id);
	fd = open(str, O_RDWR | O_TRUNC);
	if (fd == -1)
		return -1;

	ZERO(msg);
	msg.cmd = REMG_NOOP;
	i = write(fd, &msg, sizeof(msg));
	if (i <= 0)
		goto fail;

	return fd;

fail:
	close(fd);
	return -1;
}

int kernel_setup_table(unsigned int id) {
	if (kernel.is_wanted)
		abort();

	kernel.is_wanted = 1;

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


int kernel_add_stream(struct rtpengine_target_info *mti, int update) {
	struct rtpengine_message msg;
	int ret;

	if (!kernel.is_open)
		return -1;

	msg.cmd = update ? REMG_UPDATE : REMG_ADD;
	msg.u.target = *mti;

	ret = write(kernel.fd, &msg, sizeof(msg));
	if (ret > 0)
		return 0;

	ilog(LOG_ERROR, "Failed to push relay stream to kernel: %s", strerror(errno));
	return -1;
}


int kernel_del_stream(const struct re_address *a) {
	struct rtpengine_message msg;
	int ret;

	if (!kernel.is_open)
		return -1;

	ZERO(msg);
	msg.cmd = REMG_DEL;
	msg.u.target.local = *a;

	ret = write(kernel.fd, &msg, sizeof(msg));
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
	int ret;

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
	struct rtpengine_message msg;
	int ret;

	if (!kernel.is_open)
		return UNINIT_IDX;

	ZERO(msg);
	msg.cmd = REMG_ADD_CALL;
	snprintf(msg.u.call.call_id, sizeof(msg.u.call.call_id), "%s", id);

	ret = read(kernel.fd, &msg, sizeof(msg));
	if (ret != sizeof(msg))
		return UNINIT_IDX;
	return msg.u.call.call_idx;
}

int kernel_del_call(unsigned int idx) {
	struct rtpengine_message msg;
	int ret;

	if (!kernel.is_open)
		return -1;

	ZERO(msg);
	msg.cmd = REMG_DEL_CALL;
	msg.u.call.call_idx = idx;

	ret = write(kernel.fd, &msg, sizeof(msg));
	if (ret != sizeof(msg))
		return -1;
	return 0;
}

unsigned int kernel_add_intercept_stream(unsigned int call_idx, const char *id) {
	struct rtpengine_message msg;
	int ret;

	if (!kernel.is_open)
		return UNINIT_IDX;

	ZERO(msg);
	msg.cmd = REMG_ADD_STREAM;
	msg.u.stream.call_idx = call_idx;
	snprintf(msg.u.stream.stream_name, sizeof(msg.u.stream.stream_name), "%s", id);

	ret = read(kernel.fd, &msg, sizeof(msg));
	if (ret != sizeof(msg))
		return UNINIT_IDX;
	return msg.u.stream.stream_idx;
}
