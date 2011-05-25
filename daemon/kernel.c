#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <glib.h>

#include "ipt_MEDIAPROXY.h"

#include "aux.h"
#include "kernel.h"




#if 1
#define PREFIX "/proc/mediaproxy"
#else
#define PREFIX "/tmp/mediaproxy"
#endif





int kernel_create_table(unsigned int id) {
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


int kernel_open_table(unsigned int id) {
	char str[64];
	int fd;
	struct mediaproxy_message msg;
	int i;

	sprintf(str, PREFIX "/%u/control", id);
	fd = open(str, O_WRONLY | O_TRUNC);
	if (fd == -1)
		return -1;

	ZERO(msg);
	msg.cmd = MMG_NOOP;
	i = write(fd, &msg, sizeof(msg));
	if (i <= 0)
		goto fail;

	return fd;

fail:
	close(fd);
	return -1;
}


int kernel_add_stream(int fd, struct kernel_stream *info, int update) {
	struct mediaproxy_message msg;

	ZERO(msg);
	msg.cmd = update ? MMG_UPDATE : MMG_ADD;
	msg.target.target_port = info->local_port;
	msg.target.src_ip = info->src.ip;
	msg.target.dst_ip = info->dest.ip;
	msg.target.src_port = info->src.port;
	msg.target.dst_port = info->dest.port;
	msg.target.mirror_ip = info->mirror.ip;
	msg.target.mirror_port = info->mirror.port;
	msg.target.tos = info->tos;

	return write(fd, &msg, sizeof(msg)) <= 0 ? -1 : 0;
}


int kernel_del_stream(int fd, u_int16_t p) {
	struct mediaproxy_message msg;

	ZERO(msg);
	msg.cmd = MMG_DEL;
	msg.target.target_port = p;

	return write(fd, &msg, sizeof(msg)) <= 0 ? -1 : 0;
}


GList *kernel_list(unsigned int id) {
	char str[64];
	int fd;
	struct mediaproxy_list_entry *buf;
	GList *li = NULL;
	int ret;

	sprintf(str, PREFIX "/%u/blist", id);
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
