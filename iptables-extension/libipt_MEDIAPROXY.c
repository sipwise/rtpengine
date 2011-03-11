/* gcc -O2 -Wall -shared -o libipt_MEDIAPROXY.so libipt_MEDIAPROXY.c */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iptables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include "../kernel-module/ipt_MEDIAPROXY.h"


static void help(void) {
	printf(
		"MEDIAPROXY target options:\n"
		" --id <id>\n"
		"          Unique ID for this instance\n"
	);
}

static int parse(int c,
			char **argv,
			int invert,
			unsigned int *flags,
			const struct ipt_entry *entry,
			struct ipt_entry_target **target) {

	struct ipt_mediaproxy_info *info = (void *) (*target)->data;

	if (c == '1') {
		info->id = atoi(optarg);
		if (flags)
			*flags = 1;
	}
	else
		return 0;

	return 1;
}

static void final_check(unsigned int flags) {
	if (!flags)
		exit_error(PARAMETER_PROBLEM, "You must specify --id");
}

static void print(const struct ipt_ip *ip, const struct ipt_entry_target *target, int numeric) {
	struct ipt_mediaproxy_info *info = (void *) target->data;

	printf("id %u", info->id);
}

static void save(const struct ipt_ip *ip, const struct ipt_entry_target *target) {
	struct ipt_mediaproxy_info *info = (void *) target->data;

	printf("--id %u", info->id);
}

static struct option opts[] = {
	{ "id", 1, NULL, '1' },
	{ NULL, },
};


static struct iptables_target mediaproxy = {
	.name			= "MEDIAPROXY",
	.version		= "1.3.6",
	.size			= IPT_ALIGN(sizeof(struct ipt_mediaproxy_info)),
	.userspacesize		= IPT_ALIGN(sizeof(struct ipt_mediaproxy_info)),
	.help			= help,
	.parse			= parse,
	.final_check		= final_check,
	.print			= print,
	.save			= save,
	.extra_opts		= opts,
};

void _init(void) {
	register_target(&mediaproxy);
}
