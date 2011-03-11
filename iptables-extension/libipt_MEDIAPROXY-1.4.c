/* gcc -O2 -Wall -shared -o libipt_MEDIAPROXY.so libipt_MEDIAPROXY.c */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <xtables.h>
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
			const void *entry,
			struct xt_entry_target **target) {

	struct ipt_mediaproxy_info *info = (void *) *target;

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

static void print(const void *ip, const struct xt_entry_target *target, int numeric) {
	struct ipt_mediaproxy_info *info = (void *) target;

	printf("id %u", info->id);
}

static void save(const void *ip, const struct xt_entry_target *target) {
	struct ipt_mediaproxy_info *info = (void *) target;

	printf("--id %u", info->id);
}

static struct option opts[] = {
	{ "id", 1, NULL, '1' },
	{ NULL, },
};


static struct xtables_target mediaproxy = {
	.name			= "MEDIAPROXY",
	.family			= AF_INET,
	.version		= "1.4.2",
	.size			= XT_ALIGN(sizeof(struct ipt_mediaproxy_info)),
	.userspacesize		= XT_ALIGN(sizeof(struct ipt_mediaproxy_info)),
	.help			= help,
	.parse			= parse,
	.final_check		= final_check,
	.print			= print,
	.save			= save,
	.extra_opts		= opts,
};

void _init(void) {
	xtables_register_target(&mediaproxy);
}
