/* gcc -O2 -Wall -shared -fPIC -o libxt_MEDIAPROXY.so libxt_MEDIAPROXY.c */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <xtables.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>
#include "../kernel-module/xt_MEDIAPROXY.h"


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

	struct xt_mediaproxy_info *info = (void *) (*target)->data;

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
		xtables_error(PARAMETER_PROBLEM, "You must specify --id");
}

static void print(const void *ip, const struct xt_entry_target *target, int numeric) {
	struct xt_mediaproxy_info *info = (void *) target->data;

	printf("id %u", info->id);
}

static void save(const void *ip, const struct xt_entry_target *target) {
	struct xt_mediaproxy_info *info = (void *) target->data;

	printf("--id %u", info->id);
}

static struct option opts[] = {
	{ "id", 1, NULL, '1' },
	{ NULL, },
};


static struct xtables_target mediaproxy4 = {
	.name			= "MEDIAPROXY",
	.family			= NFPROTO_IPV4,
	.version		= XTABLES_VERSION,
	.size			= XT_ALIGN(sizeof(struct xt_mediaproxy_info)),
	.userspacesize		= XT_ALIGN(sizeof(struct xt_mediaproxy_info)),
	.help			= help,
	.parse			= parse,
	.final_check		= final_check,
	.print			= print,
	.save			= save,
	.extra_opts		= opts,
};

static struct xtables_target mediaproxy6 = {
	.name			= "MEDIAPROXY",
	.family			= NFPROTO_IPV6,
	.version		= XTABLES_VERSION,
	.size			= XT_ALIGN(sizeof(struct xt_mediaproxy_info)),
	.userspacesize		= XT_ALIGN(sizeof(struct xt_mediaproxy_info)),
	.help			= help,
	.parse			= parse,
	.final_check		= final_check,
	.print			= print,
	.save			= save,
	.extra_opts		= opts,
};

void _init(void) {
	xtables_register_target(&mediaproxy4);
	xtables_register_target(&mediaproxy6);
}
