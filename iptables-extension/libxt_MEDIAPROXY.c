#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#if defined(__ipt)
#include <iptables.h>
#elif defined(__ip6t)
#include <ip6tables.h>
#else
#include <xtables.h>
#endif

#include <linux/netfilter.h>

#if defined(__ipt)
#include <linux/netfilter_ipv4/ip_tables.h>
#elif defined(__ip6t)
#include <linux/netfilter_ipv6/ip6_tables.h>
#else
#include <linux/netfilter/x_tables.h>
#endif

#include "../kernel-module/xt_MEDIAPROXY.h"


static void help(void) {
	printf(
		"MEDIAPROXY (version %s) target options:\n"
		" --id <id>\n"
		"          Unique ID for this instance\n",
		MEDIAPROXY_VERSION
	);
}

#if defined(__ipt)
static int parse(int c,
			char **argv,
			int invert,
			unsigned int *flags,
			const struct ipt_entry *entry,
			struct ipt_entry_target **target) {
#elif defined(__ip6t)
static int parse(int c,
			char **argv,
			int invert,
			unsigned int *flags,
			const struct ip6t_entry *entry,
			struct ip6t_entry_target **target) {
#else
static int parse(int c,
			char **argv,
			int invert,
			unsigned int *flags,
			const void *entry,
			struct xt_entry_target **target) {
#endif

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
#if defined(__ipt) || defined(__ip6t)
	if (!flags)
		exit_error(PARAMETER_PROBLEM, "You must specify --id");
#else
	if (!flags)
		xtables_error(PARAMETER_PROBLEM, "You must specify --id");
#endif
}

#if defined(__ipt)
static void print(const struct ipt_ip *ip, const struct xt_entry_target *target, int numeric) {
#elif defined(__ip6t)
static void print(const struct ip6t_ip6 *ip, const struct xt_entry_target *target, int numeric) {
#else
static void print(const void *ip, const struct xt_entry_target *target, int numeric) {
#endif
	struct xt_mediaproxy_info *info = (void *) target->data;

	printf(" MEDIAPROXY id:%u", info->id);
}

#if defined(__ipt)
static void save(const struct ipt_ip *ip, const struct xt_entry_target *target) {
#elif defined(__ip6t)
static void save(const struct ip6t_ip6 *ip, const struct xt_entry_target *target) {
#else
static void save(const void *ip, const struct xt_entry_target *target) {
#endif
	struct xt_mediaproxy_info *info = (void *) target->data;

	printf(" --id %u", info->id);
}

static struct option opts[] = {
	{ "id", 1, NULL, '1' },
	{ NULL, },
};


#if defined(__ipt)
static struct iptables_target mediaproxy4 = {
	.name			= "MEDIAPROXY",
	.version		= "1.3.6",
	.size			= IPT_ALIGN(sizeof(struct xt_mediaproxy_info)),
	.userspacesize		= IPT_ALIGN(sizeof(struct xt_mediaproxy_info)),
	.help			= help,
	.parse			= parse,
	.final_check		= final_check,
	.print			= print,
	.save			= save,
	.extra_opts		= opts,
};
#elif defined(__ip6t)
static struct ip6tables_target mediaproxy6 = {
	.name			= "MEDIAPROXY",
	.version		= "1.3.6",
	.size			= IP6T_ALIGN(sizeof(struct xt_mediaproxy_info)),
	.userspacesize		= IP6T_ALIGN(sizeof(struct xt_mediaproxy_info)),
	.help			= help,
	.parse			= parse,
	.final_check		= final_check,
	.print			= print,
	.save			= save,
	.extra_opts		= opts,
};
#else
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
#endif

void _init(void) {
#if defined(__ipt)
	register_target(&mediaproxy4);
#elif defined(__ip6t)
	register_target6(&mediaproxy6);
#else
	xtables_register_target(&mediaproxy4);
	xtables_register_target(&mediaproxy6);
#endif
}
