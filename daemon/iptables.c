#include "iptables.h"
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <libiptc/libiptc.h>
#include <libiptc/libip6tc.h>
#include <libiptc/libxtc.h>
#include <linux/netfilter/xt_comment.h>
#include <glib.h>
#include <errno.h>
#include "aux.h"
#include "log.h"
#include "socket.h"
#include "str.h"

#undef __ALIGN_KERNEL
#define __ALIGN_KERNEL(x, a)		__ALIGN_KERNEL_MASK(x, (__typeof(x))(a) - 1)
#define __ALIGN_KERNEL_MASK(x, mask)	(((x) + (mask)) & ~(mask))
#undef XT_ALIGN
#define XT_ALIGN(s) __ALIGN_KERNEL((s), __alignof__(struct _xt_align))



struct ipt_matches {
	struct xt_entry_match udp_match;
	struct xt_udp udp;
	struct xt_entry_match comment_match;
	struct xt_comment_info comment;
	struct xt_standard_target target;
};
struct ipv4_ipt_entry {
	struct ipt_entry entry;
	struct ipt_matches matches;
};
struct ipv6_ipt_entry {
	struct ip6t_entry entry;
	struct ipt_matches matches;
};


char *g_iptables_chain;



static void ip46tables_fill_matches(struct ipt_matches *matches, const socket_t *local_sock,
		const str *comment)
{
	matches->target.target.u.user.target_size = XT_ALIGN(sizeof(struct xt_standard_target));
	strcpy(matches->target.target.u.user.name, "ACCEPT");

	strcpy(matches->udp_match.u.user.name, "udp");
	matches->udp_match.u.match_size = XT_ALIGN(sizeof(struct xt_entry_match)) + XT_ALIGN(sizeof(struct xt_udp));
	matches->udp.dpts[0] = matches->udp.dpts[1] = local_sock->local.port;
	matches->udp.spts[0] = 0;
	matches->udp.spts[1] = 0xffff;

	if (comment) {
		strcpy(matches->comment_match.u.user.name, "comment");
		matches->comment_match.u.match_size = XT_ALIGN(sizeof(struct xt_entry_match))
			+ XT_ALIGN(sizeof(struct xt_comment_info));
		str_ncpy(matches->comment.comment, sizeof(matches->comment.comment), comment);
	}
}

static const char *ip4tables_add_rule(const socket_t *local_sock, const str *comment) {
	struct xtc_handle *h;
	struct ipv4_ipt_entry entry;
	const char *err;

	h = iptc_init("filter");
	if (!h)
		return "could not initialize iptables";

	ZERO(entry);
	entry.entry.ip.proto = IPPROTO_UDP;
	entry.entry.ip.dst = local_sock->local.address.u.ipv4;
	memset(&entry.entry.ip.dmsk, 0xff, sizeof(entry.entry.ip.dmsk));
	entry.entry.target_offset = G_STRUCT_OFFSET(struct ipv4_ipt_entry, matches.target);

	ip46tables_fill_matches(&entry.matches, local_sock, comment);

	entry.entry.next_offset = entry.entry.target_offset + entry.matches.target.target.u.user.target_size;

	err = "failed to append iptables entry";
	if (!iptc_append_entry(g_iptables_chain, &entry.entry, h))
		goto err;
	err = "failed to commit iptables changes";
	if (!iptc_commit(h))
		goto err;

	err = NULL;

err:
	iptc_free(h);
	return err;
}

static const char *ip6tables_add_rule(const socket_t *local_sock, const str *comment) {
	struct xtc_handle *h;
	struct ipv6_ipt_entry entry;
	const char *err;

	h = ip6tc_init("filter");
	if (!h)
		return "could not initialize iptables";

	ZERO(entry);
	entry.entry.ipv6.proto = IPPROTO_UDP;
	entry.entry.ipv6.dst = local_sock->local.address.u.ipv6;
	memset(&entry.entry.ipv6.dmsk, 0xff, sizeof(entry.entry.ipv6.dmsk));
	entry.entry.target_offset = G_STRUCT_OFFSET(struct ipv6_ipt_entry, matches.target);

	ip46tables_fill_matches(&entry.matches, local_sock, comment);

	entry.entry.next_offset = entry.entry.target_offset + entry.matches.target.target.u.user.target_size;

	err = "failed to append iptables entry";
	if (!ip6tc_append_entry(g_iptables_chain, &entry.entry, h))
		goto err;
	err = "failed to commit iptables changes";
	if (!ip6tc_commit(h))
		goto err;

	err = NULL;

err:
	ip6tc_free(h);
	return err;
}

static const char *ip4tables_del_rule(const socket_t *local_sock) {
	struct xtc_handle *h;
	struct ipv4_ipt_entry entry, mask;
	const char *err;

	h = iptc_init("filter");
	if (!h)
		return "could not initialize iptables";

	ZERO(entry);
	entry.entry.ip.proto = IPPROTO_UDP;
	entry.entry.ip.dst = local_sock->local.address.u.ipv4;
	memset(&entry.entry.ip.dmsk, 0xff, sizeof(entry.entry.ip.dmsk));
	entry.entry.target_offset = G_STRUCT_OFFSET(struct ipv4_ipt_entry, matches.target);

	ip46tables_fill_matches(&entry.matches, local_sock, NULL);

	entry.entry.next_offset = entry.entry.target_offset + entry.matches.target.target.u.user.target_size;

	// match everything except the comment
	memset(&mask, 0, sizeof(mask));
	memset(&mask.entry, 0xff, sizeof(mask.entry));
	memset(&mask.matches.udp_match, 0xff, sizeof(mask.matches.udp_match));
	memset(&mask.matches.udp, 0xff, sizeof(mask.matches.udp));
	memset(&mask.matches.target, 0xff, sizeof(mask.matches.target));

	err = "failed to delete iptables entry";
	if (!iptc_delete_entry(g_iptables_chain, &entry.entry, (unsigned char *) &mask, h))
		goto err;
	err = "failed to commit iptables changes";
	if (!iptc_commit(h))
		goto err;

	err = NULL;

err:
	iptc_free(h);
	return err;
}

static const char *ip6tables_del_rule(const socket_t *local_sock) {
	struct xtc_handle *h;
	struct ipv6_ipt_entry entry, mask;
	const char *err;

	h = ip6tc_init("filter");
	if (!h)
		return "could not initialize iptables";

	ZERO(entry);
	entry.entry.ipv6.proto = IPPROTO_UDP;
	entry.entry.ipv6.dst = local_sock->local.address.u.ipv6;
	memset(&entry.entry.ipv6.dmsk, 0xff, sizeof(entry.entry.ipv6.dmsk));
	entry.entry.target_offset = G_STRUCT_OFFSET(struct ipv6_ipt_entry, matches.target);

	ip46tables_fill_matches(&entry.matches, local_sock, NULL);

	entry.entry.next_offset = entry.entry.target_offset + entry.matches.target.target.u.user.target_size;

	// match everything except the comment
	memset(&mask, 0, sizeof(mask));
	memset(&mask.entry, 0xff, sizeof(mask.entry));
	memset(&mask.matches.udp_match, 0xff, sizeof(mask.matches.udp_match));
	memset(&mask.matches.udp, 0xff, sizeof(mask.matches.udp));
	memset(&mask.matches.target, 0xff, sizeof(mask.matches.target));

	err = "failed to delete iptables entry";
	if (!ip6tc_delete_entry(g_iptables_chain, &entry.entry, (unsigned char *) &mask, h))
		goto err;
	err = "failed to commit iptables changes";
	if (!ip6tc_commit(h))
		goto err;

	err = NULL;

err:
	ip6tc_free(h);
	return err;
}

int iptables_add_rule(const socket_t *local_sock, const str *comment) {
	const char *err;

	if (!g_iptables_chain)
		return 0;

	switch (local_sock->family->af) {
		case AF_INET:
			err = ip4tables_add_rule(local_sock, comment);
			break;
		case AF_INET6:
			err = ip6tables_add_rule(local_sock, comment);
			break;
		default:
			err = "unsupported socket family";
			break;
	};

	if (err)
		ilog(LOG_ERROR, "Error adding iptables rule (for '" STR_FORMAT "'): %s (%s)",
				STR_FMT(comment), err, strerror(errno));

	return 0;
}


int iptables_del_rule(const socket_t *local_sock) {
	const char *err;

	if (!g_iptables_chain)
		return 0;

	switch (local_sock->family->af) {
		case AF_INET:
			err = ip4tables_del_rule(local_sock);
			break;
		case AF_INET6:
			err = ip6tables_del_rule(local_sock);
			break;
		default:
			err = "unsupported socket family";
			break;
	};

	if (err)
		ilog(LOG_ERROR, "Error deleting iptables rule: %s (%s)",
				err, strerror(errno));

	return 0;
;
}
