#include "iptables.h"
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <libiptc/libiptc.h>
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



struct ipv4_ipt_entry {
	struct ipt_entry entry;
	struct xt_entry_match udp_match;
	struct xt_udp udp;
	struct xt_entry_match comment_match;
	struct xt_comment_info comment;
	struct xt_standard_target target;
};


char *g_iptables_chain;



int iptables_add_rule(const socket_t *local_sock, const str *comment) {
	struct xtc_handle *h;
	struct ipv4_ipt_entry e;
	int ret = -1;
	const char *err;

	if (!g_iptables_chain)
		return 0;

	err = "could not initialize iptables table 'filter'";
	h = iptc_init("filter");
	if (!h)
		goto out2;

	ZERO(e);

	e.entry.ip.proto = IPPROTO_UDP;
	e.entry.ip.dst = local_sock->local.address.u.ipv4;
	e.entry.ip.dmsk.s_addr = 0xffffffff;

	e.target.target.u.user.target_size = XT_ALIGN(sizeof(struct xt_standard_target));
	strcpy(e.target.target.u.user.name, "ACCEPT");

	e.entry.target_offset = G_STRUCT_OFFSET(struct ipv4_ipt_entry, target);
	e.entry.next_offset = e.entry.target_offset + e.target.target.u.user.target_size;

	strcpy(e.udp_match.u.user.name, "udp");
	e.udp_match.u.match_size = XT_ALIGN(sizeof(struct xt_entry_match)) + XT_ALIGN(sizeof(struct xt_udp));
	e.udp.dpts[0] = e.udp.dpts[1] = local_sock->local.port;
	e.udp.spts[0] = 0;
	e.udp.spts[1] = 0xffff;

	strcpy(e.comment_match.u.user.name, "comment");
	e.comment_match.u.match_size = XT_ALIGN(sizeof(struct xt_entry_match))
		+ XT_ALIGN(sizeof(struct xt_comment_info));
	strcpy(e.comment.comment, "testing");
	str_ncpy(e.comment.comment, sizeof(e.comment.comment), comment);

	err = "failed to append iptables entry";
	if (!iptc_append_entry(g_iptables_chain, &e.entry, h))
		goto out;
	err = "failed to commit iptables changes";
	if (!iptc_commit(h))
		goto out;

	ret = 0;

out:
	iptc_free(h);
out2:
	if (ret)
		ilog(LOG_ERROR, "Error altering iptables (for '" STR_FORMAT "'): %s (%s)",
				STR_FMT(comment), err, strerror(errno));

	return ret;
}
