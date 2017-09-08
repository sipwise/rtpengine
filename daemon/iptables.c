#include "iptables.h"
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <libiptc/libiptc.h>
#include <libiptc/libxtc.h>
#include <linux/netfilter/xt_comment.h>
#include <glib.h>
#include "aux.h"
#include "log.h"
#include "socket.h"

#undef __ALIGN_KERNEL
#define __ALIGN_KERNEL(x, a)		__ALIGN_KERNEL_MASK(x, (__typeof(x))(a) - 1)
#define __ALIGN_KERNEL_MASK(x, mask)	(((x) + (mask)) & ~(mask))
#undef XT_ALIGN
#define XT_ALIGN(s) __ALIGN_KERNEL((s), __alignof__(struct _xt_align))

int iptables_add_rule(const char *chain) {
	struct xtc_handle *h;
	struct _e {
		struct ipt_entry entry;
		struct xt_entry_match udp_match;
		struct xt_udp udp;
		struct xt_entry_match comment_match;
		struct xt_comment_info comment;
		struct xt_standard_target target;
	} e;
	int ret;

	h = iptc_init("filter");
	if (!h)
		return -1;

	ZERO(e);

	e.entry.ip.dst.s_addr = 0x01020304;
	e.entry.ip.dmsk.s_addr = 0xffffffff;

	e.target.target.u.user.target_size = XT_ALIGN(sizeof(struct xt_standard_target));
	strcpy(e.target.target.u.user.name, "ACCEPT");

	e.entry.target_offset = G_STRUCT_OFFSET(struct _e, target);
	e.entry.next_offset = e.entry.target_offset + e.target.target.u.user.target_size;

	strcpy(e.udp_match.u.user.name, "udp");
	e.udp_match.u.match_size = XT_ALIGN(sizeof(struct xt_entry_match)) + XT_ALIGN(sizeof(struct xt_udp));
	e.udp.dpts[0] = e.udp.dpts[1] = 4321;
	e.udp.spts[0] = 0;
	e.udp.spts[1] = 0xffff;

	strcpy(e.comment_match.u.user.name, "comment");
	e.comment_match.u.match_size = XT_ALIGN(sizeof(struct xt_entry_match))
		+ XT_ALIGN(sizeof(struct xt_comment_info));
	strcpy(e.comment.comment, "testing");

	e.entry.ip.proto = IPPROTO_UDP;
	e.entry.ip.dst.s_addr = 0x1020304;
	e.entry.ip.dmsk.s_addr= 0xffffffff;

	ret = -1;
	if (!iptc_append_entry(chain, &e.entry, h))
		goto out;
	if (!iptc_commit(h))
		goto out;

	ret = 0;

out:
	iptc_free(h);
	return ret;
}
