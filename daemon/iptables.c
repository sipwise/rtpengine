#include "iptables.h"
#include "main.h"
#include "str.h"

int (*iptables_add_rule)(const socket_t *local_sock, const str *comment);
int (*iptables_del_rule)(const socket_t *local_sock);

#ifdef WITH_IPTABLES_OPTION

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <libiptc/libiptc.h>
#include <libiptc/libip6tc.h>
#include <libiptc/libxtc.h>
#include <linux/netfilter/xt_comment.h>
#include <glib.h>
#include <errno.h>
#include <sys/file.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "helpers.h"
#include "log.h"
#include "socket.h"

#undef __ALIGN_KERNEL
#define __ALIGN_KERNEL(x, a)		__ALIGN_KERNEL_MASK(x, (__typeof(x))(a) - 1)
#define __ALIGN_KERNEL_MASK(x, mask)	(((x) + (mask)) & ~(mask))
#undef XT_ALIGN
#define XT_ALIGN(s) __ALIGN_KERNEL((s), __alignof__(struct _xt_align))

#ifndef XT_LOCK_NAME
#define XT_LOCK_NAME	"/run/xtables.lock"
#endif


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


static mutex_t __xt_lock = MUTEX_STATIC_INIT;
static int __xt_lock_fd = -1;



static void xt_lock(void) {
	mutex_lock(&__xt_lock);

	__xt_lock_fd = open(XT_LOCK_NAME, O_CREAT, 0600);
	if (__xt_lock_fd == -1) {
		ilog(LOG_WARN, "Could not open xtables lock file '%s': %s", XT_LOCK_NAME, strerror(errno));
		// as per iptables source code, continue anyway
		return;
	}

	if (flock(__xt_lock_fd, LOCK_EX)) {
		ilog(LOG_WARN, "Failed to acquire lock file '%s': %s", XT_LOCK_NAME, strerror(errno));
		close(__xt_lock_fd);
		__xt_lock_fd = -1;
	}
}

static void xt_unlock(void) {
	if (__xt_lock_fd != -1)
		close(__xt_lock_fd);
	__xt_lock_fd = -1; // coverity[missing_lock : FALSE]
	mutex_unlock(&__xt_lock);
}

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

	matches->comment_match.u.match_size = XT_ALIGN(sizeof(struct xt_entry_match))
		+ XT_ALIGN(sizeof(struct xt_comment_info));
	strcpy(matches->comment_match.u.user.name, "comment");
	if (comment)
		str_ncpy(matches->comment.comment, sizeof(matches->comment.comment), comment);
}

static void ip4_fill_entry(struct ipv4_ipt_entry *entry, const socket_t *local_sock, const str *comment) {
	ZERO(*entry);
	entry->entry.ip.proto = IPPROTO_UDP;
	entry->entry.ip.dst = local_sock->local.address.ipv4;
	memset(&entry->entry.ip.dmsk, 0xff, sizeof(entry->entry.ip.dmsk));
	entry->entry.target_offset = G_STRUCT_OFFSET(struct ipv4_ipt_entry, matches.target);

	ip46tables_fill_matches(&entry->matches, local_sock, comment);

	entry->entry.next_offset = entry->entry.target_offset + entry->matches.target.target.u.user.target_size;
}
static void ip6_fill_entry(struct ipv6_ipt_entry *entry, const socket_t *local_sock, const str *comment) {
	ZERO(*entry);
	entry->entry.ipv6.proto = IPPROTO_UDP;
	entry->entry.ipv6.dst = local_sock->local.address.ipv6;
	entry->entry.ipv6.flags |= IP6T_F_PROTO;
	memset(&entry->entry.ipv6.dmsk, 0xff, sizeof(entry->entry.ipv6.dmsk));
	entry->entry.target_offset = G_STRUCT_OFFSET(struct ipv6_ipt_entry, matches.target);

	ip46tables_fill_matches(&entry->matches, local_sock, comment);

	entry->entry.next_offset = entry->entry.target_offset + entry->matches.target.target.u.user.target_size;
}

static const char *ip4tables_add_rule(const socket_t *local_sock, const str *comment) {
	struct xtc_handle *h;
	struct ipv4_ipt_entry entry;
	const char *err;

	xt_lock();

	err = "could not initialize iptables";
	h = iptc_init("filter");
	if (!h)
		goto err2;

	ip4_fill_entry(&entry, local_sock, comment);

	err = "failed to append iptables entry";
	if (!iptc_append_entry(rtpe_config.iptables_chain, &entry.entry, h))
		goto err;
	err = "failed to commit iptables changes";
	if (!iptc_commit(h))
		goto err;

	err = NULL;

err:
	iptc_free(h);
err2:
	xt_unlock();
	return err;
}

static const char *ip6tables_add_rule(const socket_t *local_sock, const str *comment) {
	struct xtc_handle *h;
	struct ipv6_ipt_entry entry;
	const char *err;

	xt_lock();

	err = "could not initialize ip6tables";
	h = ip6tc_init("filter");
	if (!h)
		goto err2;

	ip6_fill_entry(&entry, local_sock, comment);

	err = "failed to append ip6tables entry";
	if (!ip6tc_append_entry(rtpe_config.iptables_chain, &entry.entry, h))
		goto err;
	err = "failed to commit ip6tables changes";
	if (!ip6tc_commit(h))
		goto err;

	err = NULL;

err:
	ip6tc_free(h);
err2:
	xt_unlock();
	return err;
}

static const char *ip4tables_del_rule(const socket_t *local_sock) {
	struct xtc_handle *h;
	struct ipv4_ipt_entry entry, mask;
	const char *err;

	xt_lock();

	err = "could not initialize iptables";
	h = iptc_init("filter");
	if (!h)
		goto err2;

	ip4_fill_entry(&entry, local_sock, NULL);

	// match everything except the comment
	memset(&mask, 0, sizeof(mask));
	memset(&mask.entry, 0xff, sizeof(mask.entry));
	memset(&mask.matches.udp_match, 0xff, sizeof(mask.matches.udp_match));
	memset(&mask.matches.udp, 0xff, sizeof(mask.matches.udp));
	memset(&mask.matches.comment_match, 0xff, sizeof(mask.matches.comment_match));
	memset(&mask.matches.target, 0xff, sizeof(mask.matches.target));

	err = "failed to delete iptables entry";
	if (!iptc_delete_entry(rtpe_config.iptables_chain, &entry.entry, (unsigned char *) &mask, h))
		goto err;
	err = "failed to commit iptables changes";
	if (!iptc_commit(h))
		goto err;

	err = NULL;

err:
	iptc_free(h);
err2:
	xt_unlock();
	return err;
}

static const char *ip6tables_del_rule(const socket_t *local_sock) {
	struct xtc_handle *h;
	struct ipv6_ipt_entry entry, mask;
	const char *err;

	xt_lock();

	err = "could not initialize ip6tables";
	h = ip6tc_init("filter");
	if (!h)
		goto err2;

	ip6_fill_entry(&entry, local_sock, NULL);

	// match everything except the comment
	memset(&mask, 0, sizeof(mask));
	memset(&mask.entry, 0xff, sizeof(mask.entry));
	memset(&mask.matches.udp_match, 0xff, sizeof(mask.matches.udp_match));
	memset(&mask.matches.udp, 0xff, sizeof(mask.matches.udp));
	memset(&mask.matches.comment_match, 0xff, sizeof(mask.matches.comment_match));
	memset(&mask.matches.target, 0xff, sizeof(mask.matches.target));

	err = "failed to delete ip6tables entry";
	if (!ip6tc_delete_entry(rtpe_config.iptables_chain, &entry.entry, (unsigned char *) &mask, h))
		goto err;
	err = "failed to commit ip6tables changes";
	if (!ip6tc_commit(h))
		goto err;

	err = NULL;

err:
	ip6tc_free(h);
err2:
	xt_unlock();
	return err;
}

static int __iptables_add_rule(const socket_t *local_sock, const str *comment) {
	const char *err;

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
		ilog(LOG_ERROR, "Error adding iptables rule (for '" STR_FORMAT_M "'): %s (%s)",
				STR_FMT_M(comment), err, strerror(errno));

	return 0;
}


static int __iptables_del_rule(const socket_t *local_sock) {
	const char *err;

	if (!local_sock || !local_sock->family)
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
}

#endif // WITH_IPTABLES_OPTION

static int __iptables_stub(void) {
	return 0;
}


void iptables_init(void) {
	if (rtpe_config.iptables_chain && !rtpe_config.iptables_chain[0])
		rtpe_config.iptables_chain = NULL;

	if (!rtpe_config.iptables_chain) {
		iptables_add_rule = (void *) __iptables_stub;
		iptables_del_rule = (void *) __iptables_stub;
		return;
	}

#ifdef WITH_IPTABLES_OPTION

	iptables_add_rule = __iptables_add_rule;
	iptables_del_rule = __iptables_del_rule;

	// flush chains

	const char *err;
	struct xtc_handle *h;

	xt_lock();

	err = "could not initialize iptables";
	h = iptc_init("filter");
	if (!h)
		goto out;
	err = "could not flush iptables chain";
	if (!iptc_flush_entries(rtpe_config.iptables_chain, h))
		goto err2;
	err = "could not commit iptables changes";
	if (!iptc_commit(h))
		goto err2;
	iptc_free(h);

	err = "could not initialize ip6tables";
	h = ip6tc_init("filter");
	if (!h)
		goto out;
	err = "could not flush ip6tables chain";
	if (!ip6tc_flush_entries(rtpe_config.iptables_chain, h))
		goto err1;
	err = "could not commit iptables changes";
	if (!ip6tc_commit(h))
		goto err1;
	ip6tc_free(h);

	err = NULL;
	goto out;

err1:
	ip6tc_free(h);
	goto out;
err2:
	iptc_free(h);
	goto out;
out:
	xt_unlock();
	if (err)
		ilog(LOG_ERROR, "Failed to flush iptables chain: %s (%s)", err, strerror(errno));

#endif // WITH_IPTABLES_OPTION

}
