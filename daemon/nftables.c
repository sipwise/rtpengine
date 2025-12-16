#include "nftables.h"

#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables_compat.h>
#include <linux/netfilter/nf_tables.h>

#include "netfilter_api.h"
#include "helpers.h"

#include "nft_rtpengine.h"

#define HANDLER_COMMENT "rtpengine UDP handler"

struct iterate_callbacks {
	// called for each expression
	const char *(*parse_expr)(const char *name, const int8_t *data, size_t len, void *userdata);

	// called after all expressions have been parsed
	void (*rule_final)(struct iterate_callbacks *);

	// called after all rules have been iterated
	char *(*iterate_final)(nfapi_socket *nl, int family, const char *chain,
			struct iterate_callbacks *);

	// common arguments
	const char *chain;
	const char *base_chain;
	int table;

	// scratch area for rule callbacks, set to zero for every rule
	struct {
		bool imm_jump_matched;
		bool rtpengine_matched;
		bool have_handle;
		int64_t handle;
		const char *comment;
	} rule_scratch;

	// scratch area for rule iterating
	struct {
		GQueue handles;
		bool have_rtpengine_rule;
		bool have_imm_jump_rule;
	} iterate_scratch;
};

struct add_rule_callbacks {
	const char *(*rule_callback)(nfapi_buf *, int family, struct add_rule_callbacks *);
	const char *chain;
	const char *base_chain;
	int table;
	bool append;
	bool xtables;
};



static const char *match_immediate(const char *name, const int8_t *data, size_t len, void *userdata) {
	struct iterate_callbacks *callbacks = userdata;

	// match jumps to our configured chain
	if (!strcmp(name, "immediate")) {
		const char *chain = nfapi_get_immediate_chain(data, len);
		if (chain && !strcmp(chain, callbacks->chain))
			callbacks->rule_scratch.imm_jump_matched = true;
	}
	return NULL;
}

static const char *match_rtpe(const char *name, const int8_t *data, size_t len, void *userdata) {
	struct iterate_callbacks *callbacks = userdata;

	// match top-level targets
	if (!strcmp(name, "target")) {
		struct xt_rtpengine_info info;
		size_t info_len = sizeof(info);
		const char *n = nfapi_get_target(data, len, &info, &info_len);
		if (n && !strcmp(n, "RTPENGINE") && info_len >= sizeof(info) && info.id == callbacks->table)
			callbacks->rule_scratch.rtpengine_matched = true;
	}
	else if (!strcmp(name, "rtpengine"))
		callbacks->rule_scratch.rtpengine_matched = true;

	return NULL;
}

static const char *match_immediate_rtpe(const char *name, const int8_t *data, size_t len, void *userdata) {
	const char *err = match_immediate(name, data, len, userdata);
	if (err)
		return err;
	return match_rtpe(name, data, len, userdata);
}


static void check_matched_queue(struct iterate_callbacks *callbacks) {
	// handle must be known
	if (!callbacks->rule_scratch.have_handle)
		return;

	// delete rules which:
	//    jump to our handler chain
	//    use the rtpengine statement directly
	//    are the dummy comment rule
	if (!callbacks->rule_scratch.imm_jump_matched && !callbacks->rule_scratch.rtpengine_matched) {
		if (!callbacks->rule_scratch.comment || strcmp(callbacks->rule_scratch.comment, HANDLER_COMMENT))
			return;
	}

	uint64_t handle = callbacks->rule_scratch.handle;
	g_queue_push_tail(&callbacks->iterate_scratch.handles, __g_memdup(&handle, sizeof(handle)));
}


static void check_matched_flag(struct iterate_callbacks *callbacks) {
	if (callbacks->rule_scratch.imm_jump_matched)
		callbacks->iterate_scratch.have_imm_jump_rule = true;
	if (callbacks->rule_scratch.rtpengine_matched)
		callbacks->iterate_scratch.have_rtpengine_rule = true;
}



static void set_handle(int64_t handle, void *data) {
	struct iterate_callbacks *callbacks = data;
	callbacks->rule_scratch.handle = handle;
	callbacks->rule_scratch.have_handle = true;
}

static void set_comment(const char *comment, void *data) {
	struct iterate_callbacks *callbacks = data;
	callbacks->rule_scratch.comment = comment;
}


static const char *nftables_do_rule(const int8_t *b, size_t l, void *data) {
	struct iterate_callbacks *callbacks = data;

	memset(&callbacks->rule_scratch, 0, sizeof(callbacks->rule_scratch));

	const char *err = nfapi_rule_iter(b, l, &(nfapi_callbacks) {
			.expression = callbacks->parse_expr,
			.handle = set_handle,
			.comment = set_comment,
		}, callbacks);
	if (err)
		return err;

	if (callbacks->rule_final)
		callbacks->rule_final(callbacks);

	return NULL;
}


static char *iterate_rules(nfapi_socket *nl, int family, const char *chain,
		struct iterate_callbacks *callbacks)
{
	g_autoptr(nfapi_buf) b = nfapi_buf_new();

	nfapi_add_msg(b, NFT_MSG_GETRULE, family, NLM_F_REQUEST | NLM_F_DUMP, "get all rules [%d]", family);

	nfapi_add_str_attr(b, NFTA_RULE_TABLE, "filter", "table 'filter'");
	nfapi_add_str_attr(b, NFTA_RULE_CHAIN, chain, "chain '%s'", chain);

	if (!nfapi_send_buf(nl, b))
		return g_strdup_printf("failed to write to netlink socket trying to read rules (%s) "
				"(attempted: \"%s\")",
				strerror(errno), nfapi_buf_msg(b));

	const char *err = nfapi_recv_iter(nl, &(nfapi_callbacks) { .rule = nftables_do_rule }, callbacks);
	if (err)
		return g_strdup_printf("error received from netlink socket reading rules (%s): %s "
				"(attempted: \"%s\")",
				strerror(errno), err, nfapi_buf_msg(b));

	if (callbacks->iterate_final) {
		char *e = callbacks->iterate_final(nl, family, chain, callbacks);
		if (e)
			return e;
	}

	return NULL;
}


static void set_rule_handle(nfapi_buf *b, void *data) {
	uint64_t *handle = data;
	nfapi_add_u64_attr(b, NFTA_RULE_HANDLE, *handle, "handle %" PRIu64, *handle);
}



static char *delete_rules(nfapi_socket *nl, int family, const char *chain,
		void (*callback)(nfapi_buf *b, void *data), void *data)
{
	g_autoptr(nfapi_buf) b = nfapi_buf_new();

	nfapi_batch_begin(b);

	nfapi_add_msg(b, NFT_MSG_DELRULE, family, NLM_F_REQUEST | NLM_F_ACK, "delete rule(s) [%d]", family);
	nfapi_add_str_attr(b, NFTA_RULE_TABLE, "filter", "table 'filter'");
	nfapi_add_str_attr(b, NFTA_RULE_CHAIN, chain, "chain '%s'", chain);

	if (callback)
		callback(b, data);

	nfapi_batch_end(b);

	if (!nfapi_send_buf(nl, b))
		return g_strdup_printf("failed to write to netlink socket trying to delete rule (%s) "
				"(attempted: \"%s\")",
				strerror(errno), nfapi_buf_msg(b));

	const char *err = nfapi_recv_iter(nl, NULL, NULL);
	if (err)
		return g_strdup_printf("error received from netlink socket trying to delete rule (%s): %s "
				"(attempted: \"%s\")",
				strerror(errno), err, nfapi_buf_msg(b));

	return NULL;
}



static char *iterate_delete_rules(nfapi_socket *nl, int family, const char *chain,
		struct iterate_callbacks *callbacks)
{
	while (callbacks->iterate_scratch.handles.length) {
		uint64_t *handle = g_queue_pop_head(&callbacks->iterate_scratch.handles);
		// transfer to stack and free
		uint64_t h = *handle;
		g_free(handle);

		char *err = delete_rules(nl, family, chain, set_rule_handle, &h);
		if (err)
			return err;
	}
	return NULL;
}


static const char *local_input_chain(nfapi_buf *b) {
	nfapi_nested_begin(b, NFTA_CHAIN_HOOK, "hook");
	nfapi_add_u32_attr(b, NFTA_HOOK_HOOKNUM, htonl(NF_INET_LOCAL_IN), "hook local-in");
	nfapi_add_u32_attr(b, NFTA_HOOK_PRIORITY, htonl(0), "prio 0");
	nfapi_nested_end(b);

	nfapi_add_u32_attr(b, NFTA_CHAIN_POLICY, htonl(NF_ACCEPT), "policy accept");

	return NULL;
}


static const char *nftables_do_chain(const int8_t *b, size_t l, void *userdata) {
	bool *exists = userdata;
	*exists = true;
	return NULL;
}


static bool chain_exists(nfapi_socket *nl, int family, const char *chain) {
	g_autoptr(nfapi_buf) b = nfapi_buf_new();

	nfapi_add_msg(b, NFT_MSG_GETCHAIN, family, NLM_F_REQUEST | NLM_F_ACK, "get chain [%d]", family);
	nfapi_add_str_attr(b, NFTA_CHAIN_TABLE, "filter", "table 'filter'");
	nfapi_add_str_attr(b, NFTA_CHAIN_NAME, chain, "chain '%s'", chain);

	if (!nfapi_send_buf(nl, b))
		return false;

	bool exists = false;
	const char *err = nfapi_recv_iter(nl, &(nfapi_callbacks) { .chain = nftables_do_chain }, &exists);
	if (err)
		return false;

	return exists;
}


static char *add_chain(nfapi_socket *nl, int family, const char *chain,
		const char *(*callback)(nfapi_buf *))
{
	if (chain_exists(nl, family, chain))
		return NULL;

	g_autoptr(nfapi_buf) b = nfapi_buf_new();

	nfapi_batch_begin(b);

	nfapi_add_msg(b, NFT_MSG_NEWCHAIN, family, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK,
			"create chain [%d]", family);
	nfapi_add_str_attr(b, NFTA_CHAIN_TABLE, "filter", "table 'filter'");
	nfapi_add_str_attr(b, NFTA_CHAIN_NAME, chain, "chain '%s'", chain);

	if (callback) {
		const char *err = callback(b);
		if (err)
			return g_strdup_printf("error returned from callback trying to add chain: %s "
					"(attempted: \"%s\")",
					err, nfapi_buf_msg(b));
	}

	nfapi_batch_end(b);

	if (!nfapi_send_buf(nl, b))
		return g_strdup_printf("failed to write to netlink socket trying to add chain (%s) "
				"(attempted: \"%s\")",
				strerror(errno), nfapi_buf_msg(b));

	const char *err = nfapi_recv_iter(nl, NULL, NULL);
	if (err)
		return g_strdup_printf("error received from netlink socket trying to add chain (%s): %s "
				"(attempted: \"%s\")",
				strerror(errno), err, nfapi_buf_msg(b));

	return NULL;
}


static char *add_rule(nfapi_socket *nl, int family,
		struct add_rule_callbacks callbacks)
{
	g_autoptr(nfapi_buf) b = nfapi_buf_new();

	nfapi_batch_begin(b);

	nfapi_add_msg(b, NFT_MSG_NEWRULE, family,
			NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK | (callbacks.append ? NLM_F_APPEND : 0),
			"%s new rule [%d]", callbacks.append ? "append" : "insert", family);
	nfapi_add_str_attr(b, NFTA_RULE_TABLE, "filter", "table 'filter'");

	const char *err = callbacks.rule_callback(b, family, &callbacks);
	if (err)
		return g_strdup_printf("error returned from callback trying to add table: %s "
				"(attempted: \"%s\")",
				err, nfapi_buf_msg(b));

	nfapi_batch_end(b);

	if (!nfapi_send_buf(nl, b))
		return g_strdup_printf("failed to write to netlink socket trying to add rule (%s) "
				"(attempted: \"%s\")",
				strerror(errno), nfapi_buf_msg(b));

	err = nfapi_recv_iter(nl, NULL, NULL);
	if (err)
		return g_strdup_printf("error received from netlink socket trying to add rule (%s): %s "
				"(attempted: \"%s\")",
				strerror(errno), err, nfapi_buf_msg(b));

	return NULL;
}


static void counter(nfapi_buf *b) {
	// buffer is in the nested expressions

	nfapi_nested_begin(b, NFTA_LIST_ELEM, "element");

		nfapi_add_str_attr(b, NFTA_EXPR_NAME, "counter", "counter");

		nfapi_nested_begin(b, NFTA_EXPR_DATA, "data");

		nfapi_nested_end(b);

	nfapi_nested_end(b);
}


static const char *udp_filter(nfapi_buf *b, int family) {
	// buffer is in the nested expressions

	static const uint8_t proto = IPPROTO_UDP;

	nfapi_nested_begin(b, NFTA_LIST_ELEM, "element");

		if (family == NFPROTO_INET) {

			nfapi_add_str_attr(b, NFTA_EXPR_NAME, "meta", "meta");

			nfapi_nested_begin(b, NFTA_EXPR_DATA, "data");

				nfapi_add_u32_attr(b, NFTA_META_KEY, htonl(NFT_META_L4PROTO), "l4proto");
				nfapi_add_u32_attr(b, NFTA_META_DREG, htonl(NFT_REG_1), "reg 1");

			nfapi_nested_end(b);
		}
		else {
			nfapi_add_str_attr(b, NFTA_EXPR_NAME, "payload", "meta");

			nfapi_nested_begin(b, NFTA_EXPR_DATA, "data");

				nfapi_add_u32_attr(b, NFTA_PAYLOAD_DREG, htonl(NFT_REG_1), "reg 1");
				nfapi_add_u32_attr(b, NFTA_PAYLOAD_BASE, htonl(NFT_PAYLOAD_NETWORK_HEADER),
						"network header");

				if (family == NFPROTO_IPV4)
					nfapi_add_u32_attr(b, NFTA_PAYLOAD_OFFSET,
							htonl(offsetof(struct iphdr, protocol)),
							"offset %zu", offsetof(struct iphdr, protocol));
				else if (family == NFPROTO_IPV6)
					nfapi_add_u32_attr(b, NFTA_PAYLOAD_OFFSET,
							htonl(offsetof(struct ip6_hdr, ip6_nxt)),
							"offset %zu", offsetof(struct ip6_hdr, ip6_nxt));
				else
					return "unsupported address family for UDP filter";

				nfapi_add_u32_attr(b, NFTA_PAYLOAD_LEN, htonl(sizeof(proto)),
						"len %zu", sizeof(proto));

			nfapi_nested_end(b);
		}

	nfapi_nested_end(b);

	nfapi_nested_begin(b, NFTA_LIST_ELEM, "element");

		nfapi_add_str_attr(b, NFTA_EXPR_NAME, "cmp", "cmp");

		nfapi_nested_begin(b, NFTA_EXPR_DATA, "data");

			nfapi_add_u32_attr(b, NFTA_CMP_SREG, htonl(NFT_REG_1), "reg 1");
			nfapi_add_u32_attr(b, NFTA_CMP_OP, htonl(NFT_CMP_EQ), "eq");

			nfapi_nested_begin(b, NFTA_CMP_DATA, "data");

				nfapi_add_attr(b, NFTA_DATA_VALUE, &proto, sizeof(proto), "%u", proto);

			nfapi_nested_end(b);

		nfapi_nested_end(b);

	nfapi_nested_end(b);

	counter(b);

	return NULL;
}


static const char *input_immediate(nfapi_buf *b, int family, struct add_rule_callbacks *callbacks) {
	nfapi_add_str_attr(b, NFTA_RULE_CHAIN, callbacks->base_chain, "chain '%s'", callbacks->base_chain);

	nfapi_nested_begin(b, NFTA_RULE_EXPRESSIONS, "expr");

		const char *err = udp_filter(b, family);
		if (err)
			return err;

		nfapi_nested_begin(b, NFTA_LIST_ELEM, "element");

			nfapi_add_str_attr(b, NFTA_EXPR_NAME, "immediate", "immediate");

			nfapi_nested_begin(b, NFTA_EXPR_DATA, "data");

				nfapi_add_u32_attr(b, NFTA_IMMEDIATE_DREG, 0, "reg 0");

				nfapi_nested_begin(b, NFTA_IMMEDIATE_DATA, "data");

					nfapi_nested_begin(b, NFTA_DATA_VERDICT, "verdict");

						nfapi_add_u32_attr(b, NFTA_VERDICT_CODE, htonl(NFT_JUMP), "jump");
						nfapi_add_str_attr(b, NFTA_VERDICT_CHAIN, callbacks->chain,
								"chain '%s'", callbacks->chain);

					nfapi_nested_end(b);

				nfapi_nested_end(b);

			nfapi_nested_end(b);

		nfapi_nested_end(b);

	nfapi_nested_end(b);

	return NULL;
}


static const char *target_base_nft_expr(nfapi_buf *b, struct add_rule_callbacks *callbacks) {
	// buffer is in the nested expressions

	nfapi_nested_begin(b, NFTA_LIST_ELEM, "element");

		nfapi_add_str_attr(b, NFTA_EXPR_NAME, "rtpengine", "rtpengine");

		nfapi_nested_begin(b, NFTA_EXPR_DATA, "data");

			nfapi_add_u32_attr(b, RTPEA_RTPENGINE_TABLE, callbacks->table,
					"table %u", callbacks->table);

		nfapi_nested_end(b);

	nfapi_nested_end(b);

	return NULL;
}


static const char *target_base_xt(nfapi_buf *b, struct add_rule_callbacks *callbacks) {
	// buffer is in the nested expressions

	struct xt_rtpengine_info info = { .id = callbacks->table };

	nfapi_nested_begin(b, NFTA_LIST_ELEM, "element");

		nfapi_add_str_attr(b, NFTA_EXPR_NAME, "target", "target");

		nfapi_nested_begin(b, NFTA_EXPR_DATA, "data");

			nfapi_add_str_attr(b, NFTA_TARGET_NAME, "RTPENGINE", "RTPENGINE");
			nfapi_add_u32_attr(b, NFTA_TARGET_REV, htonl(0), "rev 0");
			nfapi_add_attr(b, NFTA_TARGET_INFO, &info, sizeof(info),
					"info table %u", callbacks->table);

		nfapi_nested_end(b);

	nfapi_nested_end(b);

	return NULL;
}


static const char *comment(nfapi_buf *b, int family, struct add_rule_callbacks *callbacks) {
	nfapi_add_str_attr(b, NFTA_RULE_CHAIN, callbacks->chain, "chain '%s'", callbacks->chain);
	nfapi_add_binary_str_attr(b, NFTA_RULE_USERDATA, HANDLER_COMMENT, "comment '%s'", HANDLER_COMMENT);

	nfapi_nested_begin(b, NFTA_RULE_EXPRESSIONS, "expr");

		nfapi_nested_begin(b, NFTA_LIST_ELEM, "element");

			nfapi_add_str_attr(b, NFTA_EXPR_NAME, "immediate", "immediate");

			nfapi_nested_begin(b, NFTA_EXPR_DATA, "data");

				nfapi_add_u32_attr(b, NFTA_IMMEDIATE_DREG, 0, "reg 0");

				nfapi_nested_begin(b, NFTA_IMMEDIATE_DATA, "data");

					nfapi_nested_begin(b, NFTA_DATA_VERDICT, "verdict");

						nfapi_add_u32_attr(b, NFTA_VERDICT_CODE, htonl(NFT_CONTINUE),
								"continue");

					nfapi_nested_end(b);

				nfapi_nested_end(b);

			nfapi_nested_end(b);

		nfapi_nested_end(b);

	nfapi_nested_end(b);

	return NULL;
}


static const char *rtpe_target_base(nfapi_buf *b, struct add_rule_callbacks *callbacks) {
	if (callbacks->xtables)
		return target_base_xt(b, callbacks);
	else
		return target_base_nft_expr(b, callbacks);
}


static const char *rtpe_target(nfapi_buf *b, int family, struct add_rule_callbacks *callbacks) {
	nfapi_add_str_attr(b, NFTA_RULE_CHAIN, callbacks->chain, "chain '%s'", callbacks->chain);

	nfapi_nested_begin(b, NFTA_RULE_EXPRESSIONS, "expr");

		const char *err = rtpe_target_base(b, callbacks);
		if (err)
			return err;

		counter(b);

	nfapi_nested_end(b);

	return NULL;
}


static const char *rtpe_target_filter(nfapi_buf *b, int family, struct add_rule_callbacks *callbacks) {
	nfapi_add_str_attr(b, NFTA_RULE_CHAIN, callbacks->chain, "chain '%s'", callbacks->chain);

	nfapi_nested_begin(b, NFTA_RULE_EXPRESSIONS, "expr");

		const char *err = rtpe_target_base(b, callbacks);
		if (err)
			return err;

		err = udp_filter(b, family);
		if (err)
			return err;

	nfapi_nested_end(b);

	return NULL;
}


static char *delete_chain(nfapi_socket *nl, int family, const char *chain) {
	g_autoptr(nfapi_buf) b = nfapi_buf_new();

	nfapi_batch_begin(b);

	nfapi_add_msg(b, NFT_MSG_DELCHAIN, family, NLM_F_REQUEST | NLM_F_ACK, "delete chain [%d]", family);

	nfapi_add_str_attr(b, NFTA_CHAIN_TABLE, "filter", "table 'filter'");
	nfapi_add_str_attr(b, NFTA_CHAIN_NAME, chain, "chain '%s'", chain);

	nfapi_batch_end(b);

	if (!nfapi_send_buf(nl, b))
		return g_strdup_printf("failed to write to netlink socket trying to delete chain (%s) "
				"(attempted: \"%s\")",
				strerror(errno), nfapi_buf_msg(b));

	const char *err = nfapi_recv_iter(nl, NULL, NULL);
	if (err)
		return g_strdup_printf("error received from netlink socket trying to delete chain (%s): %s "
				"(attempted: \"%s\")",
				strerror(errno), err, nfapi_buf_msg(b));

	return NULL;
}


static char *nftables_shutdown_family(nfapi_socket *nl, int family,
		const char *chain, const char *base_chain, nftables_args *args)
{
	char *err;

	if (!base_chain || strcmp(base_chain, "none")) {
		// clean up rules in legacy `INPUT` chain
		err = iterate_rules(nl, family, "INPUT",
				&(struct iterate_callbacks) {
					.parse_expr = match_immediate_rtpe,
					.chain = chain,
					.rule_final = check_matched_queue,
					.iterate_final = iterate_delete_rules,
					.table = args->table,
				});
		if (err)
			return err;

		// clean up rules in `input` chain
		err = iterate_rules(nl, family, "input",
				&(struct iterate_callbacks) {
					.parse_expr = match_immediate_rtpe,
					.chain = chain,
					.rule_final = check_matched_queue,
					.iterate_final = iterate_delete_rules,
					.table = args->table,
				});
		if (err)
			return err;
	}

	if (base_chain && strcmp(base_chain, "none")) {
		// clean up rules in other base chain chain if any
		err = iterate_rules(nl, family, base_chain,
				&(struct iterate_callbacks) {
					.parse_expr = match_immediate_rtpe,
					.chain = chain,
					.rule_final = check_matched_queue,
					.iterate_final = iterate_delete_rules,
					.table = args->table,
				});
		if (err)
			return err;
	}

	// clear out custom chain if it already exists
	err = delete_rules(nl, family, chain, NULL, NULL);
	if (err) {
		if (errno != ENOENT) // ignore trying to delete stuff that doesn't exist
			return err;
		g_free(err);
	}

	err = delete_chain(nl, family, chain);
	if (err) {
		if (errno != ENOENT && errno != EBUSY) // ignore trying to delete stuff that doesn't exist
			return err;
		g_free(err);
	}

	return NULL;
}


static char *add_table(nfapi_socket *nl, int family) {
	g_autoptr(nfapi_buf) b = nfapi_buf_new();

	nfapi_batch_begin(b);

	nfapi_add_msg(b, NFT_MSG_NEWTABLE, family, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK,
			"create table [%d]", family);
	nfapi_add_str_attr(b, NFTA_TABLE_NAME, "filter", "table 'filter'");

	nfapi_batch_end(b);

	if (!nfapi_send_buf(nl, b))
		return g_strdup_printf("failed to write to netlink socket trying to add table (%s) "
				"(attempted: \"%s\")",
				strerror(errno), nfapi_buf_msg(b));

	const char *err = nfapi_recv_iter(nl, NULL, NULL);
	if (err)
		return g_strdup_printf("error received from netlink socket trying to add table (%s): %s "
				"(attempted: \"%s\")",
				strerror(errno), err, nfapi_buf_msg(b));

	return NULL;
}


static char *nftables_setup_family(nfapi_socket *nl, int family,
		const char *chain, const char *base_chain, nftables_args *args)
{
	char *err = nftables_shutdown_family(nl, family, chain, base_chain, args);
	if (err)
		return err;

	// create the table in case it doesn't exist
	err = add_table(nl, family);
	if (err)
		return err;

	if (base_chain) {
		// add custom chain
		err = add_chain(nl, family, chain, NULL);
		if (err)
			return err;

		if (strcmp(base_chain, "none")) {
			// make sure we have a local input base chain
			err = add_chain(nl, family, base_chain, local_input_chain);
			if (err)
				return err;

			// add jump rule from input base chain to custom chain
			err = add_rule(nl, family, (struct add_rule_callbacks) {
					.rule_callback = input_immediate,
					.chain = chain,
					.base_chain = base_chain,
					.append = args->append,
				});
			if (err)
				return err;
		}

		// add rule for kernel forwarding
		err = add_rule(nl, family, (struct add_rule_callbacks) {
				.rule_callback = rtpe_target,
				.chain = chain,
				.table = args->table,
				.append = args->append,
				.xtables = args->xtables,
			});
		if (err)
			return err;

		// add dummy comment rule to indicate success
		return add_rule(nl, family, (struct add_rule_callbacks) {
				.rule_callback = comment,
				.chain = chain,
				.table = args->table,
				.append = args->append,
			});
	}
	else {
		// create custom base chain
		err = add_chain(nl, family, chain, local_input_chain);
		if (err)
			return err;

		// add rule for kernel forwarding
		err = add_rule(nl, family, (struct add_rule_callbacks) {
				.rule_callback = rtpe_target_filter,
				.chain = chain,
				.table = args->table,
				.append = args->append,
				.xtables = args->xtables,
			});
		if (err)
			return err;

		// add dummy comment rule to indicate success
		return add_rule(nl, family, (struct add_rule_callbacks) {
				.rule_callback = comment,
				.chain = chain,
				.table = args->table,
				.append = args->append,
			});
	}
}


static char *nftables_do(const char *chain, const char *base_chain,
		char *(*do_func)(nfapi_socket *nl, int family,
			const char *chain, const char *base_chain, nftables_args *args),
		nftables_args *args)
{
	if (!chain || !chain[0])
		return NULL;
	if (!base_chain[0])
		base_chain = NULL;

	g_autoptr(nfapi_socket) nl = nfapi_socket_open();
	if (!nl)
		return g_strdup_printf("failed to open netlink socket (%s)", strerror(errno));

	char *err = NULL;

	if (args->family == 0 || args->family == NFPROTO_IPV4)
		err = do_func(nl, NFPROTO_IPV4, chain, base_chain, args);
	if (err)
		return err;

	if (args->family == 0 || args->family == NFPROTO_IPV6)
		err = do_func(nl, NFPROTO_IPV6, chain, base_chain, args);
	if (err)
		return err;

	if (args->family == NFPROTO_INET)
		err = do_func(nl, NFPROTO_INET, chain, base_chain, args);
	if (err)
		return err;

	return NULL;
}


static char *nftables_check_family(nfapi_socket *nl, int family,
		const char *chain, const char *base_chain, nftables_args *args)
{
	// look for our custom module rule in the specified chain

	struct iterate_callbacks callbacks = {
		.parse_expr = match_rtpe,
		.rule_final = check_matched_flag,
		.table = args->table,
	};

	g_free( iterate_rules(nl, family, chain, &callbacks) );

	if (!callbacks.iterate_scratch.have_rtpengine_rule)
		return g_strdup("rtpengine handler rule not found");

	// look for a rule to jump from a base chain to our custom chain

	callbacks = (__typeof__(callbacks)) {
		.parse_expr = match_immediate,
		.chain = chain,
		.rule_final = check_matched_flag,
		.table = args->table,
	};

	g_free( iterate_rules(nl, family, "INPUT", &callbacks) );
	g_free( iterate_rules(nl, family, "input", &callbacks) );

	if (base_chain && strcmp(base_chain, "none"))
		g_free( iterate_rules(nl, family, base_chain, &callbacks) );

	if (!callbacks.iterate_scratch.have_imm_jump_rule) {
		if (base_chain && strcmp(base_chain, "none"))
			return g_strdup_printf("immediate-goto rule not found in 'INPUT' or 'input' or '%s'",
					base_chain);
		else
			return g_strdup("immediate-goto rule not found in 'INPUT' or 'input'");
	}

	return NULL;
}


char *nftables_setup(const char *chain, const char *base_chain, nftables_args args) {
	return nftables_do(chain, base_chain, nftables_setup_family, &args);
}

char *nftables_shutdown(const char *chain, const char *base_chain, nftables_args args) {
	return nftables_do(chain, base_chain, nftables_shutdown_family, &args);
}

int nftables_check(const char *chain, const char *base_chain, nftables_args args) {
	char *err = nftables_do(chain, base_chain, nftables_check_family, &args);
	if (err) {
		printf("Netfilter rules check NOT successful: %s\n", err);
		g_free(err);
		return 1;
	}

	printf("Netfilter rules check SUCCESSFUL\n");
	return 0;
}
