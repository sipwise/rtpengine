#ifndef IPT_RTPPROXY_H
#define IPT_RTPPROXY_H

struct ipt_mediaproxy_info {
	u_int32_t			id;
};

struct mediaproxy_stats {
	u_int64_t			packets;
	u_int64_t			bytes;
	u_int64_t			errors;
};

struct mediaproxy_target_info {
	u_int16_t			target_port;

	u_int32_t			src_ip;
	u_int32_t			dst_ip;
	u_int16_t			src_port;
	u_int16_t			dst_port;

	u_int32_t			mirror_ip;
	u_int16_t			mirror_port;

	unsigned char			tos;
};

struct mediaproxy_message {
	enum {
		MMG_NOOP = 1,
		MMG_ADD,
		MMG_DEL,
		MMG_UPDATE,
	}				cmd;

	struct mediaproxy_target_info	target;
};

struct mediaproxy_list_entry {
	struct mediaproxy_target_info	target;
	struct mediaproxy_stats		stats;
};

#ifdef __KERNEL__

struct mediaproxy_target {
	atomic_t			refcnt;
	u_int32_t			table;
	struct mediaproxy_target_info	target;

	spinlock_t			lock;
	struct mediaproxy_stats		stats;
};

struct mediaproxy_table {
	atomic_t			refcnt;
	rwlock_t			target_lock;
	pid_t				pid;

	u_int32_t			id;
	struct proc_dir_entry		*proc;
	struct proc_dir_entry		*status;
	struct proc_dir_entry		*control;
	struct proc_dir_entry		*list;
	struct proc_dir_entry		*blist;

	struct mediaproxy_target	**target[256];

	unsigned int			buckets;
	unsigned int			targets;
};

#endif

#endif
