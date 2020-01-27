#include <linux/types.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/version.h>
#include <linux/err.h>
#include <linux/crypto.h>
#include <crypto/aes.h>
#include <crypto/hash.h>
#include <net/icmp.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/tcp.h>
#include <net/route.h>
#include <net/dst.h>
#include <linux/proc_fs.h>
#include <linux/spinlock.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
#include <linux/bsearch.h>
#endif
#include <asm/atomic.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/netfilter/x_tables.h>
#include <linux/crc32.h>
#ifndef __RE_EXTERNAL
#include <linux/netfilter/xt_RTPENGINE.h>
#else
#include "xt_RTPENGINE.h"
#endif

#include "rtpengine_config.h"

MODULE_LICENSE("GPL");




#define MAX_ID 64 /* - 1 */
#define MAX_SKB_TAIL_ROOM (sizeof(((struct rtpengine_srtp *) 0)->mki) + 20)

#define MIPF		"%i:%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x:%u"
#define MIPP(x)		(x).family,		\
			(x).u.u8[0],		\
			(x).u.u8[1],		\
			(x).u.u8[2],		\
			(x).u.u8[3],		\
			(x).u.u8[4],		\
			(x).u.u8[5],		\
			(x).u.u8[6],		\
			(x).u.u8[7],		\
			(x).u.u8[8],		\
			(x).u.u8[9],		\
			(x).u.u8[10],		\
			(x).u.u8[11],		\
			(x).u.u8[12],		\
			(x).u.u8[13],		\
			(x).u.u8[14],		\
			(x).u.u8[15],		\
			(x).port

#if 0
#define DBG(fmt, ...) printk(KERN_DEBUG "[PID %i line %i] " fmt, current ? current->pid : -1, \
		__LINE__, ##__VA_ARGS__)
#else
#define DBG(x...) ((void)0)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
#define xt_action_param xt_target_param
#endif

#if 0
#define _s_lock(l, f) do {								\
		printk(KERN_DEBUG "[PID %i %s:%i] acquiring lock %s\n",			\
			current ? current->pid : -1,					\
				__FUNCTION__, __LINE__, #l);				\
		spin_lock_irqsave(l, f);						\
		printk(KERN_DEBUG "[PID %i %s:%i] has acquired lock %s\n",		\
			current ? current->pid : -1,					\
				__FUNCTION__, __LINE__, #l);				\
	} while (0)
#define _s_unlock(l, f) do {								\
		printk(KERN_DEBUG "[PID %i %s:%i] is unlocking %s\n",			\
			current ? current->pid : -1,					\
				__FUNCTION__, __LINE__, #l);				\
		spin_unlock_irqrestore(l, f);						\
		printk(KERN_DEBUG "[PID %i %s:%i] has released lock %s\n",		\
			current ? current->pid : -1,					\
				__FUNCTION__, __LINE__, #l);				\
	} while (0)
#define _r_lock(l, f) do {								\
		printk(KERN_DEBUG "[PID %i %s:%i] acquiring read lock %s\n",		\
			current ? current->pid : -1,					\
				__FUNCTION__, __LINE__, #l);				\
		read_lock_irqsave(l, f);						\
		printk(KERN_DEBUG "[PID %i %s:%i] has acquired read lock %s\n",		\
			current ? current->pid : -1,					\
				__FUNCTION__, __LINE__, #l);				\
	} while (0)
#define _r_unlock(l, f) do {								\
		printk(KERN_DEBUG "[PID %i %s:%i] is read unlocking %s\n",		\
			current ? current->pid : -1,					\
				__FUNCTION__, __LINE__, #l);				\
		read_unlock_irqrestore(l, f);						\
		printk(KERN_DEBUG "[PID %i %s:%i] has released read lock %s\n",		\
			current ? current->pid : -1,					\
				__FUNCTION__, __LINE__, #l);				\
	} while (0)
#define _w_lock(l, f) do {								\
		printk(KERN_DEBUG "[PID %i %s:%i] acquiring write lock %s\n",		\
			current ? current->pid : -1,					\
				__FUNCTION__, __LINE__, #l);				\
		write_lock_irqsave(l, f);						\
		printk(KERN_DEBUG "[PID %i %s:%i] has acquired write lock %s\n",	\
			current ? current->pid : -1,					\
				__FUNCTION__, __LINE__, #l);				\
	} while (0)
#define _w_unlock(l, f) do {								\
		printk(KERN_DEBUG "[PID %i %s:%i] is write unlocking %s\n",		\
			current ? current->pid : -1, 					\
				__FUNCTION__, __LINE__, #l);				\
		write_unlock_irqrestore(l, f);						\
		printk(KERN_DEBUG "[PID %i %s:%i] has released write lock %s\n",	\
			current ? current->pid : -1, 					\
				__FUNCTION__, __LINE__, #l);				\
	} while (0)
#else
#define _s_lock(l, f) spin_lock_irqsave(l, f)
#define _s_unlock(l, f) spin_unlock_irqrestore(l, f)
#define _r_lock(l, f) read_lock_irqsave(l, f)
#define _r_unlock(l, f) read_unlock_irqrestore(l, f)
#define _w_lock(l, f) write_lock_irqsave(l, f)
#define _w_unlock(l, f) write_unlock_irqrestore(l, f)
#endif



#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
#define PDE_DATA(i) (PDE(i)->data)
#endif




struct re_hmac;
struct re_cipher;
struct rtp_parsed;
struct re_crypto_context;
struct re_auto_array;
struct re_call;
struct re_stream;
struct rtpengine_table;



#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
static kuid_t proc_kuid;
static uint proc_uid = 0;
module_param(proc_uid, uint, 0);
MODULE_PARM_DESC(proc_uid, "rtpengine procfs tree user id");


static kgid_t proc_kgid;
static uint proc_gid = 0;
module_param(proc_gid, uint, 0);
MODULE_PARM_DESC(proc_gid, "rtpengine procfs tree group id");
#endif

static uint stream_packets_list_limit = 10;
module_param(stream_packets_list_limit, uint, 0);
MODULE_PARM_DESC(stream_packets_list_limit, "maximum number of packets to retain for intercept streams");

static bool log_errors = 0;
module_param(log_errors, bool, 0);
MODULE_PARM_DESC(log_errors, "generate kernel log lines from forwarding errors");



#define log_err(fmt, ...) do { if (log_errors) printk(KERN_NOTICE "rtpengine[%s:%i]: " fmt, \
		__FUNCTION__, __LINE__, ##__VA_ARGS__); } while (0)




static ssize_t proc_control_read(struct file *, char __user *, size_t, loff_t *);
static ssize_t proc_control_write(struct file *, const char __user *, size_t, loff_t *);
static int proc_control_open(struct inode *, struct file *);
static int proc_control_close(struct inode *, struct file *);

static ssize_t proc_status(struct file *, char __user *, size_t, loff_t *);

static ssize_t proc_main_control_write(struct file *, const char __user *, size_t, loff_t *);

static int proc_generic_open_modref(struct inode *, struct file *);
static int proc_generic_close_modref(struct inode *, struct file *);
static int proc_generic_seqrelease_modref(struct inode *inode, struct file *file);

static int proc_list_open(struct inode *, struct file *);

static void *proc_list_start(struct seq_file *, loff_t *);
static void proc_list_stop(struct seq_file *, void *);
static void *proc_list_next(struct seq_file *, void *, loff_t *);
static int proc_list_show(struct seq_file *, void *);

static int proc_blist_open(struct inode *, struct file *);
static int proc_blist_close(struct inode *, struct file *);
static ssize_t proc_blist_read(struct file *, char __user *, size_t, loff_t *);

static int proc_main_list_open(struct inode *, struct file *);

static void *proc_main_list_start(struct seq_file *, loff_t *);
static void proc_main_list_stop(struct seq_file *, void *);
static void *proc_main_list_next(struct seq_file *, void *, loff_t *);
static int proc_main_list_show(struct seq_file *, void *);

static int proc_stream_open(struct inode *i, struct file *f);
static int proc_stream_close(struct inode *i, struct file *f);
static ssize_t proc_stream_read(struct file *f, char __user *b, size_t l, loff_t *o);
static unsigned int proc_stream_poll(struct file *f, struct poll_table_struct *p);

static void table_put(struct rtpengine_table *);
static struct rtpengine_target *get_target(struct rtpengine_table *, const struct re_address *);
static int is_valid_address(const struct re_address *rea);

static int aes_f8_session_key_init(struct re_crypto_context *, struct rtpengine_srtp *);
static int srtp_encrypt_aes_cm(struct re_crypto_context *, struct rtpengine_srtp *,
		struct rtp_parsed *, u_int64_t);
static int srtp_encrypt_aes_f8(struct re_crypto_context *, struct rtpengine_srtp *,
		struct rtp_parsed *, u_int64_t);

static void call_put(struct re_call *call);
static void del_stream(struct re_stream *stream, struct rtpengine_table *);
static void del_call(struct re_call *call, struct rtpengine_table *);

static inline int bitfield_set(unsigned long *bf, unsigned int i);
static inline int bitfield_clear(unsigned long *bf, unsigned int i);






struct re_crypto_context {
	spinlock_t			lock; /* protects roc and last_index */
	unsigned char			session_key[32];
	unsigned char			session_salt[14];
	unsigned char			session_auth_key[20];
	u_int32_t			roc;
	struct crypto_cipher		*tfm[2];
	struct crypto_shash		*shash;
	const struct re_cipher		*cipher;
	const struct re_hmac		*hmac;
};

struct rtpengine_stats_a {
	atomic64_t			packets;
	atomic64_t			bytes;
	atomic64_t			errors;
	u_int64_t			delay_min;
	u_int64_t			delay_avg;
	u_int64_t			delay_max;
	atomic_t          in_tos;
};
struct rtpengine_rtp_stats_a {
	atomic64_t			packets;
	atomic64_t			bytes;
};
struct rtpengine_target {
	atomic_t			refcnt;
	u_int32_t			table;
	struct rtpengine_target_info	target;

	struct rtpengine_stats_a	stats;
	struct rtpengine_rtp_stats_a	rtp_stats[NUM_PAYLOAD_TYPES];

	struct re_crypto_context	decrypt;
	struct re_crypto_context	encrypt;
};

struct re_bitfield {
	unsigned long			b[256 / (sizeof(unsigned long) * 8)];
	unsigned int			used;
};

struct re_bucket {
	struct re_bitfield		ports_lo_bf;
	struct rtpengine_target		*ports_lo[256];
};

struct re_dest_addr {
	struct re_address		destination;
	struct re_bitfield		ports_hi_bf;
	struct re_bucket		*ports_hi[256];
};

struct re_dest_addr_hash {
	struct re_bitfield		addrs_bf;
	struct re_dest_addr		*addrs[256];
};

struct re_auto_array_free_list {
	struct list_head		list_entry;
	unsigned int			index;
};
struct re_auto_array {
	rwlock_t			lock;

	void				**array;
	unsigned int			array_len;
	unsigned long			*used_bitfield;
	struct list_head		free_list;
};

struct re_call {
	atomic_t			refcnt;
	struct rtpengine_call_info	info;
	unsigned int			table_id;
	u32				hash_bucket;
	int				deleted; /* protected by calls.lock */

	struct proc_dir_entry		*root;

	struct list_head		table_entry; /* protected by calls.lock */
	struct hlist_node		calls_hash_entry;

	struct list_head		streams; /* protected by streams.lock */
};

struct re_stream_packet {
	struct list_head		list_entry;
	unsigned int			buflen;
	struct sk_buff			*skbuf;
	unsigned char			buf[];
};

struct re_stream {
	atomic_t			refcnt;
	struct rtpengine_stream_info	info;
	u32				hash_bucket;

	struct proc_dir_entry		*file;
	struct re_call			*call; /* holds a reference */

	struct list_head		call_entry; /* protected by streams.lock */
	struct hlist_node		streams_hash_entry;

	spinlock_t			packet_list_lock;
	struct list_head		packet_list;
	unsigned int			list_count;
	wait_queue_head_t		read_wq;
	wait_queue_head_t		close_wq;
	int				eof; /* protected by packet_list_lock */
};

#define RE_HASH_BITS 8 /* make configurable? */
struct rtpengine_table {
	atomic_t			refcnt;
	rwlock_t			target_lock;
	pid_t				pid;

	unsigned int			id;
	struct proc_dir_entry		*proc_root;
	struct proc_dir_entry		*proc_status;
	struct proc_dir_entry		*proc_control;
	struct proc_dir_entry		*proc_list;
	struct proc_dir_entry		*proc_blist;
	struct proc_dir_entry		*proc_calls;

	struct re_dest_addr_hash	dest_addr_hash;

	unsigned int			num_targets;

	struct list_head		calls; /* protected by calls.lock */

	spinlock_t			calls_hash_lock[1 << RE_HASH_BITS];
	struct hlist_head		calls_hash[1 << RE_HASH_BITS];
	spinlock_t			streams_hash_lock[1 << RE_HASH_BITS];
	struct hlist_head		streams_hash[1 << RE_HASH_BITS];
};

struct re_cipher {
	enum rtpengine_cipher		id;
	const char			*name;
	const char			*tfm_name;
	int				(*decrypt)(struct re_crypto_context *, struct rtpengine_srtp *,
			struct rtp_parsed *, u_int64_t);
	int				(*encrypt)(struct re_crypto_context *, struct rtpengine_srtp *,
			struct rtp_parsed *, u_int64_t);
	int				(*session_key_init)(struct re_crypto_context *, struct rtpengine_srtp *);
};

struct re_hmac {
	enum rtpengine_hmac		id;
	const char			*name;
	const char			*tfm_name;
};

/* XXX shared */
struct rtp_header {
	unsigned char v_p_x_cc;
	unsigned char m_pt;
	u_int16_t seq_num;
	u_int32_t timestamp;
	u_int32_t ssrc;
	u_int32_t csrc[];
} __attribute__ ((packed));
struct rtp_extension {
	u_int16_t undefined;
	u_int16_t length;
} __attribute__ ((packed));


struct rtp_parsed {
	struct rtp_header		*header;
	unsigned int			header_len;
	unsigned char			*payload;
	unsigned int			payload_len;
	int				ok;
};





static struct proc_dir_entry *my_proc_root;
static struct proc_dir_entry *proc_list;
static struct proc_dir_entry *proc_control;

static struct rtpengine_table *table[MAX_ID];
static rwlock_t table_lock;

static struct re_auto_array calls;
static struct re_auto_array streams;








static const struct file_operations proc_control_ops = {
	.owner			= THIS_MODULE,
	.read			= proc_control_read,
	.write			= proc_control_write,
	.open			= proc_control_open,
	.release		= proc_control_close,
};

static const struct file_operations proc_main_control_ops = {
	.owner			= THIS_MODULE,
	.write			= proc_main_control_write,
	.open			= proc_generic_open_modref,
	.release		= proc_generic_close_modref,
};

static const struct file_operations proc_status_ops = {
	.owner			= THIS_MODULE,
	.read			= proc_status,
	.open			= proc_generic_open_modref,
	.release		= proc_generic_close_modref,
};

static const struct file_operations proc_list_ops = {
	.owner			= THIS_MODULE,
	.open			= proc_list_open,
	.read			= seq_read,
	.llseek			= seq_lseek,
	.release		= proc_generic_seqrelease_modref,
};

static const struct file_operations proc_blist_ops = {
	.owner			= THIS_MODULE,
	.open			= proc_blist_open,
	.read			= proc_blist_read,
	.release		= proc_blist_close,
};

static const struct seq_operations proc_list_seq_ops = {
	.start			= proc_list_start,
	.next			= proc_list_next,
	.stop			= proc_list_stop,
	.show			= proc_list_show,
};

static const struct file_operations proc_main_list_ops = {
	.owner			= THIS_MODULE,
	.open			= proc_main_list_open,
	.read			= seq_read,
	.llseek			= seq_lseek,
	.release		= proc_generic_seqrelease_modref,
};

static const struct seq_operations proc_main_list_seq_ops = {
	.start			= proc_main_list_start,
	.next			= proc_main_list_next,
	.stop			= proc_main_list_stop,
	.show			= proc_main_list_show,
};

static const struct file_operations proc_stream_ops = {
	.owner			= THIS_MODULE,
	.read			= proc_stream_read,
	.poll			= proc_stream_poll,
	.open			= proc_stream_open,
	.release		= proc_stream_close,
};

static const struct re_cipher re_ciphers[] = {
	[REC_INVALID] = {
		.id		= REC_INVALID,
		.name		= NULL,
	},
	[REC_NULL] = {
		.id		= REC_NULL,
		.name		= "NULL",
	},
	[REC_AES_CM_128] = {
		.id		= REC_AES_CM_128,
		.name		= "AES-CM-128",
		.tfm_name	= "aes",
		.decrypt	= srtp_encrypt_aes_cm,
		.encrypt	= srtp_encrypt_aes_cm,
	},
	[REC_AES_F8] = {
		.id		= REC_AES_F8,
		.name		= "AES-F8",
		.tfm_name	= "aes",
		.decrypt	= srtp_encrypt_aes_f8,
		.encrypt	= srtp_encrypt_aes_f8,
		.session_key_init = aes_f8_session_key_init,
	},
	[REC_AES_CM_192] = {
		.id		= REC_AES_CM_192,
		.name		= "AES-CM-192",
		.tfm_name	= "aes",
		.decrypt	= srtp_encrypt_aes_cm,
		.encrypt	= srtp_encrypt_aes_cm,
	},
	[REC_AES_CM_256] = {
		.id		= REC_AES_CM_256,
		.name		= "AES-CM-256",
		.tfm_name	= "aes",
		.decrypt	= srtp_encrypt_aes_cm,
		.encrypt	= srtp_encrypt_aes_cm,
	},
};

static const struct re_hmac re_hmacs[] = {
	[REH_INVALID] = {
		.id		= REH_INVALID,
		.name		= NULL,
	},
	[REH_NULL] = {
		.id		= REH_NULL,
		.name		= "NULL",
	},
	[REH_HMAC_SHA1] = {
		.id		= REH_HMAC_SHA1,
		.name		= "HMAC-SHA1",
		.tfm_name	= "hmac(sha1)",
	},
};

static const char *re_msm_strings[] = {
	[MSM_IGNORE]		= "",
	[MSM_DROP]		= "drop",
	[MSM_PROPAGATE]		= "propagate",
};





/* must already be initialized to zero */
static void auto_array_init(struct re_auto_array *a) {
	rwlock_init(&a->lock);
	INIT_LIST_HEAD(&a->free_list);
}

/* lock must be held */
static void set_auto_array_index(struct re_auto_array *a, unsigned int idx, void *ptr) {
	a->array[idx] = ptr;
	bitfield_set(a->used_bitfield, idx);
}
/* lock must be held */
static void auto_array_clear_index(struct re_auto_array *a, unsigned int idx) {
	struct re_auto_array_free_list *fl;

	bitfield_clear(a->used_bitfield, idx);
	a->array[idx] = NULL;

	fl = kmalloc(sizeof(*fl), GFP_ATOMIC);
	if (!fl)
		return;

	DBG("adding %u to free list\n", idx);
	fl->index = idx;
	list_add(&fl->list_entry, &a->free_list);
}
/* lock must be held */
static unsigned int pop_free_list_entry(struct re_auto_array *a) {
	unsigned int ret;
	struct re_auto_array_free_list *fl;

	fl = list_first_entry(&a->free_list, struct re_auto_array_free_list, list_entry);
	ret = fl->index;
	list_del(&fl->list_entry);
	kfree(fl);

	DBG("popped %u from free list\n", ret);
	return ret;
}
static void auto_array_free(struct re_auto_array *a) {

	if (a->array)
		kfree(a->array);
	if (a->used_bitfield)
		kfree(a->used_bitfield);
	while (!list_empty(&a->free_list))
		pop_free_list_entry(a);
}

static struct rtpengine_table *new_table(void) {
	struct rtpengine_table *t;
	unsigned int i;

	DBG("Creating new table\n");

	if (!try_module_get(THIS_MODULE))
		return NULL;

	t = kzalloc(sizeof(*t), GFP_KERNEL);
	if (!t) {
		module_put(THIS_MODULE);
		return NULL;
	}

	atomic_set(&t->refcnt, 1);
	rwlock_init(&t->target_lock);
	INIT_LIST_HEAD(&t->calls);
	t->id = -1;

	for (i = 0; i < ARRAY_SIZE(t->calls_hash); i++) {
		INIT_HLIST_HEAD(&t->calls_hash[i]);
		spin_lock_init(&t->calls_hash_lock[i]);
	}
	for (i = 0; i < ARRAY_SIZE(t->streams_hash); i++) {
		INIT_HLIST_HEAD(&t->streams_hash[i]);
		spin_lock_init(&t->streams_hash_lock[i]);
	}

	return t;
}




static inline void __ref_get(void *p, atomic_t *refcnt) {
	DBG("ref_get(%p) - refcnt is %u\n", p, atomic_read(refcnt));
	atomic_inc(refcnt);
}
#define ref_get(o) __ref_get(o, &(o)->refcnt)





static inline struct proc_dir_entry *proc_mkdir_user(const char *name, umode_t mode,
		struct proc_dir_entry *parent)
{
	struct proc_dir_entry *ret;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
	ret = create_proc_entry(name, S_IFDIR | mode, parent);
#else
	ret = proc_mkdir_mode(name, mode, parent);
#endif
	if (!ret)
		return NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
	proc_set_user(ret, proc_kuid, proc_kgid);
#endif

	return ret;
}
static inline struct proc_dir_entry *proc_create_user(const char *name, umode_t mode,
		struct proc_dir_entry *parent, const struct file_operations *ops,
		void *ptr)
{
	struct proc_dir_entry *ret;

	ret = proc_create_data(name, mode, parent, ops, ptr);
	if (!ret)
		return NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
	proc_set_user(ret, proc_kuid, proc_kgid);
#endif

	return ret;
}



static int table_create_proc(struct rtpengine_table *t, u_int32_t id) {
	char num[10];

	sprintf(num, "%u", id);

	t->proc_root = proc_mkdir_user(num, S_IRUGO | S_IXUGO, my_proc_root);
	if (!t->proc_root)
		return -1;

	t->proc_status = proc_create_user("status", S_IFREG | S_IRUGO, t->proc_root, &proc_status_ops,
		(void *) (unsigned long) id);
	if (!t->proc_status)
		return -1;

	t->proc_control = proc_create_user("control", S_IFREG | S_IWUSR | S_IWGRP | S_IRUSR | S_IRGRP,
			t->proc_root,
			&proc_control_ops, (void *) (unsigned long) id);
	if (!t->proc_control)
		return -1;

	t->proc_list = proc_create_user("list", S_IFREG | S_IRUGO, t->proc_root,
			&proc_list_ops, (void *) (unsigned long) id);
	if (!t->proc_list)
		return -1;

	t->proc_blist = proc_create_user("blist", S_IFREG | S_IRUGO, t->proc_root,
			&proc_blist_ops, (void *) (unsigned long) id);
	if (!t->proc_blist)
		return -1;

	t->proc_calls = proc_mkdir_user("calls", S_IRUGO | S_IXUGO, t->proc_root);
	if (!t->proc_calls)
		return -1;

	return 0;
}




static struct rtpengine_table *new_table_link(u_int32_t id) {
	struct rtpengine_table *t;
	unsigned long flags;

	if (id >= MAX_ID)
		return NULL;

	t = new_table();
	if (!t) {
		printk(KERN_WARNING "xt_RTPENGINE out of memory\n");
		return NULL;
	}

	write_lock_irqsave(&table_lock, flags);
	if (table[id]) {
		write_unlock_irqrestore(&table_lock, flags);
		table_put(t);
		printk(KERN_WARNING "xt_RTPENGINE duplicate ID %u\n", id);
		return NULL;
	}

	ref_get(t);
	table[id] = t;
	t->id = id;
	write_unlock_irqrestore(&table_lock, flags);

	if (table_create_proc(t, id))
		printk(KERN_WARNING "xt_RTPENGINE failed to create /proc entry for ID %u\n", id);


	return t;
}





static void free_crypto_context(struct re_crypto_context *c) {
	int i;

	for (i = 0; i < ARRAY_SIZE(c->tfm); i++) {
		if (c->tfm[i])
			crypto_free_cipher(c->tfm[i]);
	}
	if (c->shash)
		crypto_free_shash(c->shash);
}

static void target_put(struct rtpengine_target *t) {
	if (!t)
		return;

	if (!atomic_dec_and_test(&t->refcnt))
		return;

	DBG("Freeing target\n");

	free_crypto_context(&t->decrypt);
	free_crypto_context(&t->encrypt);

	kfree(t);
}






static void target_get(struct rtpengine_target *t) {
	atomic_inc(&t->refcnt);
}






static void clear_proc(struct proc_dir_entry **e) {
	struct proc_dir_entry *pde;

	if (!e || !(pde = *e))
		return;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
	remove_proc_entry(pde->name, pde->parent);
#else
	proc_remove(pde);
#endif
	*e = NULL;
}





static void clear_table_proc_files(struct rtpengine_table *t) {
	clear_proc(&t->proc_status);
	clear_proc(&t->proc_control);
	clear_proc(&t->proc_list);
	clear_proc(&t->proc_blist);
	clear_proc(&t->proc_calls);
	clear_proc(&t->proc_root);
}

static void table_put(struct rtpengine_table *t) {
	int i, j, k;
	struct re_dest_addr *rda;
	struct re_bucket *b;

	if (!t)
		return;

	if (!atomic_dec_and_test(&t->refcnt))
		return;

	DBG("Freeing table\n");

	for (k = 0; k < 256; k++) {
		rda = t->dest_addr_hash.addrs[k];
		if (!rda)
			continue;

		for (i = 0; i < 256; i++) {
			b = rda->ports_hi[i];
			if (!b)
				continue;

			for (j = 0; j < 256; j++) {
				if (!b->ports_lo[j])
					continue;
				b->ports_lo[j]->table = -1;
				target_put(b->ports_lo[j]);
				b->ports_lo[j] = NULL;
			}

			kfree(b);
			rda->ports_hi[i] = NULL;
		}

		kfree(rda);
		t->dest_addr_hash.addrs[k] = NULL;
	}

	clear_table_proc_files(t);
	kfree(t);

	module_put(THIS_MODULE);
}



/* must be called lock-free */
static inline void free_packet(struct re_stream_packet *packet) {
	if (packet->skbuf)
		kfree_skb(packet->skbuf);
	kfree(packet);
}

/* must be called lock-free */
static void clear_stream_packets(struct re_stream *stream) {
	struct re_stream_packet *packet;
	unsigned long flags;
	LIST_HEAD(delete_list);

	spin_lock_irqsave(&stream->packet_list_lock, flags);

	while (!list_empty(&stream->packet_list)) {
		DBG("clearing packet from queue\n");
		packet = list_first_entry(&stream->packet_list, struct re_stream_packet, list_entry);
		list_del(&packet->list_entry);
		list_add(&packet->list_entry, &delete_list);
	}

	spin_unlock_irqrestore(&stream->packet_list_lock, flags);

	while (!list_empty(&delete_list)) {
		packet = list_first_entry(&delete_list, struct re_stream_packet, list_entry);
		list_del(&packet->list_entry);
		free_packet(packet);
	}
}
static void stream_put(struct re_stream *stream) {
	DBG("stream_put(%p) - refcnt is %u\n",
			stream,
			stream ? atomic_read(&stream->refcnt) : (unsigned) -1);

	if (!stream)
		return;

	if (!atomic_dec_and_test(&stream->refcnt)) {
		/* if this is an open file being closed and there's a del_stream()
		 * waiting for us, we need to wake up the sleeping del_stream() */
		wake_up_interruptible(&stream->close_wq);
		return;
	}

	DBG("Freeing stream object\n");

	clear_stream_packets(stream);
	clear_proc(&stream->file);

	if (stream->call)
		call_put(stream->call);

	kfree(stream);
}
static void call_put(struct re_call *call) {
	DBG("call_put(%p) - refcnt is %u\n",
			call,
			call ? atomic_read(&call->refcnt) : (unsigned) -1);

	if (!call)
		return;

	if (!atomic_dec_and_test(&call->refcnt))
		return;

	DBG("Freeing call object\n");

	if (!list_empty(&call->streams))
		panic("BUG! streams list not empty in call");

	DBG("clearing call proc files\n");
	clear_proc(&call->root);

	kfree(call);
}




static int unlink_table(struct rtpengine_table *t) {
	unsigned long flags;
	struct re_call *call;

	if (t->id >= MAX_ID)
		return -EINVAL;

	DBG("Unlinking table %u\n", t->id);

	write_lock_irqsave(&table_lock, flags);
	if (t->id >= MAX_ID || table[t->id] != t) {
		write_unlock_irqrestore(&table_lock, flags);
		return -EINVAL;
	}
	if (t->pid) {
		write_unlock_irqrestore(&table_lock, flags);
		return -EBUSY;
	}
	table[t->id] = NULL;
	t->id = -1;
	write_unlock_irqrestore(&table_lock, flags);

	_w_lock(&calls.lock, flags);
	while (!list_empty(&t->calls)) {
		call = list_first_entry(&t->calls, struct re_call, table_entry);
		_w_unlock(&calls.lock, flags);
		del_call(call, t); /* removes it from this list */
		_w_lock(&calls.lock, flags);
	}
	_w_unlock(&calls.lock, flags);

	clear_table_proc_files(t);
	table_put(t);

	return 0;
}




static struct rtpengine_table *get_table(unsigned int id) {
	struct rtpengine_table *t;
	unsigned long flags;

	if (id >= MAX_ID)
		return NULL;

	read_lock_irqsave(&table_lock, flags);
	t = table[id];
	if (t)
		ref_get(t);
	read_unlock_irqrestore(&table_lock, flags);

	return t;
}




static ssize_t proc_status(struct file *f, char __user *b, size_t l, loff_t *o) {
	struct inode *inode;
	char buf[256];
	struct rtpengine_table *t;
	int len = 0;
	unsigned long flags;
	u_int32_t id;

	if (*o > 0)
		return 0;
	if (*o < 0)
		return -EINVAL;
	if (l < sizeof(buf))
		return -EINVAL;

	inode = f->f_path.dentry->d_inode;
	id = (u_int32_t) (unsigned long) PDE_DATA(inode);
	t = get_table(id);
	if (!t)
		return -ENOENT;

	read_lock_irqsave(&t->target_lock, flags);
	len += sprintf(buf + len, "Refcount:    %u\n", atomic_read(&t->refcnt) - 1);
	len += sprintf(buf + len, "Control PID: %u\n", t->pid);
	len += sprintf(buf + len, "Targets:     %u\n", t->num_targets);
	read_unlock_irqrestore(&t->target_lock, flags);

	table_put(t);

	if (copy_to_user(b, buf, len))
		return -EFAULT;
	*o += len;

	return len;
}



static int proc_main_list_open(struct inode *i, struct file *f) {
	int err;
	if ((err = proc_generic_open_modref(i, f)))
		return err;
	return seq_open(f, &proc_main_list_seq_ops);
}





static void *proc_main_list_start(struct seq_file *f, loff_t *o) {
	if (!try_module_get(THIS_MODULE))
		return NULL;
	return proc_main_list_next(f, NULL, o);
}

static void proc_main_list_stop(struct seq_file *f, void *v) {
	module_put(THIS_MODULE);
}

static void *proc_main_list_next(struct seq_file *f, void *v, loff_t *o) {	/* v is invalid */
	struct rtpengine_table *t = NULL;
	u_int32_t id;

	if (*o < 0)
		return NULL;
	id = *o;

	while (id < MAX_ID) {
		t = get_table(id++);
		if (!t)
			continue;
		break;
	}

	*o = id;

	return t;	/* might be NULL */
}

static int proc_main_list_show(struct seq_file *f, void *v) {
	struct rtpengine_table *g = v;

	seq_printf(f, "%u\n", g->id);
	table_put(g);

	return 0;
}





static inline unsigned char bitfield_next_slot(unsigned int slot) {
	unsigned char c;
	c = slot * (sizeof(unsigned long) * 8);
	c += sizeof(unsigned long) * 8;
	return c;
}
static inline unsigned int bitfield_slot(unsigned int i) {
	return i / (sizeof(unsigned long) * 8);
}
static inline unsigned int bitfield_bit(unsigned int i) {
	return i % (sizeof(unsigned long) * 8);
}
static inline int bitfield_set(unsigned long *bf, unsigned int i) {
	unsigned int b, m;
	unsigned long k;

	b = bitfield_slot(i);
	m = bitfield_bit(i);
	k = 1UL << m;
	if ((bf[b] & k))
		return 0;
	bf[b] |= k;
	return 1;
}
static inline int bitfield_clear(unsigned long *bf, unsigned int i) {
	unsigned int b, m;
	unsigned long k;

	b = bitfield_slot(i);
	m = bitfield_bit(i);
	k = 1UL << m;
	if (!(bf[b] & k))
		return 0;
	bf[b] &= ~k;
	return 1;
}
static inline void re_bitfield_set(struct re_bitfield *bf, unsigned char i) {
	if (bitfield_set(bf->b, i))
		bf->used++;
}
static inline void re_bitfield_clear(struct re_bitfield *bf, unsigned char i) {
	if (bitfield_clear(bf->b, i))
		bf->used--;
}



static inline struct rtpengine_target *find_next_target(struct rtpengine_table *t, int *addr_bucket,
		int *port)
{
	unsigned long flags;
	struct re_dest_addr *rda;
	struct re_bucket *b;
	unsigned char hi, lo, ab;
	unsigned int rda_b, hi_b, lo_b;
	struct rtpengine_target *g;

	if (*port < 0)
		return NULL;
	if (*port > 0xffff) {
		*port = 0;
		(*addr_bucket)++;
	}
	if (*addr_bucket < 0 || *addr_bucket > 255)
		return NULL;

	hi = (*port & 0xff00) >> 8;
	lo = *port & 0xff;
	ab = *addr_bucket;

	read_lock_irqsave(&t->target_lock, flags);

	for (;;) {
		rda_b = bitfield_slot(ab);
		if (!t->dest_addr_hash.addrs_bf.b[rda_b]) {
			ab = bitfield_next_slot(rda_b);
			hi = 0;
			lo = 0;
			goto next_rda;
		}

		rda = t->dest_addr_hash.addrs[ab];
		if (!rda) {
			ab++;
			hi = 0;
			lo = 0;
			goto next_rda;
		}

		hi_b = bitfield_slot(hi);
		if (!rda->ports_hi_bf.b[hi_b]) {
			hi = bitfield_next_slot(hi_b);
			lo = 0;
			goto next_hi;
		}

		b = rda->ports_hi[hi];
		if (!b) {
			hi++;
			lo = 0;
			goto next_hi;
		}

		lo_b = bitfield_slot(lo);
		if (!b->ports_lo_bf.b[lo_b]) {
			lo = bitfield_next_slot(lo_b);
			goto next_lo;
		}

		g = b->ports_lo[lo];
		if (!g) {
			lo++;
			goto next_lo;
		}

		target_get(g);
		break;

next_lo:
		if (!lo)
			hi++;
next_hi:
		if (!hi && !lo)
			ab++;
next_rda:
		if (!ab && !hi && !lo)
			break;
	}

	read_unlock_irqrestore(&t->target_lock, flags);

	*addr_bucket = ab;
	*port = (hi << 8) | lo;
	(*port)++;

	return g;
}



static int proc_blist_open(struct inode *i, struct file *f) {
	u_int32_t id;
	struct rtpengine_table *t;
	int err;

	if ((err = proc_generic_open_modref(i, f)))
		return err;

	id = (u_int32_t) (unsigned long) PDE_DATA(i);
	t = get_table(id);
	if (!t)
		return -ENOENT;

	table_put(t);

	return 0;
}

static int proc_blist_close(struct inode *i, struct file *f) {
	u_int32_t id;
	struct rtpengine_table *t;

	id = (u_int32_t) (unsigned long) PDE_DATA(i);
	t = get_table(id);
	if (!t)
		return 0;

	table_put(t);

	proc_generic_close_modref(i, f);

	return 0;
}

static ssize_t proc_blist_read(struct file *f, char __user *b, size_t l, loff_t *o) {
	struct inode *inode;
	u_int32_t id;
	struct rtpengine_table *t;
	struct rtpengine_list_entry *opp;
	int err, port, addr_bucket, i;
	struct rtpengine_target *g;
	unsigned long flags;

	if (l != sizeof(*opp))
		return -EINVAL;
	if (*o < 0)
		return -EINVAL;

	inode = f->f_path.dentry->d_inode;
	id = (u_int32_t) (unsigned long) PDE_DATA(inode);
	t = get_table(id);
	if (!t)
		return -ENOENT;

	addr_bucket = ((int) *o) >> 17;
	port = ((int) *o) & 0x1ffff;
	g = find_next_target(t, &addr_bucket, &port);
	*o = (addr_bucket << 17) | port;
	err = 0;
	if (!g)
		goto err;

	opp = kzalloc(sizeof(*opp), GFP_KERNEL);

	memcpy(&opp->target, &g->target, sizeof(opp->target));

	opp->stats.packets = atomic64_read(&g->stats.packets);
	opp->stats.bytes = atomic64_read(&g->stats.bytes);
	opp->stats.errors = atomic64_read(&g->stats.errors);
	opp->stats.delay_min = g->stats.delay_min;
	opp->stats.delay_max = g->stats.delay_max;
	opp->stats.delay_avg = g->stats.delay_avg;
	opp->stats.in_tos = atomic_read(&g->stats.in_tos);

	for (i = 0; i < g->target.num_payload_types; i++) {
		opp->rtp_stats[i].packets = atomic64_read(&g->rtp_stats[i].packets);
		opp->rtp_stats[i].bytes = atomic64_read(&g->rtp_stats[i].bytes);
	}

	spin_lock_irqsave(&g->decrypt.lock, flags);
	opp->target.decrypt.last_index = g->target.decrypt.last_index;
	spin_unlock_irqrestore(&g->decrypt.lock, flags);

	spin_lock_irqsave(&g->encrypt.lock, flags);
	opp->target.encrypt.last_index = g->target.encrypt.last_index;
	spin_unlock_irqrestore(&g->encrypt.lock, flags);

	target_put(g);

	err = -EFAULT;
	if (copy_to_user(b, opp, sizeof(*opp)))
		goto err2;

	table_put(t);
	kfree(opp);
	return l;

err2:
	kfree(opp);
err:
	table_put(t);
	return err;
}

static int proc_list_open(struct inode *i, struct file *f) {
	int err;
	struct seq_file *p;
	u_int32_t id;
	struct rtpengine_table *t;

	if ((err = proc_generic_open_modref(i, f)))
		return err;

	id = (u_int32_t) (unsigned long) PDE_DATA(i);
	t = get_table(id);
	if (!t)
		return -ENOENT;
	table_put(t);

	err = seq_open(f, &proc_list_seq_ops);
	if (err)
		return err;

	p = f->private_data;
	p->private = (void *) (unsigned long) id;

	return 0;
}




static void *proc_list_start(struct seq_file *f, loff_t *o) {
	return proc_list_next(f, NULL, o);
}

static void proc_list_stop(struct seq_file *f, void *v) {
}

static void *proc_list_next(struct seq_file *f, void *v, loff_t *o) {	/* v is invalid */
	u_int32_t id = (u_int32_t) (unsigned long) f->private;
	struct rtpengine_table *t;
	struct rtpengine_target *g;
	int port, addr_bucket;

	addr_bucket = ((int) *o) >> 17;
	port = ((int) *o) & 0x1ffff;

	t = get_table(id);
	if (!t)
		return NULL;

	g = find_next_target(t, &addr_bucket, &port);

	*o = (addr_bucket << 17) | port;
	table_put(t);

	return g;
}

static void seq_addr_print(struct seq_file *f, const struct re_address *a) {
	if (!a->family)
		return;

	switch (a->family) {
		case AF_INET:
			seq_printf(f, "inet4 %u.%u.%u.%u:%u", a->u.u8[0], a->u.u8[1], a->u.u8[2],
					a->u.u8[3], a->port);
			break;
		case AF_INET6:
			seq_printf(f, "inet6 [%x:%x:%x:%x:%x:%x:%x:%x]:%u",
				htons(a->u.u16[0]), htons(a->u.u16[1]),
				htons(a->u.u16[2]), htons(a->u.u16[3]), htons(a->u.u16[4]), htons(a->u.u16[5]),
				htons(a->u.u16[6]), htons(a->u.u16[7]), a->port);
			break;
		default:
			seq_printf(f, "<unknown>\n");
			break;
	}
}

static void proc_list_addr_print(struct seq_file *f, const char *s, const struct re_address *a) {
	if (!a->family)
		return;

	seq_printf(f, "    %6s ", s);
	seq_addr_print(f, a);
	seq_printf(f, "\n");
}

static void proc_list_crypto_print(struct seq_file *f, struct re_crypto_context *c,
		struct rtpengine_srtp *s, const char *label)
{
	int hdr = 0;

	if (c->cipher && c->cipher->id != REC_NULL) {
		if (!hdr++)
			seq_printf(f, "    SRTP %s parameters:\n", label);
		seq_printf(f, "        cipher: %s\n", c->cipher->name ? : "<invalid>");
		if (s->mki_len)
			seq_printf(f, "            MKI: length %u, %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x...\n",
					s->mki_len,
					s->mki[0], s->mki[1], s->mki[2], s->mki[3],
					s->mki[4], s->mki[5], s->mki[6], s->mki[7]);
	}
	if (c->hmac && c->hmac->id != REH_NULL) {
		if (!hdr++)
			seq_printf(f, "    SRTP %s parameters:\n", label);
		seq_printf(f, "        HMAC: %s\n", c->hmac->name ? : "<invalid>");
		seq_printf(f, "            auth tag length: %u\n", s->auth_tag_len);
	}
}

static int proc_list_show(struct seq_file *f, void *v) {
	struct rtpengine_target *g = v;
	int i;

	seq_printf(f, "local ");
	seq_addr_print(f, &g->target.local);
	seq_printf(f, "\n");
	proc_list_addr_print(f, "src", &g->target.src_addr);
	proc_list_addr_print(f, "dst", &g->target.dst_addr);
	proc_list_addr_print(f, "mirror", &g->target.mirror_addr);
	proc_list_addr_print(f, "expect", &g->target.expected_src);
	if (g->target.src_mismatch > 0 && g->target.src_mismatch <= ARRAY_SIZE(re_msm_strings))
		seq_printf(f, "    src mismatch action: %s\n", re_msm_strings[g->target.src_mismatch]);
	seq_printf(f, "    stats: %20llu bytes, %20llu packets, %20llu errors\n",
		(unsigned long long) atomic64_read(&g->stats.bytes),
		(unsigned long long) atomic64_read(&g->stats.packets),
		(unsigned long long) atomic64_read(&g->stats.errors));
	for (i = 0; i < g->target.num_payload_types; i++)
		seq_printf(f, "        RTP payload type %3u: %20llu bytes, %20llu packets\n",
			g->target.payload_types[i],
			(unsigned long long) atomic64_read(&g->rtp_stats[i].bytes),
			(unsigned long long) atomic64_read(&g->rtp_stats[i].packets));
	proc_list_crypto_print(f, &g->decrypt, &g->target.decrypt, "decryption (incoming)");
	proc_list_crypto_print(f, &g->encrypt, &g->target.encrypt, "encryption (outgoing)");
	if (g->target.rtcp_mux)
		seq_printf(f, "    option: rtcp-mux\n");
	if (g->target.dtls)
		seq_printf(f, "    option: dtls\n");
	if (g->target.stun)
		seq_printf(f, "    option: stun\n");
	if (g->target.transcoding)
		seq_printf(f, "    option: transcoding\n");
	if (g->target.non_forwarding)
		seq_printf(f, "    option: non forwarding\n");

	target_put(g);

	return 0;
}




static unsigned int re_address_hash(const struct re_address *a) {
	u_int32_t ret = 0;

	if (!a)
		goto out;

	ret += a->family;

	switch (a->family) {
		case AF_INET:
			ret += a->u.ipv4;
			break;
		case AF_INET6:
			ret += a->u.u32[0];
			ret += a->u.u32[1];
			ret += a->u.u32[2];
			ret += a->u.u32[3];
			break;
		default:
			goto out;
	}

	ret = (ret & 0xffff) ^ ((ret & 0xffff0000) >> 16);
	ret = (ret & 0xff) ^ ((ret & 0xff00) >> 8);

out:
	return ret;
}

static int re_address_match(const struct re_address *a, const struct re_address *b) {
	if (!a || !b)
		return 0;
	if (a->family != b->family)
		return 0;

	switch (a->family) {
		case AF_INET:
			if (a->u.ipv4 == b->u.ipv4)
				return 1;
			break;
		case AF_INET6:
			if (!memcmp(a->u.ipv6, b->u.ipv6, sizeof(a->u.ipv6)))
				return 1;
			break;
		default:
			return 0;
	}

	return 0;
}

static struct re_dest_addr *find_dest_addr(const struct re_dest_addr_hash *h, const struct re_address *local) {
	unsigned int rda_hash, i;
	struct re_dest_addr *rda;

	i = rda_hash = re_address_hash(local);

	while (1) {
		rda = h->addrs[i];
		if (!rda)
			return NULL;
		if (re_address_match(local, &rda->destination))
			return rda;

		i++;
		if (i >= 256)
			i = 0;
		if (i == rda_hash)
			return NULL;
	}
}





static int table_del_target(struct rtpengine_table *t, const struct re_address *local) {
	unsigned char hi, lo;
	struct re_dest_addr *rda;
	struct re_bucket *b;
	struct rtpengine_target *g = NULL;
	unsigned long flags;

	if (!local || !is_valid_address(local))
		return -EINVAL;

	hi = (local->port & 0xff00) >> 8;
	lo = local->port & 0xff;

	write_lock_irqsave(&t->target_lock, flags);

	rda = find_dest_addr(&t->dest_addr_hash, local);
	if (!rda)
		goto out;
	b = rda->ports_hi[hi];
	if (!b)
		goto out;
	g = b->ports_lo[lo];
	if (!g)
		goto out;

	b->ports_lo[lo] = NULL;
	re_bitfield_clear(&b->ports_lo_bf, lo);
	t->num_targets--;
	if (!b->ports_lo_bf.used) {
		rda->ports_hi[hi] = NULL;
		re_bitfield_clear(&rda->ports_hi_bf, hi);
	}
	else
		b = NULL;

	/* not freeing or NULLing the re_dest_addr due to hash collision logic */

out:
	write_unlock_irqrestore(&t->target_lock, flags);

	if (!g)
		return -ENOENT;
	if (b)
		kfree(b);

	target_put(g);

	return 0;
}




static int is_valid_address(const struct re_address *rea) {
	switch (rea->family) {
		case AF_INET:
			if (!rea->u.ipv4)
				return 0;
			break;

		case AF_INET6:
			if (!rea->u.u32[0] && !rea->u.u32[1] && !rea->u.u32[2] && !rea->u.u32[3])
				return 0;
			break;

		default:
			return 0;
	}

	if (!rea->port)
		return 0;

	return 1;
}




static int validate_srtp(struct rtpengine_srtp *s) {
	if (s->cipher <= REC_INVALID)
		return -1;
	if (s->cipher >= __REC_LAST)
		return -1;
	if (s->hmac <= REH_INVALID)
		return -1;
	if (s->hmac >= __REH_LAST)
		return -1;
	if (s->auth_tag_len > 20)
		return -1;
	if (s->mki_len > sizeof(s->mki))
		return -1;
	return 0;
}



/* XXX shared code */
static void aes_ctr(unsigned char *out, const unsigned char *in, int in_len,
		struct crypto_cipher *tfm, const unsigned char *iv)
{
	unsigned char ivx[16];
	unsigned char key_block[16];
	unsigned char *p, *q;
	unsigned int left;
	int i;
	u_int64_t *pi, *qi, *ki;

	if (!tfm)
		return;

	memcpy(ivx, iv, 16);
	pi = (void *) in;
	qi = (void *) out;
	ki = (void *) key_block;
	left = in_len;

	while (left) {
		crypto_cipher_encrypt_one(tfm, key_block, ivx);

		if (unlikely(left < 16)) {
			p = (void *) pi;
			q = (void *) qi;
			for (i = 0; i < 16; i++) {
				*q++ = *p++ ^ key_block[i];
				left--;
				if (!left)
					goto done;
			}
			panic("BUG!");
		}

		*qi++ = *pi++ ^ ki[0];
		*qi++ = *pi++ ^ ki[1];
		left -= 16;

		for (i = 15; i >= 0; i--) {
			ivx[i]++;
			if (likely(ivx[i]))
				break;
		}
	}

done:
	;
}

static void aes_f8(unsigned char *in_out, int in_len,
		struct crypto_cipher *tfm, struct crypto_cipher *iv_tfm,
		const unsigned char *iv)
{
	unsigned char key_block[16], last_key_block[16], /* S(j), S(j-1) */
		      ivx[16], /* IV' */
		      x[16];
	int i, left;
	u_int32_t j;
	unsigned char *p;
	u_int64_t *pi, *ki, *lki, *xi;
	u_int32_t *xu;

	crypto_cipher_encrypt_one(iv_tfm, ivx, iv);

	pi = (void *) in_out;
	ki = (void *) key_block;
	lki = (void *) last_key_block;
	xi = (void *) x;
	xu = (void *) x;
	left = in_len;
	j = 0;
	memset(last_key_block, 0, sizeof(last_key_block));

	while (left) {
		/* S(j) = E(k_e, IV' XOR j XOR S(j-1)) */
		memcpy(x, ivx, 16);

		xu[3] ^= htonl(j);

		xi[0] ^= lki[0];
		xi[1] ^= lki[1];

		crypto_cipher_encrypt_one(tfm, key_block, x);

		if (unlikely(left < 16)) {
			p = (void *) pi;
			for (i = 0; i < 16; i++) {
				*p++ ^= key_block[i];
				left--;
				if (!left)
					goto done;
			}
			panic("BUG!");
		}

		*pi++ ^= ki[0];
		*pi++ ^= ki[1];
		left -= 16;
		if (!left)
			break;

		j++;
		memcpy(last_key_block, key_block, 16);
	}

done:
	;
}

static int aes_ctr_128_no_ctx(unsigned char *out, const char *in, int in_len,
			      const unsigned char *key, unsigned int key_len, const unsigned char *iv)
{
	struct crypto_cipher *tfm;

	tfm = crypto_alloc_cipher("aes", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	crypto_cipher_setkey(tfm, key, key_len);
	aes_ctr(out, in, in_len, tfm, iv);

	crypto_free_cipher(tfm);
	return 0;
}

static int prf_n(unsigned char *out, int len, const unsigned char *key, unsigned int key_len, const unsigned char *x) {
	unsigned char iv[16];
	unsigned char o[32];
	unsigned char in[32];
	int in_len, ret;

	memcpy(iv, x, 14);
	iv[14] = iv[15] = 0;
	in_len = len > 16 ? 32 : 16;
	memset(in, 0, in_len);

	ret = aes_ctr_128_no_ctx(o, in, in_len, key, key_len, iv);
	if (ret)
		return ret;

	memcpy(out, o, len);

	return 0;
}

static int gen_session_key(unsigned char *out, int len, struct rtpengine_srtp *s, unsigned char label) {
	unsigned char key_id[7];
	unsigned char x[14];
	int i, ret;

	memset(key_id, 0, sizeof(key_id));

	key_id[0] = label;

	memcpy(x, s->master_salt, 14);
	for (i = 13 - 6; i < 14; i++)
		x[i] = key_id[i - (13 - 6)] ^ x[i];

	ret = prf_n(out, len, s->master_key, s->master_key_len, x);
	if (ret)
		return ret;
	return 0;
}




static int aes_f8_session_key_init(struct re_crypto_context *c, struct rtpengine_srtp *s) {
	unsigned char m[16];
	int i, ret;

	/* m = k_s || 0x555..5 */
	memcpy(m, c->session_salt, 14);
	m[14] = m[15] = 0x55;
	/* IV' = E(k_e XOR m, IV) */
	for (i = 0; i < 16; i++)
		m[i] ^= c->session_key[i];

	c->tfm[1] = crypto_alloc_cipher("aes", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(c->tfm[1])) {
		ret = PTR_ERR(c->tfm[1]);
		c->tfm[1] = NULL;
		goto error;
	}
	crypto_cipher_setkey(c->tfm[1], m, 16);

	return 0;

error:
	return ret;
}

static int gen_session_keys(struct re_crypto_context *c, struct rtpengine_srtp *s) {
	int ret;
	const char *err;

	if (s->cipher == REC_NULL && s->hmac == REH_NULL)
		return 0;
	err = "failed to generate session key";
	ret = gen_session_key(c->session_key, s->session_key_len, s, 0x00);
	if (ret)
		goto error;
	ret = gen_session_key(c->session_auth_key, 20, s, 0x01);
	if (ret)
		goto error;
	ret = gen_session_key(c->session_salt, 14, s, 0x02);
	if (ret)
		goto error;

	if (c->cipher->tfm_name) {
		err = "failed to load cipher";
		c->tfm[0] = crypto_alloc_cipher(c->cipher->tfm_name, 0, CRYPTO_ALG_ASYNC);
		if (IS_ERR(c->tfm[0])) {
			ret = PTR_ERR(c->tfm[0]);
			c->tfm[0] = NULL;
			goto error;
		}
		crypto_cipher_setkey(c->tfm[0], c->session_key, s->session_key_len);
	}

	if (c->cipher->session_key_init) {
		ret = c->cipher->session_key_init(c, s);
		if (ret)
			goto error;
	}

	if (c->hmac->tfm_name) {
		err = "failed to load HMAC";
		c->shash = crypto_alloc_shash(c->hmac->tfm_name, 0, CRYPTO_ALG_ASYNC);
		if (IS_ERR(c->shash)) {
			ret = PTR_ERR(c->shash);
			c->shash = NULL;
			goto error;
		}
		crypto_shash_setkey(c->shash, c->session_auth_key, 20);
	}

	switch(s->master_key_len) {
	case 16:
		DBG("master key %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
			s->master_key[0], s->master_key[1], s->master_key[2], s->master_key[3],
			s->master_key[4], s->master_key[5], s->master_key[6], s->master_key[7],
			s->master_key[8], s->master_key[9], s->master_key[10], s->master_key[11],
			s->master_key[12], s->master_key[13], s->master_key[14], s->master_key[15]);
		break;
	case 24:
		DBG("master key %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
			s->master_key[0], s->master_key[1], s->master_key[2], s->master_key[3],
			s->master_key[4], s->master_key[5], s->master_key[6], s->master_key[7],
			s->master_key[8], s->master_key[9], s->master_key[10], s->master_key[11],
		        s->master_key[12], s->master_key[13], s->master_key[14], s->master_key[15],
			s->master_key[16], s->master_key[17], s->master_key[18], s->master_key[19],
			s->master_key[20], s->master_key[21], s->master_key[22], s->master_key[23]);
		break;
	case 32:
		DBG("master key %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
			s->master_key[0], s->master_key[1], s->master_key[2], s->master_key[3],
			s->master_key[4], s->master_key[5], s->master_key[6], s->master_key[7],
			s->master_key[8], s->master_key[9], s->master_key[10], s->master_key[11],
		        s->master_key[12], s->master_key[13], s->master_key[14], s->master_key[15],
			s->master_key[16], s->master_key[17], s->master_key[18], s->master_key[19],
			s->master_key[20], s->master_key[21], s->master_key[22], s->master_key[23],
			s->master_key[24], s->master_key[25], s->master_key[26], s->master_key[27],
			s->master_key[28], s->master_key[29], s->master_key[30], s->master_key[31]);
		break;
	}
	DBG("master salt %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
			s->master_salt[0], s->master_salt[1], s->master_salt[2], s->master_salt[3],
			s->master_salt[4], s->master_salt[5], s->master_salt[6], s->master_salt[7],
			s->master_salt[8], s->master_salt[9], s->master_salt[10], s->master_salt[11],
			s->master_salt[12], s->master_salt[13]);
	switch(s->session_key_len) {
	case 16:
		DBG("session key %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
			c->session_key[0], c->session_key[1], c->session_key[2], c->session_key[3],
			c->session_key[4], c->session_key[5], c->session_key[6], c->session_key[7],
			c->session_key[8], c->session_key[9], c->session_key[10], c->session_key[11],
			c->session_key[12], c->session_key[13], c->session_key[14], c->session_key[15]);
		break;
	case 24:
		DBG("session key %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
			c->session_key[0], c->session_key[1], c->session_key[2], c->session_key[3],
			c->session_key[4], c->session_key[5], c->session_key[6], c->session_key[7],
			c->session_key[8], c->session_key[9], c->session_key[10], c->session_key[11],
		        c->session_key[12], c->session_key[13], c->session_key[14], c->session_key[15],
			c->session_key[16], c->session_key[17], c->session_key[18], c->session_key[19],
			c->session_key[20], c->session_key[21], c->session_key[22], c->session_key[23]);
		break;
	case 32:
		DBG("session key %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
			c->session_key[0], c->session_key[1], c->session_key[2], c->session_key[3],
			c->session_key[4], c->session_key[5], c->session_key[6], c->session_key[7],
			c->session_key[8], c->session_key[9], c->session_key[10], c->session_key[11],
		        c->session_key[12], c->session_key[13], c->session_key[14], c->session_key[15],
			c->session_key[16], c->session_key[17], c->session_key[18], c->session_key[19],
			c->session_key[20], c->session_key[21], c->session_key[22], c->session_key[23],
			c->session_key[24], c->session_key[25], c->session_key[26], c->session_key[27],
			c->session_key[28], c->session_key[29], c->session_key[30], c->session_key[31]);
		break;
	}
	DBG("session salt %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
			c->session_salt[0], c->session_salt[1], c->session_salt[2], c->session_salt[3],
			c->session_salt[4], c->session_salt[5], c->session_salt[6], c->session_salt[7],
			c->session_salt[8], c->session_salt[9], c->session_salt[10], c->session_salt[11],
			c->session_salt[12], c->session_salt[13]);
	DBG("session auth key %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
			c->session_auth_key[0], c->session_auth_key[1], c->session_auth_key[2], c->session_auth_key[3],
			c->session_auth_key[4], c->session_auth_key[5], c->session_auth_key[6], c->session_auth_key[7],
			c->session_auth_key[8], c->session_auth_key[9], c->session_auth_key[10], c->session_auth_key[11],
			c->session_auth_key[12], c->session_auth_key[13], c->session_auth_key[14], c->session_auth_key[15],
			c->session_auth_key[16], c->session_auth_key[17], c->session_auth_key[18], c->session_auth_key[19]);
	return 0;

error:
	free_crypto_context(c);
	printk(KERN_ERR "Failed to generate session keys: %s\n", err);
	return ret;
}




static void crypto_context_init(struct re_crypto_context *c, struct rtpengine_srtp *s) {
	c->cipher = &re_ciphers[s->cipher];
	c->hmac = &re_hmacs[s->hmac];
}

static int table_new_target(struct rtpengine_table *t, struct rtpengine_target_info *i, int update) {
	unsigned char hi, lo;
	unsigned int rda_hash, rh_it;
	struct rtpengine_target *g;
	struct re_dest_addr *rda;
	struct re_bucket *b, *ba = NULL;
	struct rtpengine_target *og = NULL;
	int err, j;
	unsigned long flags;

	/* validation */

	if (!is_valid_address(&i->local))
		return -EINVAL;
	if (!i->non_forwarding) {
		if (!is_valid_address(&i->src_addr))
			return -EINVAL;
		if (!is_valid_address(&i->dst_addr))
			return -EINVAL;
		if (i->src_addr.family != i->dst_addr.family)
			return -EINVAL;
	}
	if (i->mirror_addr.family) {
		if (!is_valid_address(&i->mirror_addr))
			return -EINVAL;
		if (i->mirror_addr.family != i->src_addr.family)
			return -EINVAL;
	}
	if (validate_srtp(&i->decrypt))
		return -EINVAL;
	if (validate_srtp(&i->encrypt))
		return -EINVAL;

	DBG("Creating new target\n");

	/* initializing */

	err = -ENOMEM;
	g = kzalloc(sizeof(*g), GFP_KERNEL);
	if (!g)
		goto fail1;

	g->table = t->id;
	atomic_set(&g->refcnt, 1);
	spin_lock_init(&g->decrypt.lock);
	spin_lock_init(&g->encrypt.lock);
	memcpy(&g->target, i, sizeof(*i));
	crypto_context_init(&g->decrypt, &g->target.decrypt);
	crypto_context_init(&g->encrypt, &g->target.encrypt);

	err = gen_session_keys(&g->decrypt, &g->target.decrypt);
	if (err)
		goto fail2;
	err = gen_session_keys(&g->encrypt, &g->target.encrypt);
	if (err)
		goto fail2;

	/* find or allocate re_dest_addr */

	rda_hash = re_address_hash(&i->local);
	hi = (i->local.port & 0xff00) >> 8;
	lo = i->local.port & 0xff;

retry:
	rh_it = rda_hash;
	write_lock_irqsave(&t->target_lock, flags);

	rda = t->dest_addr_hash.addrs[rh_it];
	while (rda) {
		if (re_address_match(&rda->destination, &i->local))
			goto got_rda;
		rh_it++;
		if (rh_it >= 256)
			rh_it = 0;
		err = -ENXIO;
		if (rh_it == rda_hash)
			goto fail4;
		rda = t->dest_addr_hash.addrs[rh_it];
	}

	err = -ENOENT;
	if (update)
		goto fail4;

	write_unlock_irqrestore(&t->target_lock, flags);

	rda = kzalloc(sizeof(*rda), GFP_KERNEL);
	err = -ENOMEM;
	if (!rda)
		goto fail2;

	memcpy(&rda->destination, &i->local, sizeof(rda->destination));

	write_lock_irqsave(&t->target_lock, flags);

	if (t->dest_addr_hash.addrs[rh_it]) {
		write_unlock_irqrestore(&t->target_lock, flags);
		kfree(rda);
		goto retry;
	}

	t->dest_addr_hash.addrs[rh_it] = rda;
	re_bitfield_set(&t->dest_addr_hash.addrs_bf, rh_it);

got_rda:
	/* find or allocate re_bucket */

	if ((b = rda->ports_hi[hi]))
		goto got_bucket;

	err = -ENOENT;
	if (update)
		goto fail4;

	write_unlock_irqrestore(&t->target_lock, flags);

	b = kzalloc(sizeof(*b), GFP_KERNEL);
	err = -ENOMEM;
	if (!b)
		goto fail2;

	write_lock_irqsave(&t->target_lock, flags);

	if (!rda->ports_hi[hi]) {
		rda->ports_hi[hi] = b;
		re_bitfield_set(&rda->ports_hi_bf, hi);
	}
	else {
		ba = b;
		b = rda->ports_hi[hi];
	}

got_bucket:
	if (update) {
		err = -ENOENT;
		og = b->ports_lo[lo];
		if (!og)
			goto fail4;

		atomic64_set(&g->stats.packets, atomic64_read(&og->stats.packets));
		atomic64_set(&g->stats.bytes, atomic64_read(&og->stats.bytes));
		atomic64_set(&g->stats.errors, atomic64_read(&og->stats.errors));
		g->stats.delay_min = og->stats.delay_min;
		g->stats.delay_max = og->stats.delay_max;
		g->stats.delay_avg = og->stats.delay_avg;
		atomic_set(&g->stats.in_tos, atomic_read(&og->stats.in_tos));

		for (j = 0; j < NUM_PAYLOAD_TYPES; j++) {
			atomic64_set(&g->rtp_stats[j].packets, atomic64_read(&og->rtp_stats[j].packets));
			atomic64_set(&g->rtp_stats[j].bytes, atomic64_read(&og->rtp_stats[j].bytes));
		}
	}
	else {
		err = -EEXIST;
		if (b->ports_lo[lo])
			goto fail4;
		re_bitfield_set(&b->ports_lo_bf, lo);
		t->num_targets++;
	}

	b->ports_lo[lo] = g;
	g = NULL;
	write_unlock_irqrestore(&t->target_lock, flags);

	if (ba)
		kfree(ba);
	if (og)
		target_put(og);

	return 0;

fail4:
	write_unlock_irqrestore(&t->target_lock, flags);
	if (ba)
		kfree(ba);
fail2:
	kfree(g);
fail1:
	return err;
}





static struct rtpengine_target *get_target(struct rtpengine_table *t, const struct re_address *local) {
	unsigned char hi, lo;
	struct re_dest_addr *rda;
	struct rtpengine_target *r;
	unsigned long flags;

	if (!t)
		return NULL;
	if (!local)
		return NULL;

	hi = (local->port & 0xff00) >> 8;
	lo = local->port & 0xff;

	read_lock_irqsave(&t->target_lock, flags);

	rda = find_dest_addr(&t->dest_addr_hash, local);
	r = rda ? (rda->ports_hi[hi] ? rda->ports_hi[hi]->ports_lo[lo] : NULL) : NULL;
	if (r)
		target_get(r);
	read_unlock_irqrestore(&t->target_lock, flags);

	return r;
}





static int proc_generic_open_modref(struct inode *inode, struct file *file) {
	if (!try_module_get(THIS_MODULE))
		return -ENXIO;
	return 0;
}
static int proc_generic_close_modref(struct inode *inode, struct file *file) {
	module_put(THIS_MODULE);
	return 0;
}
static int proc_generic_seqrelease_modref(struct inode *inode, struct file *file) {
	proc_generic_close_modref(inode, file);
	return seq_release(inode, file);
}

static ssize_t proc_main_control_write(struct file *file, const char __user *buf, size_t buflen, loff_t *off) {
	char b[30];
	unsigned long id;
	char *endp;
	struct rtpengine_table *t;
	int err;

	if (buflen < 6 || buflen > 20)
		return -EINVAL;

	if (copy_from_user(&b, buf, buflen))
		return -EFAULT;

	if (!strncmp(b, "add ", 4)) {
		id = simple_strtoul(b + 4, &endp, 10);
		if (endp == b + 4)
			return -EINVAL;
		if (id >= MAX_ID)
			return -EINVAL;
		t = new_table_link((u_int32_t) id);
		if (!t)
			return -EEXIST;
		table_put(t);
		t = NULL;
	}
	else if (!strncmp(b, "del ", 4)) {
		id = simple_strtoul(b + 4, &endp, 10);
		if (endp == b + 4)
			return -EINVAL;
		if (id >= MAX_ID)
			return -EINVAL;
		t = get_table((u_int32_t) id);
		if (!t)
			return -ENOENT;
		err = unlink_table(t);
		table_put(t);
		t = NULL;
		if (err)
			return err;
	}
	else
		return -EINVAL;

	return buflen;
}





static int proc_control_open(struct inode *inode, struct file *file) {
	u_int32_t id;
	struct rtpengine_table *t;
	unsigned long flags;
	int err;

	if ((err = proc_generic_open_modref(inode, file)))
		return err;

	id = (u_int32_t) (unsigned long) PDE_DATA(inode);
	t = get_table(id);
	if (!t)
		return -ENOENT;

	write_lock_irqsave(&table_lock, flags);
	if (t->pid) {
		write_unlock_irqrestore(&table_lock, flags);
		table_put(t);
		return -EBUSY;
	}
	t->pid = current->tgid;
	write_unlock_irqrestore(&table_lock, flags);

	table_put(t);
	return 0;
}

static int proc_control_close(struct inode *inode, struct file *file) {
	u_int32_t id;
	struct rtpengine_table *t;
	unsigned long flags;

	id = (u_int32_t) (unsigned long) PDE_DATA(inode);
	t = get_table(id);
	if (!t)
		return 0;

	write_lock_irqsave(&table_lock, flags);
	t->pid = 0;
	write_unlock_irqrestore(&table_lock, flags);

	table_put(t);

	proc_generic_close_modref(inode, file);

	return 0;
}

/* array must be locked */
static int auto_array_find_free_index(struct re_auto_array *a) {
	void *ptr;
	unsigned int u, idx;

	DBG("auto_array_find_free_index()\n");

	if (!list_empty(&a->free_list)) {
		DBG("returning from free list\n");
		return pop_free_list_entry(a);
	}

	for (idx = 0; idx < a->array_len / (sizeof(unsigned long) * 8); idx++) {
		if (~a->used_bitfield[idx])
			goto found;
	}

	/* nothing free found - extend array */
	DBG("no free slot found, extending array\n");

	u = a->array_len * 2;
	if (unlikely(!u))
		u = 256; /* XXX make configurable? */

	DBG("extending array from %u to %u\n", a->array_len, u);

	ptr = krealloc(a->array, sizeof(*a->array) * u, GFP_ATOMIC);
	if (!ptr)
		return -ENOMEM;
	a->array = ptr;
	DBG("zeroing main array starting at idx %u for %lu bytes\n",
			a->array_len, (u - a->array_len) * sizeof(*a->array));
	memset(&a->array[a->array_len], 0,
			(u - a->array_len) * sizeof(*a->array));

	ptr = krealloc(a->used_bitfield, u / 8, GFP_ATOMIC);
	if (!ptr)
		return -ENOMEM;
	a->used_bitfield = ptr;
	DBG("zeroing bitfield array starting at idx %lu for %u bytes\n",
			a->array_len / (sizeof(unsigned long) * 8),
			(u - a->array_len) / 8);
	memset(&a->used_bitfield[a->array_len / (sizeof(unsigned long) * 8)], 0,
			(u - a->array_len) / 8);

	idx = a->array_len / (sizeof(unsigned long) * 8);
	a->array_len = u;

found:
	/* got our bitfield index, now look for the slot */

	DBG("found unused slot at index %u\n", idx);

	idx = idx * sizeof(unsigned long) * 8;
	for (u = 0; u < sizeof(unsigned long) * 8; u++) {
		if (!a->array[idx + u])
			goto found2;
	}
	panic("BUG while looking for unused index");

found2:
	idx += u;
	DBG("unused idx is %u\n", idx);

	return idx;
}





/* lock must be held */
static struct re_call *get_call(struct rtpengine_table *table, unsigned int idx) {
	struct re_call *ret;

	if (idx >= calls.array_len)
		return NULL;

	ret = calls.array[idx];
	if (!ret)
		return NULL;
	if (table && ret->table_id != table->id)
		return NULL;
	if (ret->deleted)
		return NULL;
	return ret;
}
/* handles the locking (read) and reffing */
static struct re_call *get_call_lock(struct rtpengine_table *table, unsigned int idx) {
	struct re_call *ret;
	unsigned long flags;

	DBG("entering get_call_lock()\n");

	_r_lock(&calls.lock, flags);

	DBG("calls.lock acquired\n");

	ret = get_call(table, idx);
	if (ret)
		ref_get(ret);
	else
		DBG("call not found\n");

	_r_unlock(&calls.lock, flags);
	DBG("calls.lock unlocked\n");
	return ret;
}
/* lock must be held */
static struct re_stream *get_stream(struct re_call *call, unsigned int idx) {
	struct re_stream *ret;

	if (idx >= streams.array_len)
		return NULL;

	ret = streams.array[idx];
	if (!ret)
		return NULL;
	if (call && ret->info.call_idx != call->info.call_idx)
		return NULL;
	return ret;
}
/* handles the locking (read) and reffing */
static struct re_stream *get_stream_lock(struct re_call *call, unsigned int idx) {
	struct re_stream *ret;
	unsigned long flags;

	DBG("entering get_stream_lock()\n");

	_r_lock(&streams.lock, flags);

	DBG("streams.lock acquired\n");

	ret = get_stream(call, idx);
	if (ret)
		ref_get(ret);
	else
		DBG("stream not found\n");

	_r_unlock(&streams.lock, flags);
	DBG("streams.lock unlocked\n");
	return ret;
}





static int table_new_call(struct rtpengine_table *table, struct rtpengine_call_info *info) {
	int err;
	struct re_call *call, *hash_entry;
	unsigned int idx;
	unsigned long flags;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
	struct hlist_node *hlist_entry;
#endif

	/* validation */

	if (info->call_id[0] == '\0')
		return -EINVAL;
	if (!memchr(info->call_id, '\0', sizeof(info->call_id)))
		return -EINVAL;

	DBG("Creating new call object\n");

	/* allocate and initialize */

	call = kzalloc(sizeof(*call), GFP_KERNEL);
	if (!call)
		return -ENOMEM;

	atomic_set(&call->refcnt, 1);
	call->table_id = table->id;
	INIT_LIST_HEAD(&call->streams);

	/* check for name collisions */

	call->hash_bucket = crc32_le(0x52342, info->call_id, strlen(info->call_id));
	call->hash_bucket = call->hash_bucket & ((1 << RE_HASH_BITS) - 1);

	spin_lock_irqsave(&table->calls_hash_lock[call->hash_bucket], flags);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
	hlist_for_each_entry(hash_entry, hlist_entry, &table->calls_hash[call->hash_bucket],
			calls_hash_entry) {
#else
	hlist_for_each_entry(hash_entry, &table->calls_hash[call->hash_bucket], calls_hash_entry) {
#endif
		if (!strcmp(hash_entry->info.call_id, info->call_id))
			goto found;
	}
	goto not_found;
found:
	spin_unlock_irqrestore(&table->calls_hash_lock[call->hash_bucket], flags);
	printk(KERN_ERR "Call name collision: %s\n", info->call_id);
	err = -EEXIST;
	goto fail2;

not_found:
	hlist_add_head(&call->calls_hash_entry, &table->calls_hash[call->hash_bucket]);
	ref_get(call);
	spin_unlock_irqrestore(&table->calls_hash_lock[call->hash_bucket], flags);

	/* create proc */

	call->root = proc_mkdir_user(info->call_id, S_IRUGO | S_IXUGO, table->proc_calls);
	err = -ENOMEM;
	if (!call->root)
		goto fail4;

	_w_lock(&calls.lock, flags);

	idx = err = auto_array_find_free_index(&calls);
	if (err < 0)
		goto fail3;
	set_auto_array_index(&calls, idx, call); /* handing over ref */

	info->call_idx = idx;
	memcpy(&call->info, info, sizeof(call->info));

	list_add(&call->table_entry, &table->calls); /* new ref here */
	ref_get(call);

	_w_unlock(&calls.lock, flags);

	return 0;

fail3:
	_w_unlock(&calls.lock, flags);
fail4:
	spin_lock_irqsave(&table->calls_hash_lock[call->hash_bucket], flags);
	hlist_del(&call->calls_hash_entry);
	spin_unlock_irqrestore(&table->calls_hash_lock[call->hash_bucket], flags);
	call_put(call);
fail2:
	call_put(call);
	return err;
}

static int table_del_call(struct rtpengine_table *table, unsigned int idx) {
	int err;
	struct re_call *call = NULL;

	call = get_call_lock(table, idx);
	err = -ENOENT;
	if (!call)
		goto out;

	del_call(call, table);

	err = 0;

out:
	if (call)
		call_put(call);

	return err;
}
/* must be called lock-free */
static void del_call(struct re_call *call, struct rtpengine_table *table) {
	struct re_stream *stream;
	unsigned long flags;

	DBG("del_call()\n");

	/* the only references left might be the ones in the lists, so get one until we're done */
	ref_get(call);

	_w_lock(&calls.lock, flags);

	if (call->deleted) {
		/* already doing this */
		_w_unlock(&calls.lock, flags);
		call_put(call);
		return;
	}

	call->deleted = 1;

	_w_unlock(&calls.lock, flags);

	DBG("locking streams.lock\n");
	_w_lock(&streams.lock, flags);
	while (!list_empty(&call->streams)) {
		stream = list_first_entry(&call->streams, struct re_stream, call_entry);
		ref_get(stream);
		_w_unlock(&streams.lock, flags);
		del_stream(stream, table); /* removes it from this list */
		DBG("re-locking streams.lock\n");
		_w_lock(&streams.lock, flags);
	}
	_w_unlock(&streams.lock, flags);

	DBG("locking table's call hash\n");
	spin_lock_irqsave(&table->calls_hash_lock[call->hash_bucket], flags);
	if (!hlist_unhashed(&call->calls_hash_entry)) {
		hlist_del_init(&call->calls_hash_entry);
		call_put(call);
	}
	spin_unlock_irqrestore(&table->calls_hash_lock[call->hash_bucket], flags);

	_w_lock(&calls.lock, flags);

	if (!list_empty(&call->table_entry)) {
		list_del_init(&call->table_entry);
		call_put(call);
	}

	if (calls.array[call->info.call_idx] == call) {
		auto_array_clear_index(&calls, call->info.call_idx);
		call_put(call);
	}

	_w_unlock(&calls.lock, flags);

	DBG("del_call() done, releasing ref\n");
	call_put(call); /* might be the last ref */
}





static int table_new_stream(struct rtpengine_table *table, struct rtpengine_stream_info *info) {
	int err;
	struct re_call *call;
	struct re_stream *stream, *hash_entry;
	unsigned long flags;
	unsigned int idx;
	struct proc_dir_entry *pde;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
	struct hlist_node *hlist_entry;
#endif

	/* validation */

	if (info->stream_name[0] == '\0')
		return -EINVAL;
	if (!memchr(info->stream_name, '\0', sizeof(info->stream_name)))
		return -EINVAL;

	/* get call object */

	call = get_call_lock(table, info->call_idx);
	if (!call)
		return -ENOENT;

	DBG("Creating new stream object\n");

	/* allocate and initialize */

	err = -ENOMEM;
	stream = kzalloc(sizeof(*stream), GFP_KERNEL);
	if (!stream)
		goto fail2;

	atomic_set(&stream->refcnt, 1);
	INIT_LIST_HEAD(&stream->packet_list);
	spin_lock_init(&stream->packet_list_lock);
	init_waitqueue_head(&stream->read_wq);
	init_waitqueue_head(&stream->close_wq);

	/* check for name collisions */

	stream->hash_bucket = crc32_le(0x52342 ^ info->call_idx, info->stream_name, strlen(info->stream_name));
	stream->hash_bucket = stream->hash_bucket & ((1 << RE_HASH_BITS) - 1);

	spin_lock_irqsave(&table->streams_hash_lock[stream->hash_bucket], flags);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
	hlist_for_each_entry(hash_entry, hlist_entry, &table->streams_hash[stream->hash_bucket],
			streams_hash_entry) {
#else
	hlist_for_each_entry(hash_entry, &table->streams_hash[stream->hash_bucket], streams_hash_entry) {
#endif
		if (hash_entry->info.call_idx == info->call_idx
				&& !strcmp(hash_entry->info.stream_name, info->stream_name))
			goto found;
	}
	goto not_found;
found:
	spin_unlock_irqrestore(&table->streams_hash_lock[stream->hash_bucket], flags);
	printk(KERN_ERR "Stream name collision: %s\n", info->stream_name);
	err = -EEXIST;
	goto fail3;

not_found:
	hlist_add_head(&stream->streams_hash_entry, &table->streams_hash[stream->hash_bucket]);
	ref_get(stream);
	spin_unlock_irqrestore(&table->streams_hash_lock[stream->hash_bucket], flags);

	/* add into array */

	_w_lock(&streams.lock, flags);

	idx = err = auto_array_find_free_index(&streams);
	if (err < 0)
		goto fail4;
	set_auto_array_index(&streams, idx, stream); /* handing over ref */

	/* copy info */

	info->stream_idx = idx;
	memcpy(&stream->info, info, sizeof(call->info));
	if (!stream->info.max_packets)
		stream->info.max_packets = stream_packets_list_limit;

	list_add(&stream->call_entry, &call->streams); /* new ref here */
	ref_get(stream);

	stream->call = call;
	ref_get(call);

	_w_unlock(&streams.lock, flags);

	/* proc_ functions may sleep, so this must be done outside of the lock */
	pde = stream->file = proc_create_user(info->stream_name, S_IFREG | S_IRUSR | S_IRGRP, call->root,
			&proc_stream_ops, (void *) (unsigned long) info->stream_idx);
	err = -ENOMEM;
	if (!pde)
		goto fail5;

	call_put(call);

	return 0;

fail5:
	_w_lock(&streams.lock, flags);
	auto_array_clear_index(&streams, idx);
fail4:
	_w_unlock(&streams.lock, flags);

	spin_lock_irqsave(&table->streams_hash_lock[stream->hash_bucket], flags);
	hlist_del(&stream->streams_hash_entry);
	spin_unlock_irqrestore(&table->streams_hash_lock[stream->hash_bucket], flags);
	stream_put(stream);
fail3:
	stream_put(stream);
fail2:
	call_put(call);
	return err;
}

/* must be called lock-free and with one reference held, which will be released */
static void del_stream(struct re_stream *stream, struct rtpengine_table *table) {
	unsigned long flags;

	DBG("del_stream()\n");

	DBG("locking stream's packet list lock\n");
	spin_lock_irqsave(&stream->packet_list_lock, flags);

	if (stream->eof) {
		/* already done this */
		spin_unlock_irqrestore(&stream->packet_list_lock, flags);
		DBG("stream is EOF\n");
		stream_put(stream);
		return;
	}

	stream->eof = 1;

	spin_unlock_irqrestore(&stream->packet_list_lock, flags);

	clear_stream_packets(stream);

	DBG("stream is finished (EOF), waking up threads\n");
	wake_up_interruptible(&stream->read_wq);
	/* sleeping readers will now close files */

	DBG("clearing stream from streams_hash\n");
	spin_lock_irqsave(&table->streams_hash_lock[stream->hash_bucket], flags);
	if (!hlist_unhashed(&stream->streams_hash_entry)) {
		hlist_del_init(&stream->streams_hash_entry);
		stream_put(stream);
	}
	spin_unlock_irqrestore(&table->streams_hash_lock[stream->hash_bucket], flags);

	_w_lock(&streams.lock, flags);
	if (!list_empty(&stream->call_entry)) {
		DBG("clearing stream's call_entry\n");
		list_del_init(&stream->call_entry);
		stream_put(stream);
	}
	_w_unlock(&streams.lock, flags);

	/* At this point, there should only be 2 references left: ours, and the entry in
	 * the "streams" array. Any other references are open files and we must wait until
	 * they're closed. There can be no new open file references as the stream is set
	 * to eof. */
	DBG("del_stream() waiting for other refs\n");
	while (1) {
		if (wait_event_interruptible(stream->close_wq, atomic_read(&stream->refcnt) == 2) == 0)
			break;
	}

	DBG("clearing stream's stream_idx entry\n");
	_w_lock(&streams.lock, flags);
	if (streams.array[stream->info.stream_idx] == stream) {
		auto_array_clear_index(&streams, stream->info.stream_idx);
		stream_put(stream); /* down to 1 ref */
	}
	else
		printk(KERN_WARNING "BUG in del_stream with streams.array\n");
	_w_unlock(&streams.lock, flags);

	DBG("del_stream() releasing last ref\n");
	stream_put(stream);
}

static int table_del_stream(struct rtpengine_table *table, const struct rtpengine_stream_info *info) {
	int err;
	struct re_call *call;
	struct re_stream *stream;

	DBG("table_del_stream()\n");

	call = get_call_lock(table, info->call_idx);
	err = -ENOENT;
	if (!call)
		return -ENOENT;

	stream = get_stream_lock(call, info->stream_idx);
	err = -ENOENT;
	if (!stream)
		goto out;

	del_stream(stream, table);

	err = 0;

out:
	call_put(call);
	return err;
}




static ssize_t proc_stream_read(struct file *f, char __user *b, size_t l, loff_t *o) {
	unsigned int stream_idx = (unsigned int) (unsigned long) PDE_DATA(f->f_path.dentry->d_inode);
	struct re_stream *stream;
	unsigned long flags;
	struct re_stream_packet *packet;
	ssize_t ret;
	const char *to_copy;

	DBG("entering proc_stream_read()\n");

	stream = get_stream_lock(NULL, stream_idx);
	if (!stream)
		return -EINVAL;

	DBG("locking stream's packet list lock\n");
	spin_lock_irqsave(&stream->packet_list_lock, flags);

	while (list_empty(&stream->packet_list) && !stream->eof) {
		spin_unlock_irqrestore(&stream->packet_list_lock, flags);
		DBG("list is empty\n");
		ret = -EAGAIN;
		if ((f->f_flags & O_NONBLOCK))
			goto out;
		DBG("going to sleep\n");
		ret = -ERESTARTSYS;
		if (wait_event_interruptible(stream->read_wq, !list_empty(&stream->packet_list) || stream->eof))
			goto out;
		DBG("awakened\n");
		spin_lock_irqsave(&stream->packet_list_lock, flags);
	}

	ret = 0;
	if (stream->eof) {
		DBG("eof\n");
		spin_unlock_irqrestore(&stream->packet_list_lock, flags);
		goto out;
	}

	DBG("removing packet from queue, reading %i bytes\n", (int) l);
	packet = list_first_entry(&stream->packet_list, struct re_stream_packet, list_entry);
	list_del(&packet->list_entry);
	stream->list_count--;

	spin_unlock_irqrestore(&stream->packet_list_lock, flags);

	if (packet->buflen) {
		ret = packet->buflen;
		to_copy = packet->buf;
		DBG("packet is from userspace, %i bytes\n", (int) ret);
	}
	else if (packet->skbuf) {
		ret = packet->skbuf->len;
		to_copy = packet->skbuf->data;
		DBG("packet is from kernel, %i bytes\n", (int) ret);
	}
	else {
		printk(KERN_WARNING "BUG in packet stream list buffer\n");
		ret = -ENXIO;
		goto err;
	}

	if (ret > l)
		ret = l;
	if (copy_to_user(b, to_copy, ret))
		ret = -EFAULT;

err:
	free_packet(packet);

out:
	stream_put(stream);
	return ret;
}
static unsigned int proc_stream_poll(struct file *f, struct poll_table_struct *p) {
	unsigned int stream_idx = (unsigned int) (unsigned long) PDE_DATA(f->f_path.dentry->d_inode);
	struct re_stream *stream;
	unsigned long flags;
	unsigned int ret = 0;

	DBG("entering proc_stream_poll()\n");

	stream = get_stream_lock(NULL, stream_idx);
	if (!stream)
		return POLLERR;

	DBG("locking stream's packet list lock\n");
	spin_lock_irqsave(&stream->packet_list_lock, flags);

	if (!list_empty(&stream->packet_list) || stream->eof)
		ret |= POLLIN | POLLRDNORM;

	DBG("returning from proc_stream_poll()\n");

	spin_unlock_irqrestore(&stream->packet_list_lock, flags);

	poll_wait(f, &stream->read_wq, p);

	stream_put(stream);

	return ret;
}

static int proc_stream_open(struct inode *i, struct file *f) {
	int err;
	unsigned int stream_idx = (unsigned int) (unsigned long) PDE_DATA(f->f_path.dentry->d_inode);
	struct re_stream *stream;
	unsigned long flags;

	DBG("entering proc_stream_open()\n");

	if ((err = proc_generic_open_modref(i, f)))
		return err;

	stream = get_stream_lock(NULL, stream_idx);
	if (!stream)
		return -EIO;

	spin_lock_irqsave(&stream->packet_list_lock, flags);
	if (stream->eof) {
		spin_unlock_irqrestore(&stream->packet_list_lock, flags);
		stream_put(stream);
		return -ETXTBSY;
	}
	spin_unlock_irqrestore(&stream->packet_list_lock, flags);

	return 0;
}

static int proc_stream_close(struct inode *i, struct file *f) {
	unsigned int stream_idx = (unsigned int) (unsigned long) PDE_DATA(f->f_path.dentry->d_inode);
	struct re_stream *stream;

	DBG("entering proc_stream_close()\n");

	stream = get_stream_lock(NULL, stream_idx);
	if (!stream)
		return -EIO;
	/* release our own ref and the ref from _open */
	stream_put(stream);
	stream_put(stream);

	proc_generic_close_modref(i, f);

	return 0;
}




static void add_stream_packet(struct re_stream *stream, struct re_stream_packet *packet) {
	int err;
	unsigned long flags;
	LIST_HEAD(delete_list);

	/* append */

	DBG("entering add_stream_packet()\n");
	DBG("locking stream's packet list lock\n");
	spin_lock_irqsave(&stream->packet_list_lock, flags);

	err = 0;
	if (stream->eof)
		goto err; /* we accept, but ignore/discard */

	DBG("adding packet to queue\n");
	list_add_tail(&packet->list_entry, &stream->packet_list);
	stream->list_count++;

	DBG("%u packets now in queue\n", stream->list_count);

	/* discard older packets */
	while (stream->list_count > stream->info.max_packets) {
		DBG("discarding old packet from queue\n");
		packet = list_first_entry(&stream->packet_list, struct re_stream_packet, list_entry);
		list_del(&packet->list_entry);
		list_add(&packet->list_entry, &delete_list);
		stream->list_count--;
	}

	spin_unlock_irqrestore(&stream->packet_list_lock, flags);

	DBG("stream's packet list lock is unlocked, now awakening processes\n");

	wake_up_interruptible(&stream->read_wq);

	while (!list_empty(&delete_list)) {
		packet = list_first_entry(&delete_list, struct re_stream_packet, list_entry);
		list_del(&packet->list_entry);
		free_packet(packet);
	}

	return;

err:
	DBG("error adding packet to stream\n");
	spin_unlock_irqrestore(&stream->packet_list_lock, flags);
	free_packet(packet);
	return;
}

static int stream_packet(struct rtpengine_table *t, const struct rtpengine_packet_info *info,
		const unsigned char *data, unsigned int len)
{
	struct re_stream *stream;
	int err;
	struct re_stream_packet *packet;

	if (!len) /* can't have empty packets */
		return -EINVAL;

	DBG("received %u bytes of data from userspace\n", len);

	err = -ENOENT;
	stream = get_stream_lock(NULL, info->stream_idx);
	if (!stream)
		goto out;

	DBG("data for stream %s\n", stream->info.stream_name);

	/* alloc and copy */

	err = -ENOMEM;
	packet = kmalloc(sizeof(*packet) + len, GFP_KERNEL);
	if (!packet)
		goto out2;
	memset(packet, 0, sizeof(*packet));

	memcpy(packet->buf, data, len);
	packet->buflen = len;

	/* append */
	add_stream_packet(stream, packet);

	err = 0;
	goto out2;

out2:
	stream_put(stream);
out:
	return err;
}





static inline ssize_t proc_control_read_write(struct file *file, char __user *ubuf, size_t buflen, loff_t *off,
		int writeable)
{
	struct inode *inode;
	u_int32_t id;
	struct rtpengine_table *t;
	struct rtpengine_message msgbuf;
	struct rtpengine_message *msg;
	int err;

	if (buflen < sizeof(*msg))
		return -EIO;
	if (buflen == sizeof(*msg))
		msg = &msgbuf;
	else { /* > */
		msg = kmalloc(buflen, GFP_KERNEL);
		if (!msg)
			return -ENOMEM;
	}

	inode = file->f_path.dentry->d_inode;
	id = (u_int32_t) (unsigned long) PDE_DATA(inode);
	t = get_table(id);
	err = -ENOENT;
	if (!t)
		goto out;

	err = -EFAULT;
	if (copy_from_user(msg, ubuf, buflen))
		goto err;

	err = 0;

	switch (msg->cmd) {
		case REMG_NOOP:
			DBG("noop.\n");
			break;

		case REMG_ADD:
			err = table_new_target(t, &msg->u.target, 0);
			break;

		case REMG_DEL:
			err = table_del_target(t, &msg->u.target.local);
			break;

		case REMG_UPDATE:
			err = table_new_target(t, &msg->u.target, 1);
			break;

		case REMG_ADD_CALL:
			err = -EINVAL;
			if (!writeable)
				goto err;
			err = table_new_call(t, &msg->u.call);
			break;

		case REMG_DEL_CALL:
			err = table_del_call(t, msg->u.call.call_idx);
			break;

		case REMG_ADD_STREAM:
			err = -EINVAL;
			if (!writeable)
				goto err;
			err = table_new_stream(t, &msg->u.stream);
			break;

		case REMG_DEL_STREAM:
			err = table_del_stream(t, &msg->u.stream);
			break;

		case REMG_PACKET:
			err = stream_packet(t, &msg->u.packet, msg->data, buflen - sizeof(*msg));
			break;

		default:
			printk(KERN_WARNING "xt_RTPENGINE unimplemented op %u\n", msg->cmd);
			err = -EINVAL;
			break;
	}

	table_put(t);

	if (err)
		goto out;

	if (writeable) {
		err = -EFAULT;
		if (copy_to_user(ubuf, msg, sizeof(*msg)))
			goto out;
	}

	if (msg != &msgbuf)
		kfree(msg);

	return buflen;

err:
	table_put(t);
out:
	if (msg != &msgbuf)
		kfree(msg);
	return err;
}
static ssize_t proc_control_write(struct file *file, const char __user *ubuf, size_t buflen, loff_t *off) {
	return proc_control_read_write(file, (char __user *) ubuf, buflen, off, 0);
}
static ssize_t proc_control_read(struct file *file, char __user *ubuf, size_t buflen, loff_t *off) {
	return proc_control_read_write(file, ubuf, buflen, off, 1);
}






static int send_proxy_packet4(struct sk_buff *skb, struct re_address *src, struct re_address *dst,
		unsigned char tos, const struct xt_action_param *par)
{
	struct iphdr *ih;
	struct udphdr *uh;
	unsigned int datalen;

	datalen = skb->len;

	uh = (void *) skb_push(skb, sizeof(*uh));
	skb_reset_transport_header(skb);
	ih = (void *) skb_push(skb, sizeof(*ih));
	skb_reset_network_header(skb);

	DBG("datalen=%u network_header=%p transport_header=%p\n", datalen, skb_network_header(skb), skb_transport_header(skb));

	datalen += sizeof(*uh);
	*uh = (struct udphdr) {
		.source		= htons(src->port),
		.dest		= htons(dst->port),
		.len		= htons(datalen),
	};
	*ih = (struct iphdr) {
		.version	= 4,
		.ihl		= 5,
		.tos		= tos,
		.tot_len	= htons(sizeof(*ih) + datalen),
		.ttl		= 64,
		.protocol	= IPPROTO_UDP,
		.saddr		= src->u.ipv4,
		.daddr		= dst->u.ipv4,
	};

	skb->csum_start = skb_transport_header(skb) - skb->head;
	skb->csum_offset = offsetof(struct udphdr, check);
	uh->check = csum_tcpudp_magic(src->u.ipv4, dst->u.ipv4, datalen, IPPROTO_UDP, csum_partial(uh, datalen, 0));
	if (uh->check == 0)
		uh->check = CSUM_MANGLED_0;

	skb->protocol = htons(ETH_P_IP);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
	if (ip_route_me_harder(par->state->net, skb, RTN_UNSPEC))
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
	if (ip_route_me_harder(par->net, skb, RTN_UNSPEC))
#else
	if (ip_route_me_harder(skb, RTN_UNSPEC))
#endif
		goto drop;

	skb->ip_summed = CHECKSUM_NONE;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
	ip_select_ident(par->state->net, skb, NULL);
	ip_send_check(ih);
	ip_local_out(par->state->net, skb->sk, skb);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
	ip_select_ident(par->net, skb, NULL);
	ip_send_check(ih);
	ip_local_out(par->net, skb->sk, skb);
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
	ip_select_ident(par->net, skb, NULL);
#elif (LINUX_VERSION_CODE == KERNEL_VERSION(3,10,0) && RHEL_MAJOR == 7) /* CentOS 7 */
	/* nothing */
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,15,10) \
		|| (LINUX_VERSION_CODE < KERNEL_VERSION(3,15,0) && LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,17)) \
		|| (LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0) && LINUX_VERSION_CODE >= KERNEL_VERSION(3,12,27)) \
		|| (LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0) && LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,53)) \
		|| (LINUX_VERSION_CODE < KERNEL_VERSION(3,5,0) && LINUX_VERSION_CODE >= KERNEL_VERSION(3,4,103)) \
		|| (LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0) && LINUX_VERSION_CODE >= KERNEL_VERSION(3,2,63))
	ip_select_ident(skb, NULL);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,5) \
		|| (LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0) && LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,16)) \
		|| (LINUX_VERSION_CODE < KERNEL_VERSION(3,5,0) && LINUX_VERSION_CODE >= KERNEL_VERSION(3,4,66)) \
		|| (LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0) && LINUX_VERSION_CODE >= KERNEL_VERSION(3,2,52)) \
		|| (LINUX_VERSION_CODE < KERNEL_VERSION(3,1,0) && LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,100))
	ip_select_ident(skb, skb_dst(skb), NULL);
#else // 3.9.x, 3.8.x, 3.7.x, 3.6.x, 3.5.x, 3.3.x, 3.1.x, 2.6.x
	ip_select_ident(ih, skb_dst(skb), NULL);
#endif
	ip_send_check(ih);
	ip_local_out(skb);
#endif

	return 0;

drop:
	log_err("IPv4 routing failed");
	kfree_skb(skb);
	return -1;
}





static int send_proxy_packet6(struct sk_buff *skb, struct re_address *src, struct re_address *dst,
		unsigned char tos, const struct xt_action_param *par)
{
	struct ipv6hdr *ih;
	struct udphdr *uh;
	unsigned int datalen;

	datalen = skb->len;

	uh = (void *) skb_push(skb, sizeof(*uh));
	skb_reset_transport_header(skb);
	ih = (void *) skb_push(skb, sizeof(*ih));
	skb_reset_network_header(skb);

	DBG("datalen=%u network_header=%p transport_header=%p\n", datalen, skb_network_header(skb), skb_transport_header(skb));

	datalen += sizeof(*uh);
	*uh = (struct udphdr) {
		.source		= htons(src->port),
		.dest		= htons(dst->port),
		.len		= htons(datalen),
	};
	*ih = (struct ipv6hdr) {
		.version	= 6,
		.priority	= (tos & 0xf0) >> 4,
		.flow_lbl	= {(tos & 0xf) << 4, 0, 0},
		.payload_len	= htons(datalen),
		.nexthdr	= IPPROTO_UDP,
		.hop_limit	= 64,
	};
	memcpy(&ih->saddr, src->u.ipv6, sizeof(ih->saddr));
	memcpy(&ih->daddr, dst->u.ipv6, sizeof(ih->daddr));

	skb->csum_start = skb_transport_header(skb) - skb->head;
	skb->csum_offset = offsetof(struct udphdr, check);
	uh->check = csum_ipv6_magic(&ih->saddr, &ih->daddr, datalen, IPPROTO_UDP, csum_partial(uh, datalen, 0));
	if (uh->check == 0)
		uh->check = CSUM_MANGLED_0;

	skb->protocol = htons(ETH_P_IPV6);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
	if (ip6_route_me_harder(par->state->net, skb))
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
	if (ip6_route_me_harder(par->net, skb))
#else
	if (ip6_route_me_harder(skb))
#endif
		goto drop;

	skb->ip_summed = CHECKSUM_NONE;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
	ip6_local_out(par->state->net, skb->sk, skb);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
	ip6_local_out(par->net, skb->sk, skb);
#else
	ip6_local_out(skb);
#endif

	return 0;

drop:
	log_err("IPv6 routing failed");
	kfree_skb(skb);
	return -1;
}




static int send_proxy_packet(struct sk_buff *skb, struct re_address *src, struct re_address *dst,
		unsigned char tos, const struct xt_action_param *par)
{
	if (src->family != dst->family) {
		log_err("address family mismatch");
		goto drop;
	}

	switch (src->family) {
		case AF_INET:
			return send_proxy_packet4(skb, src, dst, tos, par);
			break;

		case AF_INET6:
			return send_proxy_packet6(skb, src, dst, tos, par);
			break;

		default:
			log_err("unsupported address family");
			goto drop;
	}

drop:
	kfree_skb(skb);
	return -1;
}






/* XXX shared code */
static void parse_rtp(struct rtp_parsed *rtp, struct sk_buff *skb) {
	struct rtp_extension *ext;
	int ext_len;

	if (skb->len < sizeof(*rtp->header))
		goto error;
	rtp->header = (void *) skb->data;
	if ((rtp->header->v_p_x_cc & 0xc0) != 0x80) /* version 2 */
		goto error;
	rtp->header_len = sizeof(*rtp->header);

	/* csrc list */
	rtp->header_len += (rtp->header->v_p_x_cc & 0xf) * 4;
	if (skb->len < rtp->header_len)
		goto error;
	rtp->payload = skb->data + rtp->header_len;
	rtp->payload_len = skb->len - rtp->header_len;

	if ((rtp->header->v_p_x_cc & 0x10)) {
		/* extension */
		if (rtp->payload_len < sizeof(*ext))
			goto error;
		ext = (void *) rtp->payload;
		ext_len = 4 + ntohs(ext->length) * 4;
		if (rtp->payload_len < ext_len)
			goto error;
		rtp->payload += ext_len;
		rtp->payload_len -= ext_len;
		rtp->header_len += ext_len;
	}

	DBG("rtp header parsed, payload length is %u\n", rtp->payload_len);

	rtp->ok = 1;
	return;

error:
	rtp->ok = 0;
}

/* XXX shared code */
static u_int64_t packet_index(struct re_crypto_context *c,
		struct rtpengine_srtp *s, struct rtp_header *rtp)
{
	u_int16_t seq;
	u_int64_t index;
	unsigned long flags;
	u_int16_t s_l;
	u_int32_t roc;
	u_int32_t v;

	seq = ntohs(rtp->seq_num);

	spin_lock_irqsave(&c->lock, flags);

	/* rfc 3711 section 3.3.1 */
	if (unlikely(!s->last_index))
		s->last_index = seq;

	/* rfc 3711 appendix A, modified, and sections 3.3 and 3.3.1 */
	s_l = (s->last_index & 0x00000000ffffULL);
	roc = (s->last_index & 0xffffffff0000ULL) >> 16;
	v = 0;

	if (s_l < 0x8000) {
		if (((seq - s_l) > 0x8000) && roc > 0)
			v = (roc - 1) % 0x10000;
		else
			v = roc;
	} else {
		if ((s_l - 0x8000) > seq)
			v = (roc + 1) % 0x10000;
		else
			v = roc;
	}

	index = (v << 16) | seq;
	s->last_index = index;
	c->roc = v;

	spin_unlock_irqrestore(&c->lock, flags);

	return index;
}

static void update_packet_index(struct re_crypto_context *c,
		struct rtpengine_srtp *s, u_int64_t idx)
{
	unsigned long flags;

	spin_lock_irqsave(&c->lock, flags);
	s->last_index = idx;
	c->roc = (idx >> 16);
	spin_unlock_irqrestore(&c->lock, flags);
}

static int srtp_hash(unsigned char *hmac,
		struct re_crypto_context *c,
		struct rtpengine_srtp *s, struct rtp_parsed *r,
		u_int64_t pkt_idx)
{
	u_int32_t roc;
	struct shash_desc *dsc;
	size_t alloc_size;

	if (!s->auth_tag_len)
		return 0;

	roc = htonl((pkt_idx & 0xffffffff0000ULL) >> 16);

	alloc_size = sizeof(*dsc) + crypto_shash_descsize(c->shash);
	dsc = kmalloc(alloc_size, GFP_ATOMIC);
	if (!dsc)
		return -1;
	memset(dsc, 0, alloc_size);

	dsc->tfm = c->shash;

	if (crypto_shash_init(dsc))
		goto error;

	crypto_shash_update(dsc, (void *) r->header, r->header_len + r->payload_len);
	crypto_shash_update(dsc, (void *) &roc, sizeof(roc));

	crypto_shash_final(dsc, hmac);

	kfree(dsc);

	DBG("calculated HMAC %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
			hmac[0], hmac[1], hmac[2], hmac[3],
			hmac[4], hmac[5], hmac[6], hmac[7],
			hmac[8], hmac[9], hmac[10], hmac[11],
			hmac[12], hmac[13], hmac[14], hmac[15],
			hmac[16], hmac[17], hmac[18], hmac[19]);

	return 0;

error:
	kfree(dsc);
	return -1;
}

/* XXX shared code */
static void rtp_append_mki(struct rtp_parsed *r, struct rtpengine_srtp *c) {
	unsigned char *p;

	if (!c->mki_len)
		return;

	p = r->payload + r->payload_len;
	memcpy(p, c->mki, c->mki_len);
	r->payload_len += c->mki_len;
}

static int srtp_authenticate(struct re_crypto_context *c,
		struct rtpengine_srtp *s, struct rtp_parsed *r,
		u_int64_t pkt_idx)
{
	unsigned char hmac[20];

	if (!r->header)
		return 0;
	if (s->hmac == REH_NULL)
		return 0;
	if (!c->hmac)
		return 0;
	if (!c->shash)
		return -1;

	if (srtp_hash(hmac, c, s, r, pkt_idx))
		return -1;

	rtp_append_mki(r, s);

	memcpy(r->payload + r->payload_len, hmac, s->auth_tag_len);
	r->payload_len += s->auth_tag_len;

	return 0;
}

static int srtp_auth_validate(struct re_crypto_context *c,
		struct rtpengine_srtp *s, struct rtp_parsed *r,
		u_int64_t *pkt_idx_p)
{
	unsigned char *auth_tag;
	unsigned char hmac[20];
	u_int64_t pkt_idx = *pkt_idx_p;

	if (s->hmac == REH_NULL)
		return 0;
	if (!c->hmac)
		return 0;
	if (!c->shash)
		return -1;

	if (r->payload_len < s->auth_tag_len)
		return -1;

	r->payload_len -= s->auth_tag_len;
	auth_tag = r->payload + r->payload_len;

	if (r->payload_len < s->mki_len)
		return -1;
	r->payload_len -= s->mki_len;

	if (!s->auth_tag_len)
		return 0;

	DBG("packet auth tag %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
			auth_tag[0], auth_tag[1], auth_tag[2], auth_tag[3],
			auth_tag[4], auth_tag[5], auth_tag[6], auth_tag[7],
			auth_tag[8], auth_tag[9]);

	if (srtp_hash(hmac, c, s, r, pkt_idx))
		return -1;
	if (!memcmp(auth_tag, hmac, s->auth_tag_len))
		goto ok;

	/* possible ROC mismatch, attempt to guess */
	/* first, let's see if we missed a rollover */
	pkt_idx += 0x10000;
	if (srtp_hash(hmac, c, s, r, pkt_idx))
		return -1;
	if (!memcmp(auth_tag, hmac, s->auth_tag_len))
		goto ok_update;
	/* or maybe we did a rollover too many */
	if (pkt_idx >= 0x20000) {
		pkt_idx -= 0x20000;
		if (srtp_hash(hmac, c, s, r, pkt_idx))
			return -1;
		if (!memcmp(auth_tag, hmac, s->auth_tag_len))
			goto ok_update;
	}
	/* last guess: reset ROC to zero */
	pkt_idx &= 0xffff;
	if (srtp_hash(hmac, c, s, r, pkt_idx))
		return -1;
	if (!memcmp(auth_tag, hmac, s->auth_tag_len))
		goto ok_update;

	return -1;

ok_update:
	*pkt_idx_p = pkt_idx;
	update_packet_index(c, s, pkt_idx);
ok:
	return 0;
}


/* XXX shared code */
static int srtp_encrypt_aes_cm(struct re_crypto_context *c,
		struct rtpengine_srtp *s, struct rtp_parsed *r,
		u_int64_t pkt_idx)
{
	unsigned char iv[16];
	u_int32_t *ivi;
	u_int32_t idxh, idxl;

	memcpy(iv, c->session_salt, 14);
	iv[14] = iv[15] = '\0';
	ivi = (void *) iv;
	pkt_idx <<= 16;
	idxh = htonl((pkt_idx & 0xffffffff00000000ULL) >> 32);
	idxl = htonl(pkt_idx & 0xffffffffULL);

	ivi[1] ^= r->header->ssrc;
	ivi[2] ^= idxh;
	ivi[3] ^= idxl;

	aes_ctr(r->payload, r->payload, r->payload_len, c->tfm[0], iv);

	return 0;
}

static int srtp_encrypt_aes_f8(struct re_crypto_context *c,
		struct rtpengine_srtp *s, struct rtp_parsed *r,
		u_int64_t pkt_idx)
{
	unsigned char iv[16];
	u_int32_t roc;

	iv[0] = 0;
	memcpy(&iv[1], &r->header->m_pt, 11);
	roc = htonl((pkt_idx & 0xffffffff0000ULL) >> 16);
	memcpy(&iv[12], &roc, sizeof(roc));

	aes_f8(r->payload, r->payload_len, c->tfm[0], c->tfm[1], iv);

	return 0;
}


static inline int srtp_encrypt(struct re_crypto_context *c,
		struct rtpengine_srtp *s, struct rtp_parsed *r,
		u_int64_t pkt_idx)
{
	if (!r->header)
		return 0;
	if (!c->cipher->encrypt)
		return 0;
	return c->cipher->encrypt(c, s, r, pkt_idx);
}

static inline int srtp_decrypt(struct re_crypto_context *c,
		struct rtpengine_srtp *s, struct rtp_parsed *r,
		u_int64_t pkt_idx)
{
	if (!c->cipher->decrypt)
		return 0;
	return c->cipher->decrypt(c, s, r, pkt_idx);
}

static inline int is_muxed_rtcp(struct rtp_parsed *r) {
	if (r->header->m_pt < 194)
		return 0;
	if (r->header->m_pt > 223)
		return 0;
	return 1;
}

static inline int is_dtls(struct sk_buff *skb) {
	if (skb->len < 1)
		return 0;
	if (skb->data[0] < 20)
		return 0;
	if (skb->data[0] > 63)
		return 0;
	return 1;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
static int rtp_payload_match(const void *a, const void *b) {
	const unsigned char *A = a, *B = b;

	if (*A < *B)
		return -1;
	if (*A > *B)
		return 1;
	return 0;
}
#endif

static inline int rtp_payload_type(const struct rtp_header *hdr, const struct rtpengine_target_info *tg) {
	unsigned char pt;
	const unsigned char *match;

	pt = hdr->m_pt & 0x7f;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
	match = bsearch(&pt, tg->payload_types, tg->num_payload_types, sizeof(pt), rtp_payload_match);
#else
	for (match = tg->payload_types; match < tg->payload_types + tg->num_payload_types; match++) {
		if (*match == pt)
			goto found;
	}
	match = NULL;
found:
#endif
	if (!match)
		return -1;
	return match - tg->payload_types;
}

static struct sk_buff *intercept_skb_copy(struct sk_buff *oskb, const struct re_address *src) {
	struct sk_buff *ret;
	struct udphdr *uh;
	struct iphdr *ih;
	struct ipv6hdr *ih6;

	ret = skb_copy_expand(oskb, MAX_HEADER, MAX_SKB_TAIL_ROOM, GFP_ATOMIC);
	if (!ret)
		return NULL;

	// restore original header. it's still present in the copied skb, so we just need
	// to push back our head room. the payload lengths might be wrong and must be fixed.
	// checksums might also be wrong, but can be ignored.

	// restore transport header
	skb_push(ret, ret->data - skb_transport_header(ret));
	uh = (void *) skb_transport_header(ret);
	uh->len = htons(ret->len);

	// restore network header
	skb_push(ret, ret->data - skb_network_header(ret));

	// restore network length field
	switch (src->family) {
		case AF_INET:
			ih = (void *) skb_network_header(ret);
			ih->tot_len = htons(ret->len);
			break;
		case AF_INET6:
			ih6 = (void *) skb_network_header(ret);
			ih6->payload_len = htons(ret->len - sizeof(*ih6));
			break;
		default:
			kfree_skb(ret);
			return NULL;
	}

	return ret;
}





static unsigned int rtpengine46(struct sk_buff *skb, struct rtpengine_table *t, struct re_address *src,
		struct re_address *dst, u_int8_t in_tos, const struct xt_action_param *par)
{
	struct udphdr *uh;
	struct rtpengine_target *g;
	struct sk_buff *skb2;
	int err;
	int error_nf_action = XT_CONTINUE;
	int rtp_pt_idx = -2;
	unsigned int datalen;
	u_int32_t *u32;
	struct rtp_parsed rtp;
	u_int64_t pkt_idx;
	struct re_stream *stream;
	struct re_stream_packet *packet;
	const char *errstr = NULL;

#if (RE_HAS_MEASUREDELAY)
	u_int64_t starttime, endtime, delay;
#endif

	skb_reset_transport_header(skb);
	uh = udp_hdr(skb);
	skb_pull(skb, sizeof(*uh));

	datalen = ntohs(uh->len);
	if (datalen < sizeof(*uh))
		goto skip2;
	datalen -= sizeof(*uh);
	DBG("udp payload = %u\n", datalen);
	skb_trim(skb, datalen);

	src->port = ntohs(uh->source);
	dst->port = ntohs(uh->dest);

	g = get_target(t, dst);
	if (!g)
		goto skip2;

	DBG("target found, src "MIPF" -> dst "MIPF"\n", MIPP(g->target.src_addr), MIPP(g->target.dst_addr));
	DBG("target decrypt hmac and cipher are %s and %s", g->decrypt.hmac->name,
			g->decrypt.cipher->name);

	if (!g->target.stun)
		goto not_stun;
	if (datalen < 28)
		goto not_stun;
	if ((datalen & 0x3))
		goto not_stun;
	u32 = (void *) skb->data;
	if (u32[1] != htonl(0x2112A442UL)) /* magic cookie */
		goto not_stun;
	if ((u32[0] & htonl(0xc0000003UL))) /* zero bits required by rfc */
		goto not_stun;
	u32 = (void *) &skb->data[datalen - 8];
	if (u32[0] != htonl(0x80280004UL)) /* required fingerprint attribute */
		goto not_stun;

	/* probably stun, pass to application */
	goto skip1;

not_stun:
	if (g->target.src_mismatch == MSM_IGNORE)
		goto src_check_ok;
	if (!memcmp(&g->target.expected_src, src, sizeof(*src)))
		goto src_check_ok;
	if (g->target.src_mismatch == MSM_PROPAGATE)
		goto skip1;
	/* MSM_DROP */
	error_nf_action = NF_DROP;
	errstr = "source address mismatch";
	goto skip_error;

src_check_ok:
	if (g->target.non_forwarding)
		goto skip1;
	if (g->target.dtls && is_dtls(skb))
		goto skip1;

	rtp.ok = 0;
	if (!g->target.rtp)
		goto not_rtp;

	parse_rtp(&rtp, skb);
	if (!rtp.ok) {
		if (g->target.rtp_only)
			goto skip1;
		goto not_rtp;
	}

	if (g->target.rtcp_mux && is_muxed_rtcp(&rtp))
		goto skip1;

	rtp_pt_idx = rtp_payload_type(rtp.header, &g->target);

	// Pass to userspace if SSRC has changed.
	errstr = "SSRC mismatch";
	if (unlikely((g->target.ssrc) && (g->target.ssrc != rtp.header->ssrc)))
		goto skip_error;

	pkt_idx = packet_index(&g->decrypt, &g->target.decrypt, rtp.header);
	errstr = "SRTP authentication tag mismatch";
	if (srtp_auth_validate(&g->decrypt, &g->target.decrypt, &rtp, &pkt_idx))
		goto skip_error;

	// if RTP, only forward packets of known/passthrough payload types
	if (g->target.rtp && rtp_pt_idx < 0)
		goto skip1;

	errstr = "SRTP decryption failed";
	if (srtp_decrypt(&g->decrypt, &g->target.decrypt, &rtp, pkt_idx))
		goto skip_error;

	skb_trim(skb, rtp.header_len + rtp.payload_len);

	DBG("packet payload decrypted as %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x...\n",
			rtp.payload[0], rtp.payload[1], rtp.payload[2], rtp.payload[3],
			rtp.payload[4], rtp.payload[5], rtp.payload[6], rtp.payload[7],
			rtp.payload[8], rtp.payload[9], rtp.payload[10], rtp.payload[11],
			rtp.payload[12], rtp.payload[13], rtp.payload[14], rtp.payload[15],
			rtp.payload[16], rtp.payload[17], rtp.payload[18], rtp.payload[19]);

not_rtp:
	if (g->target.mirror_addr.family) {
		DBG("sending mirror packet to dst "MIPF"\n", MIPP(g->target.mirror_addr));
		skb2 = skb_copy_expand(skb, MAX_HEADER, MAX_SKB_TAIL_ROOM, GFP_ATOMIC);
		err = send_proxy_packet(skb2, &g->target.src_addr, &g->target.mirror_addr, g->target.tos,
				par);
		if (err)
			atomic64_inc(&g->stats.errors);
	}

	if (g->target.do_intercept) {
		DBG("do_intercept is set\n");
		stream = get_stream_lock(NULL, g->target.intercept_stream_idx);
		if (!stream)
			goto no_intercept;
		packet = kzalloc(sizeof(*packet), GFP_ATOMIC);
		if (!packet)
			goto intercept_done;
		packet->skbuf = intercept_skb_copy(skb, src);
		if (!packet->skbuf)
			goto no_intercept_free;
		add_stream_packet(stream, packet);
		goto intercept_done;

no_intercept_free:
		free_packet(packet);
intercept_done:
		stream_put(stream);
	}

no_intercept:
	if (rtp.ok) {
		pkt_idx = packet_index(&g->encrypt, &g->target.encrypt, rtp.header);
		srtp_encrypt(&g->encrypt, &g->target.encrypt, &rtp, pkt_idx);
		skb_put(skb, g->target.encrypt.mki_len + g->target.encrypt.auth_tag_len);
		srtp_authenticate(&g->encrypt, &g->target.encrypt, &rtp, pkt_idx);

		// SSRC substitution
		if (g->target.transcoding && g->target.ssrc_out)
			rtp.header->ssrc = g->target.ssrc_out;
	}

	err = send_proxy_packet(skb, &g->target.src_addr, &g->target.dst_addr, g->target.tos, par);

	if (atomic64_read(&g->stats.packets)==0)
		atomic_set(&g->stats.in_tos,in_tos);

	if (err)
		atomic64_inc(&g->stats.errors);
	else {
		atomic64_inc(&g->stats.packets);
		atomic64_add(datalen, &g->stats.bytes);
	}

	if (rtp_pt_idx >= 0) {
		atomic64_inc(&g->rtp_stats[rtp_pt_idx].packets);
		atomic64_add(datalen, &g->rtp_stats[rtp_pt_idx].bytes);

#if (RE_HAS_MEASUREDELAY)
		starttime = ktime_to_ns(skb->tstamp);
		endtime = ktime_to_ns(ktime_get_real());

		delay = endtime - starttime;

		/* XXX needs locking - not atomic */
		if (atomic64_read(&g->stats.packets)==1) {
			g->stats.delay_min=delay;
			g->stats.delay_avg=delay;
			g->stats.delay_max=delay;
		} else {
			if (g->stats.delay_min > delay) {
				g->stats.delay_min = delay;
			}
			if (g->stats.delay_max < delay) {
				g->stats.delay_max = delay;
			}

			g->stats.delay_avg = g->stats.delay_avg * (atomic64_read(&g->stats.packets)-1);
			g->stats.delay_avg = g->stats.delay_avg + delay;
			g->stats.delay_avg = g->stats.delay_avg / atomic64_read(&g->stats.packets);
		}
#endif
	}
	else if (rtp_pt_idx == -2)
		/* not RTP */ ;
	else if (rtp_pt_idx == -1)
		atomic64_inc(&g->stats.errors);

	target_put(g);
	table_put(t);

	return NF_DROP;

skip_error:
	log_err("x_tables action failed: %s", errstr);
	atomic64_inc(&g->stats.errors);
skip1:
	target_put(g);
skip2:
	kfree_skb(skb);
	table_put(t);
	return error_nf_action;
}






static unsigned int rtpengine4(struct sk_buff *oskb, const struct xt_action_param *par) {
	const struct xt_rtpengine_info *pinfo = par->targinfo;
	struct sk_buff *skb;
	struct iphdr *ih;
	struct rtpengine_table *t;
	struct re_address src, dst;

	t = get_table(pinfo->id);
	if (!t)
		goto skip;

	skb = skb_copy_expand(oskb, MAX_HEADER, MAX_SKB_TAIL_ROOM, GFP_ATOMIC);
	if (!skb)
		goto skip3;

	skb_reset_network_header(skb);
	ih = ip_hdr(skb);
	skb_pull(skb, (ih->ihl << 2));
	if (ih->protocol != IPPROTO_UDP)
		goto skip2;

	memset(&src, 0, sizeof(src));
	memset(&dst, 0, sizeof(dst));
	src.family = AF_INET;
	src.u.ipv4 = ih->saddr;
	dst.family = AF_INET;
	dst.u.ipv4 = ih->daddr;

	return rtpengine46(skb, t, &src, &dst, (u_int8_t)ih->tos, par);

skip2:
	kfree_skb(skb);
skip3:
	table_put(t);
skip:
	return XT_CONTINUE;
}




static unsigned int rtpengine6(struct sk_buff *oskb, const struct xt_action_param *par) {
	const struct xt_rtpengine_info *pinfo = par->targinfo;
	struct sk_buff *skb;
	struct ipv6hdr *ih;
	struct rtpengine_table *t;
	struct re_address src, dst;

	t = get_table(pinfo->id);
	if (!t)
		goto skip;

	skb = skb_copy_expand(oskb, MAX_HEADER, MAX_SKB_TAIL_ROOM, GFP_ATOMIC);
	if (!skb)
		goto skip3;

	skb_reset_network_header(skb);
	ih = ipv6_hdr(skb);

	skb_pull(skb, sizeof(*ih));
	if (ih->nexthdr != IPPROTO_UDP)
		goto skip2;

	memset(&src, 0, sizeof(src));
	memset(&dst, 0, sizeof(dst));
	src.family = AF_INET6;
	memcpy(&src.u.ipv6, &ih->saddr, sizeof(src.u.ipv6));
	dst.family = AF_INET6;
	memcpy(&dst.u.ipv6, &ih->daddr, sizeof(dst.u.ipv6));

	return rtpengine46(skb, t, &src, &dst, ipv6_get_dsfield(ih), par);

skip2:
	kfree_skb(skb);
skip3:
	table_put(t);
skip:
	return XT_CONTINUE;
}





#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
#define CHECK_ERR false
#define CHECK_SCC true
static bool check(const struct xt_tgchk_param *par) {
#else
#define CHECK_ERR -EINVAL
#define CHECK_SCC 0
static int check(const struct xt_tgchk_param *par) {
#endif
	const struct xt_rtpengine_info *pinfo = par->targinfo;

	if (!my_proc_root) {
		printk(KERN_WARNING "xt_RTPENGINE check() without proc_root\n");
		return CHECK_ERR;
	}
	if (pinfo->id >= MAX_ID) {
		printk(KERN_WARNING "xt_RTPENGINE ID too high (%u >= %u)\n", pinfo->id, MAX_ID);
		return CHECK_ERR;
	}

	return CHECK_SCC;
}




static struct xt_target xt_rtpengine_regs[] = {
	{
		.name		= "RTPENGINE",
		.family		= NFPROTO_IPV4,
		.target		= rtpengine4,
		.targetsize	= sizeof(struct xt_rtpengine_info),
		.table		= "filter",
		.hooks		= (1 << NF_INET_LOCAL_IN),
		.checkentry	= check,
		.me		= THIS_MODULE,
	},
	{
		.name		= "RTPENGINE",
		.family		= NFPROTO_IPV6,
		.target		= rtpengine6,
		.targetsize	= sizeof(struct xt_rtpengine_info),
		.table		= "filter",
		.hooks		= (1 << NF_INET_LOCAL_IN),
		.checkentry	= check,
		.me		= THIS_MODULE,
	},
};

static int __init init(void) {
	int ret;
	const char *err;

	err = "stream_packets_list_limit parameter must be larger than 0";
	ret = -EINVAL;
	if (stream_packets_list_limit <= 0)
		goto fail;

	printk(KERN_NOTICE "Registering xt_RTPENGINE module - version %s\n", RTPENGINE_VERSION);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
	DBG("using uid %u, gid %d\n", proc_uid, proc_gid);
	proc_kuid = KUIDT_INIT(proc_uid);
	proc_kgid = KGIDT_INIT(proc_gid);
#endif
	rwlock_init(&table_lock);
	auto_array_init(&calls);
	auto_array_init(&streams);

	ret = -ENOMEM;
	err = "could not register /proc/ entries";
	my_proc_root = proc_mkdir_user("rtpengine", S_IRUGO | S_IXUGO, NULL);
	if (!my_proc_root)
		goto fail;
	/* my_proc_root->owner = THIS_MODULE; */

	proc_control = proc_create_user("control", S_IFREG | S_IWUSR | S_IWGRP, my_proc_root,
			&proc_main_control_ops, NULL);
	if (!proc_control)
		goto fail;

	proc_list = proc_create_user("list", S_IFREG | S_IRUGO, my_proc_root, &proc_main_list_ops, NULL);
	if (!proc_list)
		goto fail;

	err = "could not register xtables target";
	ret = xt_register_targets(xt_rtpengine_regs, ARRAY_SIZE(xt_rtpengine_regs));
	if (ret)
		goto fail;

	return 0;

fail:
	clear_proc(&proc_control);
	clear_proc(&proc_list);
	clear_proc(&my_proc_root);

	printk(KERN_ERR "Failed to load xt_RTPENGINE module: %s\n", err);

	return ret;
}

static void __exit fini(void) {
	printk(KERN_NOTICE "Unregistering xt_RTPENGINE module\n");
	xt_unregister_targets(xt_rtpengine_regs, ARRAY_SIZE(xt_rtpengine_regs));

	clear_proc(&proc_control);
	clear_proc(&proc_list);
	clear_proc(&my_proc_root);

	auto_array_free(&streams);
	auto_array_free(&calls);
}

module_init(init);
module_exit(fini);
