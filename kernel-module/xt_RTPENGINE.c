#include <linux/types.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/ip6_checksum.h>
#include <linux/udp.h>
#include <net/udp.h>
#include <linux/icmp.h>
#include <linux/version.h>
#include <linux/err.h>
#include <linux/crypto.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0)
#include <crypto/internal/cipher.h>
#endif
#include <crypto/aes.h>
#include <crypto/hash.h>
#include <crypto/aead.h>
#include <net/icmp.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/tcp.h>
#include <net/route.h>
#include <net/ip6_route.h>
#include <net/dst.h>
#include <linux/proc_fs.h>
#include <linux/spinlock.h>
#include <linux/bsearch.h>
#include <asm/atomic.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/netfilter/x_tables.h>
#include <linux/crc32.h>
#include <linux/math64.h>
#include <linux/kthread.h>
#include <linux/wait.h>
#ifdef CONFIG_BTREE
#include <linux/btree.h>
#define KERNEL_PLAYER
#else
#warning "Kernel without CONFIG_BTREE - kernel media player unavailable"
#endif

#include "xt_RTPENGINE.h"

MODULE_LICENSE("GPL");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,13,0)
MODULE_IMPORT_NS("CRYPTO_INTERNAL");
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0)
MODULE_IMPORT_NS(CRYPTO_INTERNAL);
#endif
MODULE_ALIAS("ipt_RTPENGINE");
MODULE_ALIAS("ip6t_RTPENGINE");

// fix for older compilers
#ifndef RHEL_RELEASE_VERSION
#define RHEL_RELEASE_VERSION(x,y) 0
#endif




#define MAX_ID 64 /* - 1 */
#define MAX_SKB_TAIL_ROOM (sizeof(((struct rtpengine_srtp *) 0)->mki) + 20 + 16)

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

// RFC 3711 non-complience (4 vs 6, see rtcp.c)
#define SRTCP_R_LENGTH 6

#if 0
#define DBG(fmt, ...) printk(KERN_DEBUG "[PID %i line %i] " fmt, current ? current->pid : -1, \
		__LINE__, ##__VA_ARGS__)
#else
#define DBG(x...) ((void)0)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
#define PAR_STATE_NET(p) (p)->state->net
#else /* minimum 4.4.x */
#define PAR_STATE_NET(p) (p)->net
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





#if defined(RHEL_RELEASE_CODE) && LINUX_VERSION_CODE >= KERNEL_VERSION(5,14,0) && \
		RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(9,1)
#define PDE_DATA(i) pde_data(i)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5,17,0)
#define PDE_DATA(i) pde_data(i)
#endif




struct re_hmac;
struct re_cipher;
struct rtp_parsed;
struct re_crypto_context;
struct re_auto_array;
struct re_call;
struct re_stream;
struct rtpengine_table;
struct crypto_aead;
struct rtpengine_output;



static kuid_t proc_kuid;
static uint proc_uid = 0;
module_param(proc_uid, uint, 0444);
MODULE_PARM_DESC(proc_uid, "rtpengine procfs tree user id");

static kgid_t proc_kgid;
static uint proc_gid = 0;
module_param(proc_gid, uint, 0444);
MODULE_PARM_DESC(proc_gid, "rtpengine procfs tree group id");

static int proc_mask;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
module_param(proc_mask, hexint, 0444);
#else
module_param(proc_mask, uint, 0444);
#endif
MODULE_PARM_DESC(proc_mask, "rtpengine procfs tree mode mask");

static uint stream_packets_list_limit = 10;
module_param(stream_packets_list_limit, uint, 0444);
MODULE_PARM_DESC(stream_packets_list_limit, "maximum number of packets to retain for intercept streams");

static bool log_errors = 0;
module_param(log_errors, bool, 0644);
MODULE_PARM_DESC(log_errors, "generate kernel log lines from forwarding errors");



#define log_err(fmt, ...) do { if (log_errors) printk(KERN_NOTICE "rtpengine[%s:%i]: " fmt, \
		__FUNCTION__, __LINE__, ##__VA_ARGS__); } while (0)




static ssize_t proc_control_read(struct file *, char __user *, size_t, loff_t *);
static ssize_t proc_control_write(struct file *, const char __user *, size_t, loff_t *);
static int proc_control_open(struct inode *, struct file *);
static int proc_control_close(struct inode *, struct file *);
static int proc_control_mmap(struct file *, struct vm_area_struct *);

static ssize_t proc_status(struct file *, char __user *, size_t, loff_t *);

static ssize_t proc_main_control_write(struct file *, const char __user *, size_t, loff_t *);

static int proc_generic_open_modref(struct inode *, struct file *);
static int proc_generic_open_stream_modref(struct inode *inode, struct file *file);
static int proc_generic_close_modref(struct inode *, struct file *);
static int proc_generic_seqrelease_modref(struct inode *inode, struct file *file);

static int proc_list_open(struct inode *, struct file *);

static void *proc_list_start(struct seq_file *, loff_t *);
static void proc_list_stop(struct seq_file *, void *);
static void *proc_list_next(struct seq_file *, void *, loff_t *);
static int proc_list_show(struct seq_file *, void *);

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

static int aes_f8_session_key_init(struct re_crypto_context *, const struct rtpengine_srtp *);
static int srtp_encrypt_aes_cm(struct re_crypto_context *, struct rtpengine_srtp *,
		struct rtp_parsed *, uint32_t *);
static int srtcp_encrypt_aes_cm(struct re_crypto_context *, struct rtpengine_srtp *,
		struct rtp_parsed *, uint32_t *);
static int srtp_encrypt_aes_f8(struct re_crypto_context *, struct rtpengine_srtp *,
		struct rtp_parsed *, uint32_t *);
static int srtcp_encrypt_aes_f8(struct re_crypto_context *, struct rtpengine_srtp *,
		struct rtp_parsed *, uint32_t *);
static int srtp_encrypt_aes_gcm(struct re_crypto_context *, struct rtpengine_srtp *,
		struct rtp_parsed *, uint32_t *);
static int srtcp_encrypt_aes_gcm(struct re_crypto_context *, struct rtpengine_srtp *,
		struct rtp_parsed *, uint32_t *);
static int srtp_decrypt_aes_gcm(struct re_crypto_context *, struct rtpengine_srtp *,
		struct rtp_parsed *, uint32_t *);
static int srtcp_decrypt_aes_gcm(struct re_crypto_context *, struct rtpengine_srtp *,
		struct rtp_parsed *, uint32_t *);

static int send_proxy_packet_output(struct sk_buff *skb, struct rtpengine_target *g,
		int rtp_pt_idx,
		struct rtpengine_output *o, struct rtp_parsed *rtp, int ssrc_idx,
		const struct xt_action_param *par);
static int send_proxy_packet(struct sk_buff *skb, struct re_address *src, struct re_address *dst,
		unsigned char tos, const struct xt_action_param *par);
static uint32_t proxy_packet_srtp_encrypt(struct sk_buff *skb, struct re_crypto_context *ctx,
		struct rtpengine_srtp *srtp,
		struct rtp_parsed *rtp, int ssrc_idx,
		struct ssrc_stats **ssrc_stats);

static void call_put(struct re_call *call);
static void del_stream(struct re_stream *stream, struct rtpengine_table *);
static void del_call(struct re_call *call, struct rtpengine_table *);

static inline int bitfield_set(unsigned long *bf, unsigned int i);
static inline int bitfield_clear(unsigned long *bf, unsigned int i);




// mirror global_stats_counter from userspace
struct global_stats_counter {
#define F(x) atomic64_t x;
#include "kernel_counter_stats_fields.inc"
#undef F
};

struct re_crypto_context {
	spinlock_t			lock; /* protects roc and last_*_index */
	unsigned char			session_key[32];
	unsigned char			session_salt[14];
	unsigned char			session_auth_key[20];
	struct crypto_cipher		*tfm[2];
	struct crypto_shash		*shash;
	struct crypto_aead		*aead;
	const struct re_cipher		*cipher;
	const struct re_hmac		*hmac;
};

struct rtpengine_output {
	struct rtpengine_output_info	output;
	struct re_crypto_context	encrypt_rtp;
	struct re_crypto_context	encrypt_rtcp;
};
struct rtpengine_target {
	atomic_t			refcnt;
	uint32_t			table;
	struct rtpengine_target_info	target;
	unsigned int			last_pt; // index into pt_input[] and pt_output[]

	spinlock_t			ssrc_stats_lock;

	struct re_crypto_context	decrypt_rtp;
	struct re_crypto_context	decrypt_rtcp;

	rwlock_t			outputs_lock;
	struct rtpengine_output		*outputs;
	unsigned int			num_rtp_destinations;
	unsigned int			outputs_unfilled; // only ever decreases
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
	struct proc_dir_entry		*proc_calls;

	struct re_dest_addr_hash	dest_addr_hash;

	unsigned int			num_targets;

	struct list_head		calls; /* protected by calls.lock */

	spinlock_t			calls_hash_lock[1 << RE_HASH_BITS];
	struct hlist_head		calls_hash[1 << RE_HASH_BITS];
	spinlock_t			streams_hash_lock[1 << RE_HASH_BITS];
	struct hlist_head		streams_hash[1 << RE_HASH_BITS];

	spinlock_t			shm_lock;
	struct list_head		shm_list;

	struct global_stats_counter	*rtpe_stats;

	spinlock_t			player_lock;
	struct list_head		play_streams;
	unsigned int			num_play_streams;
	struct list_head		packet_streams;
	unsigned int			num_packet_streams;
};

struct re_cipher {
	enum rtpengine_cipher		id;
	const char			*name;
	const char			*tfm_name;
	const char			*aead_name;
	int				(*decrypt_rtp)(struct re_crypto_context *, struct rtpengine_srtp *,
			struct rtp_parsed *, uint32_t *);
	int				(*encrypt_rtp)(struct re_crypto_context *, struct rtpengine_srtp *,
			struct rtp_parsed *, uint32_t *);
	int				(*decrypt_rtcp)(struct re_crypto_context *, struct rtpengine_srtp *,
			struct rtp_parsed *, uint32_t *);
	int				(*encrypt_rtcp)(struct re_crypto_context *, struct rtpengine_srtp *,
			struct rtp_parsed *, uint32_t *);
	int				(*session_key_init)(struct re_crypto_context *, const struct rtpengine_srtp *);
};

struct re_hmac {
	enum rtpengine_hmac		id;
	const char			*name;
	const char			*tfm_name;
};

struct re_shm {
	void				*head;
	size_t				size;
	unsigned int			order;
	struct list_head		list_entry;
};

/* XXX shared */
struct rtp_header {
	unsigned char v_p_x_cc;
	unsigned char m_pt;
	uint16_t seq_num;
	uint32_t timestamp;
	uint32_t ssrc;
	uint32_t csrc[];
} __attribute__ ((packed));
struct rtcp_header {
	unsigned char v_p_x_cc;
	unsigned char pt;
	uint16_t length;
	uint32_t ssrc;
} __attribute__ ((packed));
struct rtp_extension {
	uint16_t undefined;
	uint16_t length;
} __attribute__ ((packed));


struct rtp_parsed {
	union {
		struct rtp_header		*rtp_header;
		struct rtcp_header		*rtcp_header;
	};
	unsigned int			header_len;
	unsigned char			*payload;
	unsigned int			payload_len;
	int				ok;
	int				rtcp;
};

#ifdef KERNEL_PLAYER

struct play_stream_packet {
	struct list_head list;
	ktime_t delay;
	uint32_t ts;
	uint32_t duration_ts;
	uint16_t seq;
	//struct sk_buff *skb;
	char *data;
	size_t len;
};

struct play_stream_packets {
	atomic_t refcnt;
	rwlock_t lock;
	struct list_head packets;
	unsigned int len;
	unsigned int table_id;
	struct list_head table_entry;
	unsigned int idx;
};

struct play_stream {
	spinlock_t lock;
	atomic_t refcnt;
	unsigned int idx;
	struct rtpengine_play_stream_info info;
	struct re_crypto_context encrypt;
	struct play_stream_packets *packets;
	ktime_t start_time;
	struct play_stream_packet *position;
	struct timer_thread *timer_thread;
	uint64_t tree_index;
	unsigned int table_id;
	struct list_head table_entry;
};

struct timer_thread {
	struct list_head list;
	unsigned int idx;
	struct task_struct *task;

	wait_queue_head_t queue;
	atomic_t shutdown;

	spinlock_t tree_lock; // XXX use mutex?
	struct btree_head64 tree; // timer entries // XXX use rbtree?
	bool tree_added;
	struct play_stream *scheduled;
	ktime_t scheduled_at;
};


static void free_packet_stream(struct play_stream_packets *stream);
static void free_play_stream_packet(struct play_stream_packet *p);
static void free_play_stream(struct play_stream *s);
static void do_stop_stream(struct play_stream *stream);

#endif


static struct proc_dir_entry *my_proc_root;
static struct proc_dir_entry *proc_list;
static struct proc_dir_entry *proc_control;

static struct rtpengine_table *table[MAX_ID];
static rwlock_t table_lock;

static struct re_auto_array calls;
static struct re_auto_array streams;

#ifdef KERNEL_PLAYER
static rwlock_t media_player_lock;
static struct play_stream_packets **stream_packets;
static unsigned int num_stream_packets;
static atomic_t last_stream_packets_idx;

static struct play_stream **play_streams;
static unsigned int num_play_streams;
static atomic_t last_play_stream_idx;

static struct timer_thread **timer_threads;
static unsigned int num_timer_threads;
static atomic_t last_timer_thread_idx;
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)
#  define PROC_OP_STRUCT file_operations
#  define PROC_OWNER \
	.owner			= THIS_MODULE,
#  define PROC_READ read
#  define PROC_WRITE write
#  define PROC_OPEN open
#  define PROC_RELEASE release
#  define PROC_LSEEK llseek
#  define PROC_POLL poll
#  define PROC_MMAP mmap
#else
#  define PROC_OP_STRUCT proc_ops
#  define PROC_OWNER
#  define PROC_READ proc_read
#  define PROC_WRITE proc_write
#  define PROC_OPEN proc_open
#  define PROC_RELEASE proc_release
#  define PROC_LSEEK proc_lseek
#  define PROC_POLL proc_poll
#  define PROC_MMAP proc_mmap
#endif

static const struct PROC_OP_STRUCT proc_control_ops = {
	PROC_OWNER
	.PROC_READ		= proc_control_read,
	.PROC_WRITE		= proc_control_write,
	.PROC_OPEN		= proc_control_open,
	.PROC_RELEASE		= proc_control_close,
	.PROC_MMAP		= proc_control_mmap,
};

static const struct PROC_OP_STRUCT proc_main_control_ops = {
	PROC_OWNER
	.PROC_WRITE		= proc_main_control_write,
	.PROC_OPEN		= proc_generic_open_stream_modref,
	.PROC_RELEASE		= proc_generic_close_modref,
};

static const struct PROC_OP_STRUCT proc_status_ops = {
	PROC_OWNER
	.PROC_READ		= proc_status,
	.PROC_OPEN		= proc_generic_open_modref,
	.PROC_RELEASE		= proc_generic_close_modref,
};

static const struct PROC_OP_STRUCT proc_list_ops = {
	PROC_OWNER
	.PROC_OPEN		= proc_list_open,
	.PROC_READ		= seq_read,
	.PROC_LSEEK		= seq_lseek,
	.PROC_RELEASE		= proc_generic_seqrelease_modref,
};

static const struct seq_operations proc_list_seq_ops = {
	.start			= proc_list_start,
	.next			= proc_list_next,
	.stop			= proc_list_stop,
	.show			= proc_list_show,
};

static const struct PROC_OP_STRUCT proc_main_list_ops = {
	PROC_OWNER
	.PROC_OPEN		= proc_main_list_open,
	.PROC_READ		= seq_read,
	.PROC_LSEEK		= seq_lseek,
	.PROC_RELEASE		= proc_generic_seqrelease_modref,
};

static const struct seq_operations proc_main_list_seq_ops = {
	.start			= proc_main_list_start,
	.next			= proc_main_list_next,
	.stop			= proc_main_list_stop,
	.show			= proc_main_list_show,
};

static const struct PROC_OP_STRUCT proc_stream_ops = {
	PROC_OWNER
	.PROC_READ		= proc_stream_read,
	.PROC_POLL		= proc_stream_poll,
	.PROC_OPEN		= proc_stream_open,
	.PROC_RELEASE		= proc_stream_close,
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
		.decrypt_rtp	= srtp_encrypt_aes_cm,
		.encrypt_rtp	= srtp_encrypt_aes_cm,
		.decrypt_rtcp	= srtcp_encrypt_aes_cm,
		.encrypt_rtcp	= srtcp_encrypt_aes_cm,
	},
	[REC_AES_F8] = {
		.id		= REC_AES_F8,
		.name		= "AES-F8",
		.tfm_name	= "aes",
		.decrypt_rtp	= srtp_encrypt_aes_f8,
		.encrypt_rtp	= srtp_encrypt_aes_f8,
		.decrypt_rtcp	= srtcp_encrypt_aes_f8,
		.encrypt_rtcp	= srtcp_encrypt_aes_f8,
		.session_key_init = aes_f8_session_key_init,
	},
	[REC_AES_CM_192] = {
		.id		= REC_AES_CM_192,
		.name		= "AES-CM-192",
		.tfm_name	= "aes",
		.decrypt_rtp	= srtp_encrypt_aes_cm,
		.encrypt_rtp	= srtp_encrypt_aes_cm,
		.decrypt_rtcp	= srtcp_encrypt_aes_cm,
		.encrypt_rtcp	= srtcp_encrypt_aes_cm,
	},
	[REC_AES_CM_256] = {
		.id		= REC_AES_CM_256,
		.name		= "AES-CM-256",
		.tfm_name	= "aes",
		.decrypt_rtp	= srtp_encrypt_aes_cm,
		.encrypt_rtp	= srtp_encrypt_aes_cm,
		.decrypt_rtcp	= srtcp_encrypt_aes_cm,
		.encrypt_rtcp	= srtcp_encrypt_aes_cm,
	},
	[REC_AEAD_AES_GCM_128] = {
		.id		= REC_AEAD_AES_GCM_128,
		.name		= "AEAD-AES-GCM-128",
		.aead_name	= "gcm(aes)",
		.decrypt_rtp	= srtp_decrypt_aes_gcm,
		.encrypt_rtp	= srtp_encrypt_aes_gcm,
		.decrypt_rtcp	= srtcp_decrypt_aes_gcm,
		.encrypt_rtcp	= srtcp_encrypt_aes_gcm,
	},
	[REC_AEAD_AES_GCM_256] = {
		.id		= REC_AEAD_AES_GCM_256,
		.name		= "AEAD-AES-GCM-256",
		.aead_name	= "gcm(aes)",
		.decrypt_rtp	= srtp_decrypt_aes_gcm,
		.encrypt_rtp	= srtp_encrypt_aes_gcm,
		.decrypt_rtcp	= srtcp_decrypt_aes_gcm,
		.encrypt_rtcp	= srtcp_encrypt_aes_gcm,
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
	INIT_LIST_HEAD(&t->shm_list);
	spin_lock_init(&t->shm_lock);
	INIT_LIST_HEAD(&t->packet_streams);
	INIT_LIST_HEAD(&t->play_streams);
	t->id = -1;
	spin_lock_init(&t->player_lock);

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

	ret = proc_mkdir_mode(name, mode, parent);
	if (!ret)
		return NULL;
	proc_set_user(ret, proc_kuid, proc_kgid);

	return ret;
}
static inline struct proc_dir_entry *proc_create_user(const char *name, umode_t mode,
		struct proc_dir_entry *parent, const struct PROC_OP_STRUCT *ops,
		void *ptr)
{
	struct proc_dir_entry *ret;

	ret = proc_create_data(name, mode, parent, ops, ptr);
	if (!ret)
		return NULL;
	proc_set_user(ret, proc_kuid, proc_kgid);

	return ret;
}



static int table_create_proc(struct rtpengine_table *t, uint32_t id) {
	char num[10];

	sprintf(num, "%u", id);

	t->proc_root = proc_mkdir_user(num, 0555 & ~proc_mask, my_proc_root);
	if (!t->proc_root)
		return -1;

	t->proc_status = proc_create_user("status", S_IFREG | 0444, t->proc_root, &proc_status_ops,
		(void *) (unsigned long) id);
	if (!t->proc_status)
		return -1;

	t->proc_control = proc_create_user("control", S_IFREG | 0660,
			t->proc_root,
			&proc_control_ops, (void *) (unsigned long) id);
	if (!t->proc_control)
		return -1;

	t->proc_list = proc_create_user("list", S_IFREG | 0444, t->proc_root,
			&proc_list_ops, (void *) (unsigned long) id);
	if (!t->proc_list)
		return -1;

	t->proc_calls = proc_mkdir_user("calls", 0555, t->proc_root);
	if (!t->proc_calls)
		return -1;

	return 0;
}




static struct rtpengine_table *new_table_link(uint32_t id) {
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
	if (c->aead)
		crypto_free_aead(c->aead);
}

static void target_put(struct rtpengine_target *t) {
	unsigned int i;

	if (!t)
		return;

	if (!atomic_dec_and_test(&t->refcnt))
		return;

	DBG("Freeing target\n");

	free_crypto_context(&t->decrypt_rtp);
	free_crypto_context(&t->decrypt_rtcp);

	if (t->outputs) {
		for (i = 0; i < t->target.num_destinations; i++) {
			free_crypto_context(&t->outputs[i].encrypt_rtp);
			free_crypto_context(&t->outputs[i].encrypt_rtcp);
		}
		kfree(t->outputs);
	}
	kfree(t);
}



static void target_get(struct rtpengine_target *t) {
	atomic_inc(&t->refcnt);
}



static void clear_proc(struct proc_dir_entry **e) {
	struct proc_dir_entry *pde;

	if (!e || !(pde = *e))
		return;

	proc_remove(pde);
	*e = NULL;
}




#ifdef KERNEL_PLAYER

static void __unref_play_stream(struct play_stream *s);
static void __unref_packet_stream(struct play_stream_packets *stream);
static void end_of_stream(struct play_stream *stream);

#define unref_play_stream(s) do { \
	/* printk(KERN_WARNING "unref play stream %p (%i--) @ %s:%i\n", s, atomic_read(&(s)->refcnt), __FILE__, __LINE__); */ \
	__unref_play_stream(s); \
} while (0)

#define ref_play_stream(s) do { \
	/* printk(KERN_WARNING "ref play stream %p (%i++) @ %s:%i\n", s, atomic_read(&(s)->refcnt), __FILE__, __LINE__); */ \
	atomic_inc(&(s)->refcnt); \
} while (0)

#define ref_packet_stream(s) do { \
	/* printk(KERN_WARNING "ref packet stream %p (%i++) @ %s:%i\n", s, atomic_read(&(s)->refcnt), __FILE__, __LINE__); */ \
	atomic_inc(&(s)->refcnt); \
} while (0)

#define unref_packet_stream(s) do { \
	/* printk(KERN_WARNING "unref packet stream %p (%i--) @ %s:%i\n", s, atomic_read(&(s)->refcnt), __FILE__, __LINE__); */ \
	__unref_packet_stream(s); \
} while (0)

#endif

static void clear_table_proc_files(struct rtpengine_table *t) {
	clear_proc(&t->proc_status);
	clear_proc(&t->proc_control);
	clear_proc(&t->proc_list);
	clear_proc(&t->proc_calls);
	clear_proc(&t->proc_root);
}

#ifdef KERNEL_PLAYER

static void clear_table_player(struct rtpengine_table *t) {
	struct play_stream *stream, *ts;
	struct play_stream_packets *packets, *tp;
	unsigned int idx;

	list_for_each_entry_safe(stream, ts, &t->play_streams, table_entry) {
		spin_lock(&stream->lock);
		stream->table_id = -1;
		idx = stream->idx;
		spin_unlock(&stream->lock);
		write_lock(&media_player_lock);
		if (play_streams[idx] == stream) {
			play_streams[idx] = NULL;
			unref_play_stream(stream);
		}
		write_unlock(&media_player_lock);
		do_stop_stream(stream);
		unref_play_stream(stream);
	}

	list_for_each_entry_safe(packets, tp, &t->packet_streams, table_entry) {
		write_lock(&packets->lock);
		packets->table_id = -1;
		idx = packets->idx;
		write_unlock(&packets->lock);
		write_lock(&media_player_lock);
		if (stream_packets[idx] == packets) {
			stream_packets[idx] = NULL;
			unref_packet_stream(packets);
		}
		write_unlock(&media_player_lock);
		unref_packet_stream(packets);
	}
}

#endif

static void table_put(struct rtpengine_table *t) {
	int i, j, k;
	struct re_dest_addr *rda;
	struct re_bucket *b;
	struct re_shm *shm;

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

	while (!list_empty(&t->shm_list)) {
		shm = list_first_entry(&t->shm_list, struct re_shm, list_entry);
		list_del_init(&shm->list_entry);
		free_pages((unsigned long) shm->head, shm->order);
		kfree(shm);
	}

	clear_table_proc_files(t);
#ifdef KERNEL_PLAYER
	clear_table_player(t);
#endif
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
	uint32_t id;

	if (*o > 0)
		return 0;
	if (*o < 0)
		return -EINVAL;
	if (l < sizeof(buf))
		return -EINVAL;

	inode = f->f_path.dentry->d_inode;
	id = (uint32_t) (unsigned long) PDE_DATA(inode);
	t = get_table(id);
	if (!t)
		return -ENOENT;

	read_lock_irqsave(&t->target_lock, flags);
	len += sprintf(buf + len, "Refcount:    %u\n", atomic_read(&t->refcnt) - 1);
	len += sprintf(buf + len, "Control PID: %u\n", t->pid);
	len += sprintf(buf + len, "Targets:     %u\n", t->num_targets);
	read_unlock_irqrestore(&t->target_lock, flags);

	// unlocked/unsafe read
	len += sprintf(buf + len, "Players:     %u\n", t->num_play_streams);
	len += sprintf(buf + len, "PStreams:    %u\n", t->num_packet_streams);

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
	uint32_t id;

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

	return g;
}



static int proc_list_open(struct inode *i, struct file *f) {
	int err;
	struct seq_file *p;
	uint32_t id;
	struct rtpengine_table *t;

	if ((err = proc_generic_open_modref(i, f)))
		return err;

	id = (uint32_t) (unsigned long) PDE_DATA(i);
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

static void *proc_list_next(struct seq_file *f, void *v, loff_t *o) {
	uint32_t id = (uint32_t) (unsigned long) f->private;
	struct rtpengine_table *t;
	struct rtpengine_target *g;
	int port, addr_bucket;

	addr_bucket = ((int) *o) >> 17;
	port = ((int) *o) & 0x1ffff;

	t = get_table(id);
	if (!t)
		return NULL;

	if (v) // this is a `next` call
		port++;

	g = find_next_target(t, &addr_bucket, &port);

	*o = (addr_bucket << 17) | port;
	table_put(t);

	if (!g) // EOF
		*o = 256 << 17;

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
	int i;

	if (c->cipher && c->cipher->id != REC_NULL) {
		if (!hdr++)
			seq_printf(f, "    SRTP %s parameters:\n", label);
		seq_printf(f, "        cipher: %s\n", c->cipher->name ? : "<invalid>");

		seq_printf(f, "    master key: ");
		for (i = 0; i < s->master_key_len; i++)
			seq_printf(f, "%02x", s->master_key[i]);
		seq_printf(f, "\n");

		seq_printf(f, "   master salt: ");
		for (i = 0; i < sizeof(s->master_salt); i++)
			seq_printf(f, "%02x", s->master_salt[i]);
		seq_printf(f, "\n");

		seq_printf(f, "   session key: ");
		for (i = 0; i < s->session_key_len; i++)
			seq_printf(f, "%02x", c->session_key[i]);
		seq_printf(f, "\n");

		seq_printf(f, "  session salt: ");
		for (i = 0; i < sizeof(c->session_salt); i++)
			seq_printf(f, "%02x", c->session_salt[i]);
		seq_printf(f, "\n");

		seq_printf(f, "  session auth: ");
		for (i = 0; i < sizeof(c->session_auth_key); i++)
			seq_printf(f, "%02x", c->session_auth_key[i]);
		seq_printf(f, "\n");

		if (s->mki_len)
			seq_printf(f, "            MKI: length %u, %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x...\n",
					s->mki_len,
					s->mki[0], s->mki[1], s->mki[2], s->mki[3],
					s->mki[4], s->mki[5], s->mki[6], s->mki[7]);
	}
	if (c->hmac && c->hmac->id != REH_NULL) {
		if (!hdr++)
			seq_printf(f, "      SRTP %s parameters:\n", label);
		seq_printf(f, "          HMAC: %s\n", c->hmac->name ? : "<invalid>");
		seq_printf(f, "            auth tag length: %u\n", s->rtp_auth_tag_len);
	}
}

static int proc_list_show(struct seq_file *f, void *v) {
	struct rtpengine_target *g = v;
	unsigned int i, j;
	unsigned long flags;

	seq_printf(f, "local ");
	seq_addr_print(f, &g->target.local);
	seq_printf(f, "\n");

	// all outputs filled?
	_r_lock(&g->outputs_lock, flags);
	if (g->outputs_unfilled) {
		unsigned int uf = g->outputs_unfilled;
		_r_unlock(&g->outputs_lock, flags);
		seq_printf(f, "    outputs not fully filled (%u missing)\n", uf);
		goto out;
	}
	_r_unlock(&g->outputs_lock, flags);

	proc_list_addr_print(f, "expect", &g->target.expected_src);
	if (g->target.src_mismatch > 0 && g->target.src_mismatch <= ARRAY_SIZE(re_msm_strings))
		seq_printf(f, "    src mismatch action: %s\n", re_msm_strings[g->target.src_mismatch]);
	seq_printf(f, "    stats: %20llu bytes, %20llu packets, %20llu errors\n",
		(unsigned long long) atomic64_read(&g->target.stats->bytes),
		(unsigned long long) atomic64_read(&g->target.stats->packets),
		(unsigned long long) atomic64_read(&g->target.stats->errors));
	for (i = 0; i < g->target.num_payload_types; i++) {
		seq_printf(f, "        RTP payload type %3u: %20llu bytes, %20llu packets\n",
			g->target.pt_stats[i]->payload_type,
			(unsigned long long) atomic64_read(&g->target.pt_stats[i]->bytes),
			(unsigned long long) atomic64_read(&g->target.pt_stats[i]->packets));
	}

	seq_printf(f, "    last packet: %lli", (long long) atomic64_read(&g->target.stats->last_packet));

	seq_printf(f, "    SSRC in:");
	for (i = 0; i < ARRAY_SIZE(g->target.ssrc); i++) {
		if (!g->target.ssrc[i] || !g->target.ssrc_stats[i])
			break;
		seq_printf(f, "%s %lx [seq %u/%u]",
				(i == 0) ? "" : ",",
				(unsigned long) ntohl(g->target.ssrc[i]),
				atomic_read(&g->target.ssrc_stats[i]->ext_seq),
				atomic_read(&g->target.ssrc_stats[i]->rtcp_seq));
	}
	seq_printf(f, "\n");

	proc_list_crypto_print(f, &g->decrypt_rtp, &g->target.decrypt, "decryption");

	seq_printf(f, "    options:");
	if (g->target.rtp)
		seq_printf(f, " RTP");
	if (g->target.pt_filter)
		seq_printf(f, " PT-filter");
	if (g->target.rtp_only)
		seq_printf(f, " RTP-only");
	if (g->target.rtcp)
		seq_printf(f, " RTCP");
	if (g->target.rtcp_mux)
		seq_printf(f, " RTCP-mux");
	if (g->target.dtls)
		seq_printf(f, " DTLS");
	if (g->target.stun)
		seq_printf(f, " STUN");
	if (g->target.non_forwarding)
		seq_printf(f, " non-forwarding");
	if (g->target.blackhole)
		seq_printf(f, " blackhole");
	if (g->target.rtp_stats)
		seq_printf(f, " RTP-stats");
	if (g->target.track_ssrc)
		seq_printf(f, " SSRC-tracking");
	if (g->target.do_intercept)
		seq_printf(f, " intercept");
	if (g->target.rtcp_fw)
		seq_printf(f, " forward-RTCP");
	if (g->target.rtcp_fb_fw)
		seq_printf(f, " forward-RTCP-FB");
	seq_printf(f, "\n");

	for (i = 0; i < g->target.num_destinations; i++) {
		struct rtpengine_output *o = &g->outputs[i];
		if (i < g->num_rtp_destinations)
			seq_printf(f, "    output #%u\n", i);
		else
			seq_printf(f, "    output #%u (RTCP)\n", i);
		proc_list_addr_print(f, "src", &o->output.src_addr);
		proc_list_addr_print(f, "dst", &o->output.dst_addr);

		seq_printf(f, "      stats: %20llu bytes, %20llu packets, %20llu errors\n",
			(unsigned long long) atomic64_read(&o->output.stats->bytes),
			(unsigned long long) atomic64_read(&o->output.stats->packets),
			(unsigned long long) atomic64_read(&o->output.stats->errors));

		seq_printf(f, " SSRC out:");
		for (j = 0; j < ARRAY_SIZE(o->output.ssrc_out); j++) {
			if (!o->output.ssrc_stats[j])
				break;
			seq_printf(f, "%s %lx [seq %u+%u/%u]",
					(j == 0) ? "" : ",",
					(unsigned long) ntohl(o->output.ssrc_out[j]),
					atomic_read(&o->output.ssrc_stats[j]->ext_seq),
					(unsigned int) o->output.seq_offset[j],
					atomic_read(&o->output.ssrc_stats[j]->rtcp_seq));
		}
		seq_printf(f, "\n");

		for (j = 0; j < g->target.num_payload_types; j++) {
			if (o->output.pt_output[j].replace_pattern_len || o->output.pt_output[j].min_payload_len)
				seq_printf(f, "        RTP payload type %3u: "
						"%u bytes replacement payload, min payload len %u\n",
						g->target.pt_stats[j]->payload_type,
						o->output.pt_output[j].replace_pattern_len,
						o->output.pt_output[j].min_payload_len);
		}

		proc_list_crypto_print(f, &o->encrypt_rtp, &o->output.encrypt, "encryption");
	}

out:
	target_put(g);
	return 0;
}




static unsigned int re_address_hash(const struct re_address *a) {
	uint32_t ret = 0;

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




// removes a target from the table and returns it
static struct rtpengine_target *table_steal_target(struct rtpengine_table *t, const struct re_address *local) {
	unsigned char hi, lo;
	struct re_dest_addr *rda;
	struct re_bucket *b;
	struct rtpengine_target *g = NULL;
	unsigned long flags;

	if (!local || !is_valid_address(local))
		return ERR_PTR(-EINVAL);

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
		return ERR_PTR(-ENOENT);
	if (b)
		kfree(b);

	return g;
}



// removes target from table and returns the stats before releasing the target
static int table_del_target(struct rtpengine_table *t, const struct re_address *local) {
	struct rtpengine_target *g = table_steal_target(t, local);

	if (IS_ERR(g))
		return PTR_ERR(g);

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

static void vm_mmap_close(struct vm_area_struct *vma) {
}
static const struct vm_operations_struct vm_mmap_ops = {
	.close = vm_mmap_close,
};

static void *shm_map_resolve(void *p, size_t size) {
	struct vm_area_struct *vma;
	// XXX is there a better way to map this to the kernel address?
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,14,0)
	vma = vma_lookup(current->mm, (unsigned long) p);
#else
	vma = find_vma(current->mm, (unsigned long) p);
	if (vma && (unsigned long) p < vma->vm_start)
		vma = NULL;
#endif
	if (!vma)
		return NULL;
	if (!vma->vm_private_data)
		return NULL;
	if ((unsigned long) p + size > vma->vm_end || (unsigned long) p + size < vma->vm_start)
		return NULL;
	if (vma->vm_ops != &vm_mmap_ops)
		return NULL;
	return vma->vm_private_data + ((unsigned long) p - (unsigned long) vma->vm_start);
}



static int validate_srtp(const struct rtpengine_srtp *s) {
	if (s->cipher <= REC_INVALID)
		return -1;
	if (s->cipher >= __REC_LAST)
		return -1;
	if (s->hmac <= REH_INVALID)
		return -1;
	if (s->hmac >= __REH_LAST)
		return -1;
	if (s->rtp_auth_tag_len > 20)
		return -1;
	if (s->mki_len > sizeof(s->mki))
		return -1;
	return 0;
}



/* XXX shared code */
static void aes_ctr(unsigned char *out, const unsigned char *in, size_t in_len,
		struct crypto_cipher *tfm, const unsigned char *iv)
{
	unsigned char ivx[16];
	unsigned char key_block[16];
	unsigned char *p, *q;
	size_t left;
	int i;
	uint64_t *pi, *qi, *ki;

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

static void aes_f8(unsigned char *in_out, size_t in_len,
		struct crypto_cipher *tfm, struct crypto_cipher *iv_tfm,
		const unsigned char *iv)
{
	unsigned char key_block[16], last_key_block[16], /* S(j), S(j-1) */
		      ivx[16], /* IV' */
		      x[16];
	size_t i, left;
	uint32_t j;
	unsigned char *p;
	uint64_t *pi, *ki, *lki, *xi;
	uint32_t *xu;

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

static int gen_session_key(unsigned char *out, int len, const struct rtpengine_srtp *s, unsigned char label,
		unsigned int index_len)
{
	unsigned char key_id[7];
	unsigned char x[14];
	int i, ret;

	memset(key_id, 0, sizeof(key_id));

	key_id[0] = label;

	memcpy(x, s->master_salt, s->master_salt_len);
	// AEAD uses 12 bytes master salt; pad on the right to get 14
	// Errata: https://www.rfc-editor.org/errata_search.php?rfc=7714
	if (s->master_salt_len == 12)
		x[12] = x[13] = '\x00';
	for (i = 13 - index_len; i < 14; i++)
		x[i] = key_id[i - (13 - index_len)] ^ x[i];

	ret = prf_n(out, len, s->master_key, s->master_key_len, x);
	if (ret)
		return ret;
	return 0;
}




static int aes_f8_session_key_init(struct re_crypto_context *c, const struct rtpengine_srtp *s) {
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

static int gen_session_keys(struct re_crypto_context *c, const struct rtpengine_srtp *s, unsigned int label_offset,
		unsigned int index_len)
{
	int ret;
	const char *err;

	if (s->cipher == REC_NULL && s->hmac == REH_NULL)
		return 0;
	err = "failed to generate session key";
	ret = gen_session_key(c->session_key, s->session_key_len, s, 0x00 + label_offset, index_len);
	if (ret)
		goto error;
	ret = gen_session_key(c->session_auth_key, 20, s, 0x01 + label_offset, index_len); // XXX fixed length auth key
	if (ret)
		goto error;
	ret = gen_session_key(c->session_salt, s->session_salt_len, s, 0x02 + label_offset, index_len);
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
		ret = crypto_cipher_setkey(c->tfm[0], c->session_key, s->session_key_len);
		if (ret)
			goto error;
	}

	if (c->cipher->aead_name) {
		err = "failed to load AEAD";
		c->aead = crypto_alloc_aead(c->cipher->aead_name, 0, CRYPTO_ALG_ASYNC);
		if (IS_ERR(c->aead)) {
			ret = PTR_ERR(c->aead);
			c->aead = NULL;
			goto error;
		}
		ret = -EINVAL;
		if (crypto_aead_ivsize(c->aead) != 12)
			goto error;
		ret = crypto_aead_setkey(c->aead, c->session_key, s->session_key_len);
		if (ret)
			goto error;
		ret = crypto_aead_setauthsize(c->aead, 16);
		if (ret)
			goto error;
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
		ret = crypto_shash_setkey(c->shash, c->session_auth_key, 20);
		if (ret)
			goto error;
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
static int gen_rtp_session_keys(struct re_crypto_context *c, const struct rtpengine_srtp *s) {
	return gen_session_keys(c, s, 0, 6);
}
static int gen_rtcp_session_keys(struct re_crypto_context *c, const struct rtpengine_srtp *s) {
	return gen_session_keys(c, s, 3, SRTCP_R_LENGTH);
}




static void crypto_context_init(struct re_crypto_context *c, const struct rtpengine_srtp *s) {
	c->cipher = &re_ciphers[s->cipher];
	c->hmac = &re_hmacs[s->hmac];
}

static int table_new_target(struct rtpengine_table *t, struct rtpengine_target_info *i) {
	unsigned char hi, lo;
	unsigned int rda_hash, rh_it;
	struct rtpengine_target *g;
	struct re_dest_addr *rda;
	struct re_bucket *b, *ba = NULL;
	struct rtpengine_target *og = NULL;
	int err;
	unsigned long flags;
	unsigned int u;
	struct interface_stats_block *iface_stats;
	struct stream_stats *stats;
	struct rtp_stats *pt_stats[RTPE_NUM_PAYLOAD_TYPES];
	struct ssrc_stats *ssrc_stats[RTPE_NUM_SSRC_TRACKING];

	/* validation */

	if (!t->rtpe_stats)
		return -EIO;
	if (!is_valid_address(&i->local))
		return -EINVAL;
	if (i->num_destinations > RTPE_MAX_FORWARD_DESTINATIONS)
		return -EINVAL;
	if (i->num_rtcp_destinations > i->num_destinations)
		return -EINVAL;
	if (i->num_payload_types > RTPE_NUM_PAYLOAD_TYPES)
		return -EINVAL;
	if (!i->non_forwarding) {
		if (!i->num_destinations)
			return -EINVAL;
	}
	else {
		if (i->num_destinations)
			return -EINVAL;
	}
	if (validate_srtp(&i->decrypt))
		return -EINVAL;

	iface_stats = shm_map_resolve(i->iface_stats, sizeof(*iface_stats));
	if (!iface_stats)
		return -EFAULT;
	stats = shm_map_resolve(i->stats, sizeof(*stats));
	if (!stats)
		return -EFAULT;
	for (u = 0; u < i->num_payload_types; u++) {
		pt_stats[u] = shm_map_resolve(i->pt_stats[u], sizeof(*pt_stats[u]));
		if (!pt_stats[u])
			return -EFAULT;
	}
	for (u = 0; u < RTPE_NUM_SSRC_TRACKING; u++) {
		if (!i->ssrc[u])
			break;
		if (!i->ssrc_stats[u])
			return -EFAULT;
		ssrc_stats[u] = shm_map_resolve(i->ssrc_stats[u], sizeof(*ssrc_stats[u]));
		if (!ssrc_stats[u])
			return -EFAULT;
	}

	DBG("Creating new target\n");

	/* initializing */

	err = -ENOMEM;
	g = kzalloc(sizeof(*g), GFP_KERNEL);
	if (!g)
		goto fail1;

	g->table = t->id;
	atomic_set(&g->refcnt, 1);
	spin_lock_init(&g->decrypt_rtp.lock);
	spin_lock_init(&g->decrypt_rtcp.lock);
	memcpy(&g->target, i, sizeof(*i));
	crypto_context_init(&g->decrypt_rtp, &g->target.decrypt);
	crypto_context_init(&g->decrypt_rtcp, &g->target.decrypt);
	spin_lock_init(&g->ssrc_stats_lock);
	for (u = 0; u < RTPE_NUM_SSRC_TRACKING; u++)
		g->target.ssrc_stats[u] = ssrc_stats[u];
	rwlock_init(&g->outputs_lock);
	g->target.iface_stats = iface_stats;
	g->target.stats = stats;
	for (u = 0; u < i->num_payload_types; u++)
		g->target.pt_stats[u] = pt_stats[u];

	if (i->num_destinations) {
		err = -ENOMEM;
		g->outputs = kzalloc(sizeof(*g->outputs) * i->num_destinations, GFP_KERNEL);
		if (!g->outputs)
			goto fail2;
		g->outputs_unfilled = i->num_destinations;
		g->num_rtp_destinations = i->num_destinations - i->num_rtcp_destinations;
	}

	err = gen_rtp_session_keys(&g->decrypt_rtp, &g->target.decrypt);
	if (err)
		goto fail2;
	err = gen_rtcp_session_keys(&g->decrypt_rtcp, &g->target.decrypt);
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
	err = -EEXIST;
	if (b->ports_lo[lo])
		goto fail4;
	re_bitfield_set(&b->ports_lo_bf, lo);
	t->num_targets++;

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
	if (g->outputs)
		kfree(g->outputs);
	kfree(g);
fail1:
	return err;
}

static int table_add_destination(struct rtpengine_table *t, struct rtpengine_destination_info *i) {
	unsigned long flags;
	int err;
	struct rtpengine_target *g;
	struct interface_stats_block *iface_stats;
	struct stream_stats *stats;
	struct ssrc_stats *ssrc_stats[RTPE_NUM_SSRC_TRACKING] = {0};
	unsigned int u;

	// validate input

	if (!is_valid_address(&i->output.src_addr))
		return -EINVAL;
	if (!is_valid_address(&i->output.dst_addr))
		return -EINVAL;
	if (i->output.src_addr.family != i->output.dst_addr.family)
		return -EINVAL;
	if (validate_srtp(&i->output.encrypt))
		return -EINVAL;

	iface_stats = shm_map_resolve(i->output.iface_stats, sizeof(*iface_stats));
	if (!iface_stats)
		return -EFAULT;
	stats = shm_map_resolve(i->output.stats, sizeof(*stats));
	if (!stats)
		return -EFAULT;
	for (u = 0; u < RTPE_NUM_SSRC_TRACKING; u++) {
		// XXX order expected to be the same as input target
		// XXX validate if target->ssrc[u] is set?
		if (!i->output.ssrc_stats[u])
			break;
		ssrc_stats[u] = shm_map_resolve(i->output.ssrc_stats[u], sizeof(*ssrc_stats[u]));
		if (!ssrc_stats[u])
			return -EFAULT;
	}


	g = get_target(t, &i->local);
	if (!g)
		return -ENOENT;

	// ready to fill in

	_w_lock(&g->outputs_lock, flags);

	err = -EBUSY;
	if (!g->outputs_unfilled)
		goto out;

	// out of range entry?
	err = -ERANGE;
	if (i->num >= g->target.num_destinations)
		goto out;

	// already filled?
	err = -EEXIST;
	if (g->outputs[i->num].output.src_addr.family)
		goto out;

	g->outputs[i->num].output = i->output;
	g->outputs[i->num].output.iface_stats = iface_stats;
	g->outputs[i->num].output.stats = stats;
	for (u = 0; u < RTPE_NUM_SSRC_TRACKING; u++)
		g->outputs[i->num].output.ssrc_stats[u] = ssrc_stats[u];

	// init crypto stuff lock free: the "output" is already filled so we
	// know it's there, but outputs_unfilled hasn't been decreased yet, so
	// this won't be used until we do, which makes it safe to do it lock
	// free

	_w_unlock(&g->outputs_lock, flags);

	spin_lock_init(&g->outputs[i->num].encrypt_rtp.lock);
	spin_lock_init(&g->outputs[i->num].encrypt_rtcp.lock);
	crypto_context_init(&g->outputs[i->num].encrypt_rtp, &i->output.encrypt);
	crypto_context_init(&g->outputs[i->num].encrypt_rtcp, &i->output.encrypt);
	err = gen_rtp_session_keys(&g->outputs[i->num].encrypt_rtp, &i->output.encrypt);
	if (!err)
		err = gen_rtcp_session_keys(&g->outputs[i->num].encrypt_rtcp, &i->output.encrypt);

	// re-acquire lock and finish up: decreasing outputs_unfillled to zero
	// makes this usable

	_w_lock(&g->outputs_lock, flags);

	if (err)
		goto out;

	g->outputs_unfilled--;

	err = 0;

out:
	_w_unlock(&g->outputs_lock, flags);
	target_put(g);
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
static int proc_generic_open_stream_modref(struct inode *inode, struct file *file) {
	if (!try_module_get(THIS_MODULE))
		return -ENXIO;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,1,0)
	return stream_open(inode, file);
#else
	return 0;
#endif
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
		t = new_table_link((uint32_t) id);
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
		t = get_table((uint32_t) id);
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


static int proc_control_mmap(struct file *file, struct vm_area_struct *vma) {
	size_t size, order;
	unsigned long pfn;
	struct page *page;
	void *pages;
	uint32_t id;
	struct rtpengine_table *t;
	int ret;
	struct re_shm *shm;
	struct inode *inode;

	// verify arguments
	if ((vma->vm_flags & VM_EXEC))
		return -EPERM;
	if (vma->vm_pgoff)
		return -EINVAL;

	// verify size
	size = vma->vm_end - vma->vm_start;
	if (size == 0)
		return -EINVAL;

	// determine and verify order (1<<n)
	// is a power of 2?
	if ((size & (size - 1)) != 0)
		return -EIO;

	order = __fls((unsigned long) size); // size = 256 -> order = 8
	if (1 << order != size)
		return -ENXIO;

	// adjust order to page size
	if (order < PAGE_SHIFT)
		return -E2BIG;
	order -= PAGE_SHIFT;

	// ok, allocate pages
	page = alloc_pages(GFP_KERNEL_ACCOUNT, order);
	if (!page)
		return -ENOMEM;

	pages = page_address(page);

	shm = kzalloc(sizeof(*shm), GFP_KERNEL);
	if (!shm) {
		free_pages((unsigned long) pages, order);
		return -ENOMEM;
	}

	shm->head = pages;
	shm->size = size;
	shm->order = order;

	// get our table
	inode = file->f_path.dentry->d_inode;
	id = (uint32_t) (unsigned long) PDE_DATA(inode);
	t = get_table(id);
	if (!t) {
		free_pages((unsigned long) pages, order);
		kfree(shm);
		return -ENOENT;
	}

	pfn = virt_to_phys(pages) >> PAGE_SHIFT;
	vma->vm_private_data = pages; // remember kernel-space address
	vma->vm_ops = &vm_mmap_ops;

	ret = remap_pfn_range(vma, vma->vm_start, pfn, size, vma->vm_page_prot);

	if (ret == 0) {
		spin_lock(&t->shm_lock);
		list_add(&shm->list_entry, &t->shm_list);
		spin_unlock(&t->shm_lock);
	}

	table_put(t);

	return ret;
}

static int proc_control_open(struct inode *inode, struct file *file) {
	uint32_t id;
	struct rtpengine_table *t;
	unsigned long flags;
	int err;

	if ((err = proc_generic_open_modref(inode, file)))
		return err;

	id = (uint32_t) (unsigned long) PDE_DATA(inode);
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,1,0)
	return stream_open(inode, file);
#else
	return 0;
#endif
}

static int proc_control_close(struct inode *inode, struct file *file) {
	uint32_t id;
	struct rtpengine_table *t;
	unsigned long flags;

	id = (uint32_t) (unsigned long) PDE_DATA(inode);
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
	if (call && ret->info.idx.call_idx != call->info.call_idx)
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
	INIT_LIST_HEAD(&call->table_entry);

	/* check for name collisions */

	call->hash_bucket = crc32_le(0x52342, info->call_id, strlen(info->call_id));
	call->hash_bucket = call->hash_bucket & ((1 << RE_HASH_BITS) - 1);

	spin_lock_irqsave(&table->calls_hash_lock[call->hash_bucket], flags);

	hlist_for_each_entry(hash_entry, &table->calls_hash[call->hash_bucket], calls_hash_entry) {
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

	call->root = proc_mkdir_user(info->call_id, 0555, table->proc_calls);
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

	/* validation */

	if (info->stream_name[0] == '\0')
		return -EINVAL;
	if (!memchr(info->stream_name, '\0', sizeof(info->stream_name)))
		return -EINVAL;

	/* get call object */

	call = get_call_lock(table, info->idx.call_idx);
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
	INIT_LIST_HEAD(&stream->call_entry);
	spin_lock_init(&stream->packet_list_lock);
	init_waitqueue_head(&stream->read_wq);
	init_waitqueue_head(&stream->close_wq);

	/* check for name collisions */

	stream->hash_bucket = crc32_le(0x52342 ^ info->idx.call_idx, info->stream_name, strlen(info->stream_name));
	stream->hash_bucket = stream->hash_bucket & ((1 << RE_HASH_BITS) - 1);

	spin_lock_irqsave(&table->streams_hash_lock[stream->hash_bucket], flags);

	hlist_for_each_entry(hash_entry, &table->streams_hash[stream->hash_bucket], streams_hash_entry) {
		if (hash_entry->info.idx.call_idx == info->idx.call_idx
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

	info->idx.stream_idx = idx;
	memcpy(&stream->info, info, sizeof(call->info));
	if (!stream->info.max_packets)
		stream->info.max_packets = stream_packets_list_limit;

	list_add(&stream->call_entry, &call->streams); /* new ref here */
	ref_get(stream);

	stream->call = call;
	ref_get(call);

	_w_unlock(&streams.lock, flags);

	/* proc_ functions may sleep, so this must be done outside of the lock */
	pde = stream->file = proc_create_user(info->stream_name, S_IFREG | 0440, call->root,
			&proc_stream_ops, (void *) (unsigned long) info->idx.stream_idx);
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
	while (atomic_read(&stream->refcnt) != 2) {
		if (wait_event_interruptible_timeout(stream->close_wq, atomic_read(&stream->refcnt) == 2, HZ / 10) == 0)
			break;
	}

	DBG("clearing stream's stream_idx entry\n");
	_w_lock(&streams.lock, flags);
	if (streams.array[stream->info.idx.stream_idx] == stream) {
		auto_array_clear_index(&streams, stream->info.idx.stream_idx);
		stream_put(stream); /* down to 1 ref */
	}
	else
		printk(KERN_WARNING "BUG in del_stream with streams.array\n");
	_w_unlock(&streams.lock, flags);

	DBG("del_stream() releasing last ref\n");
	stream_put(stream);
}

static int table_del_stream(struct rtpengine_table *table, const struct rtpengine_stream_idx_info *info) {
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
	struct udphdr *uh;
	struct iphdr *ih;
	struct ipv6hdr *ih6;
	unsigned int udplen, version;

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
		if (wait_event_interruptible_timeout(stream->read_wq, !list_empty(&stream->packet_list) || stream->eof, HZ / 10))
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

	version = ((to_copy[0] & 0xF0) >> 4);
	if (version == 4) {
		ih = (struct iphdr *)to_copy;
		ih->check = 0;
		ih->check = ip_fast_csum((u8 *)ih, ih->ihl);
		if (ih->check == 0){
			ih->check = CSUM_MANGLED_0;
		}

		uh = (struct udphdr *)(to_copy + sizeof(struct iphdr));
		udplen = ntohs(uh->len);
		uh->check = 0;
		uh->check = csum_tcpudp_magic(ih->saddr, ih->daddr, udplen, IPPROTO_UDP, csum_partial(uh, udplen, 0));
		if (uh->check == 0){
			uh->check = CSUM_MANGLED_0;
		}
	} else if (version == 6) {
		ih6 = (struct ipv6hdr *)to_copy;

		uh = (struct udphdr *)(to_copy + sizeof(struct ipv6hdr));
		udplen = ntohs(uh->len);
		uh->check = 0;
		uh->check = csum_ipv6_magic(&ih6->saddr, &ih6->daddr, udplen, IPPROTO_UDP, csum_partial(uh, udplen, 0));
		if (uh->check == 0){
			uh->check = CSUM_MANGLED_0;
		}
	}

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

	poll_wait(f, &stream->read_wq, p);

	DBG("locking stream's packet list lock\n");
	spin_lock_irqsave(&stream->packet_list_lock, flags);

	if (!list_empty(&stream->packet_list))
		ret |= POLLIN | POLLRDNORM;
	if (stream->eof)
		ret |= POLLIN | POLLRDNORM | POLLHUP | POLLRDHUP;

	DBG("returning from proc_stream_poll()\n");

	spin_unlock_irqrestore(&stream->packet_list_lock, flags);

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
		log_err("Queue is full, discarding old packet from queue");
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

static int stream_packet(struct rtpengine_table *t, const struct rtpengine_packet_info *info, size_t len) {
	struct re_stream *stream;
	int err;
	struct re_stream_packet *packet;
	const char *data = info->data;

	if (!len) /* can't have empty packets */
		return -EINVAL;

	DBG("received %zu bytes of data from userspace\n", len);

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

// returns: -1 = no SSRCs were given, -2 = SSRCs were given but SSRC not found
static int target_find_ssrc(struct rtpengine_target *g, uint32_t ssrc) {
	int ssrc_idx;

	if (unlikely(!g->target.ssrc[0]))
		return -1;

	for (ssrc_idx = 0; ssrc_idx < RTPE_NUM_SSRC_TRACKING; ssrc_idx++) {
		if (!g->target.ssrc[ssrc_idx])
			break;
		if (g->target.ssrc[ssrc_idx] == ssrc)
			return ssrc_idx;
	}
	return -2;
}

static void parse_rtcp(struct rtp_parsed *rtp, struct sk_buff *skb) {
	rtp->ok = 0;
	rtp->rtcp = 0;

	if (skb->len < sizeof(struct rtcp_header))
		return;

	rtp->rtcp_header = (void *) skb->data;
	rtp->header_len = sizeof(struct rtcp_header);
	rtp->payload = skb->data + sizeof(struct rtcp_header);
	rtp->payload_len = skb->len - sizeof(struct rtcp_header);
	rtp->rtcp = 1;
}

#ifdef KERNEL_PLAYER

static void shut_threads(struct timer_thread **thr, unsigned int nt) {
	unsigned int i;

	if (!thr)
		return;

	for (i = 0; i < nt; i++) {
		struct timer_thread *tt = thr[i];
		if (!tt)
			continue;
		//printk(KERN_WARNING "stopping %u\n", i);
		atomic_set(&tt->shutdown, 1);
		wake_up_interruptible(&tt->queue);
		// thread frees itself
	}

	kfree(thr);
}

static void shut_all_threads(void) {
	LIST_HEAD(list);
	unsigned int nt;
	struct timer_thread **thr;

	write_lock(&media_player_lock);

	thr = timer_threads;
	nt = num_timer_threads;
	timer_threads = NULL;
	num_timer_threads = 0;
	write_unlock(&media_player_lock);

	shut_threads(thr, nt);
}

static void free_packet_stream(struct play_stream_packets *stream) {
	struct play_stream_packet *packet, *tp;
	struct rtpengine_table *t;

	//printk(KERN_WARNING "freeing packet stream %p\n", stream);

	list_for_each_entry_safe(packet, tp, &stream->packets, list)
		free_play_stream_packet(packet);

	if (stream->table_id != -1 && !list_empty(&stream->table_entry)) {
		t = get_table(stream->table_id);
		if (t) {
			spin_lock(&t->player_lock);
			list_del_init(&stream->table_entry);
			t->num_packet_streams--;
			spin_unlock(&t->player_lock);
			table_put(t);
		}
	}
	kfree(stream);
}

static void __unref_packet_stream(struct play_stream_packets *stream) {
	if (atomic_dec_and_test(&stream->refcnt))
		free_packet_stream(stream);
}


// stream must be locked and started
static ktime_t play_stream_packet_time(struct play_stream *stream, struct play_stream_packet *packet) {
	return ktime_add(stream->start_time, packet->delay);
}

// stream must be locked, started, and non-empty
static void play_stream_next_packet(struct play_stream *stream) {
	struct play_stream_packet *packet = stream->position;
	struct play_stream_packets *packets = stream->packets;
	read_lock(&packets->lock);
	stream->position = list_is_last(&packet->list, &packets->packets) ? NULL : list_next_entry(packet, list);
	if (!stream->position) {
		if (stream->info.repeat > 1) {
			stream->info.repeat--;
			stream->position = list_first_entry(&packets->packets, struct play_stream_packet, list);
			stream->start_time = play_stream_packet_time(stream, packet);
			stream->info.ts += packet->ts + packet->duration_ts;
			stream->info.seq += packet->seq + 1;
		}
	}
	read_unlock(&packets->lock);
}

// stream must be locked, started, and non-empty
// tt->tree_lock must be locked
static void play_stream_insert_packet_to_tree(struct play_stream *stream, struct timer_thread *tt, ktime_t scheduled) {
	int64_t offset;

	// make sure key is unique
	// negative as we only have btree_last(), no btree_first()
	for (offset = 0; btree_lookup64(&tt->tree, -1 * ktime_to_ns(scheduled) + offset) != NULL; offset++)
		{ }
	stream->tree_index = -1 * ktime_to_ns(scheduled) + offset;
	btree_insert64(&tt->tree, stream->tree_index, stream, GFP_ATOMIC);
}

// stream must be locked, started, and non-empty
// tree must not be locked
static void play_stream_schedule_packet_to_thread(struct play_stream *stream, struct timer_thread *tt,
		bool reschedule)
{
	ktime_t scheduled;
	struct play_stream_packet *packet;

	packet = stream->position;
	scheduled = play_stream_packet_time(stream, packet);

	//if (sleeper)
		//printk(KERN_WARNING "scheduling packet %u on thread %u\n", packet->seq, tt->idx);
	//printk(KERN_WARNING "scheduling stream %p on thread %p (sleeper %i)\n", stream, tt, sleeper);

	spin_lock(&tt->tree_lock);

	if (reschedule && !tt->scheduled && !tt->tree_added) {
		// we know we are next. remember this
		tt->scheduled = stream;
		ref_play_stream(stream);
		tt->scheduled_at = scheduled;
	}
	else {
		// all other cases: add to tree, or put as next
		if (tt->scheduled && ktime_before(scheduled, tt->scheduled_at)) {
			// we are next. return previous entry to tree and put us as next
			play_stream_insert_packet_to_tree(tt->scheduled, tt, tt->scheduled_at);
			tt->scheduled = stream;
			ref_play_stream(stream);
			tt->scheduled_at = scheduled;
		}
		else {
			// insert into tree
			play_stream_insert_packet_to_tree(stream, tt, scheduled);
			ref_play_stream(stream);
		}
		tt->tree_added = true;
	}

	stream->timer_thread = tt;

	spin_unlock(&tt->tree_lock);
}

// stream must be locked, started, and non-empty
// threads->tree_lock must be unlocked (one will be locked)
// lock order: stream lock first, thread->tree_lock second
// num_timer_threads must be >0
static void play_stream_schedule_packet(struct play_stream *stream) {
	struct timer_thread *tt;
	unsigned int idx;

	// XXX check if already scheduled
	read_lock(&media_player_lock);
	idx = atomic_fetch_add(1, &last_timer_thread_idx) % num_timer_threads;
	tt = timer_threads[idx];
	read_unlock(&media_player_lock);

	play_stream_schedule_packet_to_thread(stream, tt, false);

	wake_up_interruptible(&tt->queue); // XXX need to refcount tt? for shutdown/free race?
}

static void play_stream_send_packet(struct play_stream *stream, struct play_stream_packet *packet) {
	struct sk_buff *skb;
	struct rtp_parsed rtp;
       
	skb = alloc_skb(packet->len + MAX_HEADER + MAX_SKB_TAIL_ROOM, GFP_KERNEL);
	if (!skb)
		return; // XXX log/count error?

	// reserve head room (L2/L3 header) and copy data in
	skb_reserve(skb, MAX_HEADER);

	// RTP header
	rtp.header_len = sizeof(*rtp.rtp_header);
	rtp.rtp_header = skb_put(skb, sizeof(*rtp.rtp_header));
	*rtp.rtp_header = (struct rtp_header) {
		.v_p_x_cc = 0x80,
		.m_pt = stream->info.pt,
		.seq_num = htons(stream->info.seq + packet->seq),
		.timestamp = htonl(stream->info.ts + packet->ts),
		.ssrc = stream->info.ssrc,
	};

	// payload
	rtp.payload = skb_put(skb, packet->len);
	memcpy(rtp.payload, packet->data, packet->len);
	rtp.payload_len = packet->len;

	rtp.ok = 1;
	rtp.rtcp = 0;

	// XXX add TOS
	proxy_packet_srtp_encrypt(skb, &stream->encrypt, &stream->info.encrypt, &rtp, 0, &stream->info.ssrc_stats);
	send_proxy_packet(skb, &stream->info.src_addr, &stream->info.dst_addr, 0, NULL);

	atomic64_inc(&stream->info.stats->packets);
	atomic64_add(packet->len, &stream->info.stats->bytes);
	atomic64_inc(&stream->info.iface_stats->out.packets);
	atomic64_add(packet->len, &stream->info.iface_stats->out.bytes);
}

static void free_play_stream(struct play_stream *s) {
	//printk(KERN_WARNING "freeing play stream %p\n", s);
	free_crypto_context(&s->encrypt);
	if (s->packets)
		unref_packet_stream(s->packets);
	kfree(s);
}

static void __unref_play_stream(struct play_stream *s) {
	if (atomic_dec_and_test(&s->refcnt))
		free_play_stream(s);
}

static int timer_worker(void *p) {
	struct timer_thread *tt = p;

	//printk(KERN_WARNING "cpu %u running\n", smp_processor_id());
	while (!atomic_read(&tt->shutdown)) {
		int64_t timer_scheduled;
		struct play_stream *stream;
		ktime_t now, packet_scheduled;
		int64_t sleeptime_ns;
		struct play_stream_packet *packet;
		struct play_stream_packets *packets;

		//printk(KERN_WARNING "cpu %u (%p) loop enter\n", smp_processor_id(), tt);

		spin_lock(&tt->tree_lock);
		// grab and remove next scheduled stream, either from predetermined entry or from tree
		stream = tt->scheduled;
		if (!stream) {
			// XXX combine lookup and removal into one operation
			stream = btree_last64(&tt->tree, &timer_scheduled);
			if (stream)
				btree_remove64(&tt->tree, timer_scheduled);
		}
		else {
			tt->scheduled = NULL;
			tt->scheduled_at = 0;
		}

		tt->tree_added = false; // we're up to date before unlock
		spin_unlock(&tt->tree_lock);

		sleeptime_ns = 500000000LL; // 0.5 seconds
		if (stream) {
			//printk(KERN_WARNING "cpu %u got stream\n", smp_processor_id());

			now = ktime_get();

			spin_lock(&stream->lock);

			if (stream->table_id == -1) {
				// we've been descheduled
				spin_unlock(&stream->lock);
				unref_play_stream(stream);
				continue;
			}

			stream->timer_thread = NULL;
			packet = stream->position;
			packet_scheduled = play_stream_packet_time(stream, packet);
			//printk(KERN_WARNING "next packet %p at %li, time now %li\n", packet,
					//(long int) ktime_to_ns(packet_scheduled), 
					//(long int) ktime_to_ns(now));

			if (ktime_after(now, packet_scheduled)) {
				//printk(KERN_WARNING "cpu %u sending packet %p from stream %p now\n",
						//smp_processor_id(), packet, stream);

				spin_unlock(&stream->lock);

				//printk(KERN_WARNING "cpu %u sending packet %u now\n", tt->idx, packet->seq);
				play_stream_send_packet(stream, packet);

				spin_lock(&stream->lock);

				if (stream->table_id != -1)
					play_stream_next_packet(stream);
				else
					stream->position = NULL;

				packets = NULL;

				if (stream->position) {
					play_stream_schedule_packet_to_thread(stream, tt, false);
					sleeptime_ns = 0; // loop and get next packet from tree
					spin_unlock(&stream->lock);
					unref_play_stream(stream);
					stream = NULL;
				}
				else {
					// end of stream
					if (!stream->info.remove_at_end)
						spin_unlock(&stream->lock);
					else {
						// remove it
						end_of_stream(stream);
						spin_unlock(&stream->lock);
						write_lock(&media_player_lock);
						if (play_streams[stream->idx] == stream) {
							play_streams[stream->idx] = NULL;
							unref_play_stream(stream);
						}
						// else log error?
						write_unlock(&media_player_lock);
					}
					unref_play_stream(stream);
					stream = NULL;
				}
			}
			else {
				// figure out sleep time
				int64_t ns_diff = ktime_to_ns(ktime_sub(packet_scheduled, now));
				//printk(KERN_WARNING "stream time diff %li ns\n", (long int) ns_diff);
				//if (diff == 0 && ns_diff > 0)
					//printk(KERN_WARNING "stream time diff %li ns %li jiffies\n",
							//(long int) ns_diff, (long int) diff);
				//if (ns_diff > 0)
					//printk(KERN_WARNING "sleep time %li ms for packet %u on cpu %u\n",
							//(long int) (ns_diff / 1000000LL), packet->seq,
							//tt->idx);
				// return packet to tree
				play_stream_schedule_packet_to_thread(stream, tt, true);
				spin_unlock(&stream->lock);
				sleeptime_ns = min(sleeptime_ns, ns_diff);
				unref_play_stream(stream);
				stream = NULL;
			}
		}

		if (sleeptime_ns > 0) {
			ktime_t a, b, c;
			int64_t c_ns;
			//printk(KERN_WARNING "cpu %u sleep %li ms, slack %li ns\n", tt->idx,
					//(long int) (sleeptime_ns / 1000000LL),
					//(long int) (current->timer_slack_ns / 1000000LL));
			a = ktime_get();
			wait_event_interruptible_hrtimeout(tt->queue, atomic_read(&tt->shutdown) || tt->tree_added,
					ktime_set(0, sleeptime_ns));
			b = ktime_get();
			c = ktime_sub(b, a);
			c_ns = ktime_to_ns(c);
			//printk(KERN_WARNING "cpu %u wanted sleep %li ms, actual sleep %li ms\n", tt->idx,
					//(long int) (sleeptime_ns / 1000000LL), (long int) (c_ns / 1000000LL));
		}
		//printk(KERN_WARNING "cpu %u awoken\n", smp_processor_id());
	}

	//printk(KERN_WARNING "cpu %u exiting\n", smp_processor_id());
	btree_destroy64(&tt->tree);
	kfree(tt);
	return 0;
}

static struct timer_thread *launch_thread(unsigned int cpu) {
	struct timer_thread *tt;
	int ret;
	//printk(KERN_WARNING "try to launch %u\n", cpu);
	tt = kzalloc(sizeof(*tt), GFP_KERNEL);
	if (!tt)
		return ERR_PTR(-ENOMEM);
	init_waitqueue_head(&tt->queue);
	atomic_set(&tt->shutdown, 0);
	ret = btree_init64(&tt->tree);
	if (ret) {
		btree_destroy64(&tt->tree);
		kfree(tt);
		return ERR_PTR(ret);
	}
	spin_lock_init(&tt->tree_lock);
	tt->idx = cpu;
	tt->task = kthread_create_on_node(timer_worker, tt, cpu_to_node(cpu), "rtpengine_%u", cpu);
	if (IS_ERR(tt->task)) {
		int ret = PTR_ERR(tt->task);
		btree_destroy64(&tt->tree);
		kfree(tt);
		return ERR_PTR(ret);
	}
	kthread_bind(tt->task, cpu);
	wake_up_process(tt->task);
	//printk(KERN_WARNING "cpu %u ok\n", cpu);
	return tt;
}

static int init_play_streams(unsigned int n_play_streams, unsigned int n_stream_packets) {
	int ret = 0;
	struct timer_thread **threads_new = NULL;
	unsigned int new_num_threads = 0;
	bool need_threads;
	struct play_stream **new_play_streams, **old_play_streams = NULL;
	struct play_stream_packets **new_stream_packets, **old_stream_packets = NULL;
	unsigned int cpu;

	write_lock(&media_player_lock);

	if (num_play_streams >= n_play_streams && num_stream_packets >= n_stream_packets)
		goto out;

	need_threads = timer_threads == NULL;

	write_unlock(&media_player_lock);

	//printk(KERN_WARNING "allocating for %u/%u -> %u/%u streams\n",
			//num_play_streams, n_play_streams,
			//num_stream_packets, n_stream_packets);

	ret = -ENOMEM;
	new_play_streams = kzalloc(sizeof(*new_play_streams) * n_play_streams, GFP_KERNEL);
	if (!new_play_streams)
		goto err;
	new_stream_packets = kzalloc(sizeof(*new_stream_packets) * n_stream_packets, GFP_KERNEL);
	if (!new_stream_packets)
		goto err;

	if (need_threads) {
		ret = -ENXIO;
		new_num_threads = num_online_cpus();
		if (new_num_threads == 0)
			goto err;

		threads_new = kzalloc(sizeof(*threads_new) * new_num_threads, GFP_KERNEL);
		if (!threads_new)
			goto err;

		for (cpu = 0; cpu < num_online_cpus(); cpu++) {
			threads_new[cpu] = launch_thread(cpu);
			if (IS_ERR(threads_new[cpu])) {
				ret = PTR_ERR(threads_new[cpu]);
				threads_new[cpu] = NULL;
				goto err;
			}
		}
	}

	write_lock(&media_player_lock);

	// check again
	ret = 0;
	if (num_play_streams >= n_play_streams && num_stream_packets >= n_stream_packets)
		goto out;

	memcpy(new_play_streams, play_streams, sizeof(*play_streams) * num_play_streams);
	num_play_streams = n_play_streams;
	old_play_streams = play_streams;
	play_streams = new_play_streams;

	memcpy(new_stream_packets, stream_packets, sizeof(*stream_packets) * num_stream_packets);
	num_stream_packets = n_stream_packets;
	old_stream_packets = stream_packets;
	stream_packets = new_stream_packets;

	if (!timer_threads) {
		timer_threads = threads_new;
		num_timer_threads = new_num_threads;
		new_num_threads = 0;
		threads_new = NULL;
	}

out:
	write_unlock(&media_player_lock);
err:
	shut_threads(threads_new, new_num_threads);
	kfree(old_play_streams);
	kfree(old_stream_packets);
	return ret;
}

static int get_packet_stream(struct rtpengine_table *t, unsigned int *num) {
	struct play_stream_packets *new_stream;
	unsigned int idx = -1;
	unsigned int i;

	new_stream = kzalloc(sizeof(*new_stream), GFP_KERNEL);
	if (!new_stream)
		return -ENOMEM;

	INIT_LIST_HEAD(&new_stream->packets);
	INIT_LIST_HEAD(&new_stream->table_entry);
	rwlock_init(&new_stream->lock);
	new_stream->table_id = t->id;
	atomic_set(&new_stream->refcnt, 1);

	for (i = 0; i < num_stream_packets; i++) {
		write_lock(&media_player_lock);
		idx = atomic_fetch_add(1, &last_stream_packets_idx) % num_stream_packets;
		if (stream_packets[idx]) {
			idx = -1;
			write_unlock(&media_player_lock);
			continue;
		}
		stream_packets[idx] = new_stream;
		new_stream->idx = idx;
		ref_packet_stream(new_stream);
		write_unlock(&media_player_lock);
		break;
	}

	if (idx == -1) {
		kfree(new_stream);
		return -EBUSY;
	}

	spin_lock(&t->player_lock);
	list_add(&new_stream->table_entry, &t->packet_streams);
	// hand over ref
	new_stream = NULL;
	t->num_packet_streams++;
	// XXX race between adding to list and stop/free?
	spin_unlock(&t->player_lock);

	*num = idx;
	return 0;
}

static void free_play_stream_packet(struct play_stream_packet *p) {
	//printk(KERN_WARNING "freeing stream packet %u\n", p->seq);
	kfree(p->data);
	kfree(p);
}

static int play_stream_packet(const struct rtpengine_play_stream_packet_info *info, size_t len) {
	const char *data = info->data;
	struct play_stream_packets *stream;
	int ret = 0;
	struct play_stream_packet *packet = NULL, *last;

	//printk(KERN_WARNING "size %zu\n", len);

	packet = kzalloc(sizeof(*packet), GFP_KERNEL);
	if (!packet)
		return -ENOMEM;

	packet->len = len;
	packet->data = kmalloc(len, GFP_KERNEL);
	if (!packet)
		goto out;

	memcpy(packet->data, data, len);
	packet->delay = ms_to_ktime(info->delay_ms);
	packet->ts = info->delay_ts;
	packet->duration_ts = info->duration_ts;
	//printk(KERN_WARNING "new packet %p, delay %ld us\n", packet, (long int) ktime_to_us(packet->delay));
	// XXX alloc skb

	read_lock(&media_player_lock);

	ret = -ERANGE;
	if (info->packet_stream_idx >= num_stream_packets)
		goto out;

	stream = stream_packets[info->packet_stream_idx];
	ret = -ENOENT;
	if (!stream)
		goto out;

	write_lock(&stream->lock);

	if (!list_empty(&stream->packets)) {
		last = list_last_entry(&stream->packets, struct play_stream_packet, list);
		if (ktime_after(last->delay, packet->delay)) {
			write_unlock(&stream->lock);
			ret = -ELOOP;
			goto out;
		}
	}
	list_add_tail(&packet->list, &stream->packets);
	packet->seq = stream->len;
	stream->len++;

	write_unlock(&stream->lock);

	packet = NULL;
	ret = 0;
out:
	read_unlock(&media_player_lock);
	if (packet)
		free_play_stream_packet(packet);
	return ret;
}

static int play_stream(struct rtpengine_table *t, const struct rtpengine_play_stream_info *info, unsigned int *num) {
	struct play_stream *play_stream;
	struct play_stream_packets *packets = NULL;
	int ret;
	unsigned int idx = -1;
	unsigned int i;
	struct interface_stats_block *iface_stats;
	struct stream_stats *stats;
	struct ssrc_stats *ssrc_stats;

	if (!is_valid_address(&info->src_addr))
		return -EINVAL;
	if (!is_valid_address(&info->dst_addr))
		return -EINVAL;
	if (info->dst_addr.family != info->src_addr.family)
		return -EINVAL;
	if (validate_srtp(&info->encrypt))
		return -EINVAL;

	iface_stats = shm_map_resolve(info->iface_stats, sizeof(*iface_stats));
	if (!iface_stats)
		return -EFAULT;
	stats = shm_map_resolve(info->stats, sizeof(*stats));
	if (!stats)
		return -EFAULT;
	ssrc_stats = shm_map_resolve(info->ssrc_stats, sizeof(*ssrc_stats));
	if (!ssrc_stats)
		return -EFAULT;

	ret = -ENOMEM;
	play_stream = kzalloc(sizeof(*play_stream), GFP_KERNEL);
	if (!play_stream)
		goto out;

	INIT_LIST_HEAD(&play_stream->table_entry);
	play_stream->info = *info;
	play_stream->table_id = t->id;
	atomic_set(&play_stream->refcnt, 1);
	spin_lock_init(&play_stream->lock);
	play_stream->info.stats = stats;
	play_stream->info.iface_stats = iface_stats;
	play_stream->info.ssrc_stats = ssrc_stats;

	ret = 0;

	read_lock(&media_player_lock);

	if (info->packet_stream_idx >= num_stream_packets)
		ret = -ERANGE;
	else {
		packets = stream_packets[info->packet_stream_idx];
		if (!packets)
			ret = -ENOENT;
		else
			ref_packet_stream(packets);
	}

	read_unlock(&media_player_lock);

	if (ret)
		goto out;

	read_lock(&packets->lock);

	ret = -ENXIO;
	if (list_empty(&packets->packets)) {
		read_unlock(&packets->lock);
		goto out;
	}

	play_stream->packets = packets;
	play_stream->position = list_first_entry(&packets->packets, struct play_stream_packet, list);

	read_unlock(&packets->lock);

	packets = NULL; // ref handed over

	for (i = 0; i < num_play_streams; i++) {
		write_lock(&media_player_lock);
		idx = atomic_fetch_add(1, &last_play_stream_idx) % num_play_streams;
		if (play_streams[idx]) {
			write_unlock(&media_player_lock);
			idx = -1;
			continue;
		}
		play_streams[idx] = play_stream;
		ref_play_stream(play_stream);
		play_stream->idx = idx;
		write_unlock(&media_player_lock);
		break;
	}

	ret = -EBUSY;
	if (idx == -1)
		goto out;

	spin_lock(&t->player_lock);
	list_add(&play_stream->table_entry, &t->play_streams);
	ref_play_stream(play_stream);
	t->num_play_streams++;
	// XXX race between adding to list and stop/free?
	spin_unlock(&t->player_lock);

	spin_lock(&play_stream->lock);

	play_stream->start_time = ktime_get();
	crypto_context_init(&play_stream->encrypt, &info->encrypt);
	ret = gen_rtp_session_keys(&play_stream->encrypt, &info->encrypt);
	if (ret) {
		spin_unlock(&play_stream->lock);
		goto out;
	}
	//printk(KERN_WARNING "start time %ld us\n", (long int) ktime_to_us(play_stream->start_time));

	play_stream_schedule_packet(play_stream);

	spin_unlock(&play_stream->lock);

	*num = idx;
	ret = 0;

out:
	if (play_stream)
		unref_play_stream(play_stream);
	if (packets)
		unref_packet_stream(packets);
	return ret;
}

// stream must be locked, reference must be held
static void end_of_stream(struct play_stream *stream) {
	struct rtpengine_table *t;

	if (stream->table_id != -1 && !list_empty(&stream->table_entry)) {
		t = get_table(stream->table_id);
		if (t) {
			//printk(KERN_WARNING "removing stream %p from table\n", stream);
			spin_lock(&t->player_lock);
			list_del_init(&stream->table_entry);
			t->num_play_streams--;
			spin_unlock(&t->player_lock);
			table_put(t);
			unref_play_stream(stream);
		}
	}
	stream->table_id = -1;
}

// stream lock is not held, reference must be held
static void do_stop_stream(struct play_stream *stream) {
	struct timer_thread *tt;
	struct play_stream *old_stream;

	//printk(KERN_WARNING "stop stream %p\n", stream);

	spin_lock(&stream->lock);

	end_of_stream(stream);

	tt = stream->timer_thread;
	stream->timer_thread = NULL;

	if (tt) {
		spin_lock(&tt->tree_lock);

		if (tt->scheduled == stream) {
			//printk(KERN_WARNING "stream %p was scheduled\n", stream);
			tt->scheduled = NULL;
			unref_play_stream(stream);
		}
		else {
			old_stream = btree_lookup64(&tt->tree, stream->tree_index);
			if (old_stream == stream) {
				//printk(KERN_WARNING "stream %p was in tree\n", stream);
				btree_remove64(&tt->tree, stream->tree_index);
				unref_play_stream(stream);
			}
			else {
				//printk(KERN_ERR "stream %p not scheduled!\n", stream);
			}
		}

		spin_unlock(&tt->tree_lock);
	}

	spin_unlock(&stream->lock);
}

static int stop_stream(struct rtpengine_table *t, unsigned int num) {
	struct play_stream *stream;
	int ret;

	ret = 0;

	write_lock(&media_player_lock);

	if (num >= num_play_streams)
		ret = -ERANGE;
	else {
		stream = play_streams[num];
		if (!stream)
			ret = -ENOENT;
		else
			play_streams[num] = NULL;;
	}

	write_unlock(&media_player_lock);

	if (ret)
		return ret;

	do_stop_stream(stream);

	// check if stream was released, wait if it wasn't
	spin_lock(&stream->lock);
	while (stream->timer_thread) {
		spin_unlock(&stream->lock);
		cpu_relax();
		schedule();
		spin_lock(&stream->lock);
	}
	spin_unlock(&stream->lock);

	unref_play_stream(stream);

	return 0;
}

static int cmd_free_packet_stream(struct rtpengine_table *t, unsigned int idx) {
	struct play_stream_packets *stream = NULL;
	int ret;

	write_lock(&media_player_lock);

	ret = -ERANGE;
	if (idx >= num_stream_packets)
		goto out;

	stream = stream_packets[idx];
	ret = -ENOENT;
	if (!stream)
		goto out;

	// steal reference
	stream_packets[idx] = NULL;

	ret = 0;

out:
	write_unlock(&media_player_lock);

	if (!stream)
		return ret;

	write_lock(&stream->lock);
	idx = stream->idx;
	stream->table_id = -1;
	write_unlock(&stream->lock);

	if (idx != -1) {
		write_lock(&media_player_lock);
		if (stream_packets[idx] == stream) {
			stream_packets[idx] = NULL;
			unref_packet_stream(stream);
		}
		write_unlock(&media_player_lock);
	}

	if (!list_empty(&stream->table_entry)) {
		spin_lock(&t->player_lock);
		list_del_init(&stream->table_entry);
		t->num_packet_streams--;
		spin_unlock(&t->player_lock);
		unref_packet_stream(stream);
	}

	unref_packet_stream(stream);

	return 0;
}

#endif


static const size_t min_req_sizes[__REMG_LAST] = {
	[REMG_INIT]		= sizeof(struct rtpengine_command_init),
	[REMG_ADD_TARGET]	= sizeof(struct rtpengine_command_add_target),
	[REMG_DEL_TARGET]	= sizeof(struct rtpengine_command_del_target),
	[REMG_ADD_DESTINATION]	= sizeof(struct rtpengine_command_destination),
	[REMG_ADD_CALL]		= sizeof(struct rtpengine_command_add_call),
	[REMG_DEL_CALL]		= sizeof(struct rtpengine_command_del_call),
	[REMG_ADD_STREAM]	= sizeof(struct rtpengine_command_add_stream),
	[REMG_DEL_STREAM]	= sizeof(struct rtpengine_command_del_stream),
	[REMG_PACKET]		= sizeof(struct rtpengine_command_packet),
	[REMG_INIT_PLAY_STREAMS]= sizeof(struct rtpengine_command_init_play_streams),
	[REMG_GET_PACKET_STREAM]= sizeof(struct rtpengine_command_get_packet_stream),
	[REMG_PLAY_STREAM_PACKET]= sizeof(struct rtpengine_command_play_stream_packet),
	[REMG_PLAY_STREAM]	= sizeof(struct rtpengine_command_play_stream),
	[REMG_STOP_STREAM]	= sizeof(struct rtpengine_command_stop_stream),
	[REMG_FREE_PACKET_STREAM]= sizeof(struct rtpengine_command_free_packet_stream),

};
static const size_t max_req_sizes[__REMG_LAST] = {
	[REMG_INIT]		= sizeof(struct rtpengine_command_init),
	[REMG_ADD_TARGET]	= sizeof(struct rtpengine_command_add_target),
	[REMG_DEL_TARGET]	= sizeof(struct rtpengine_command_del_target),
	[REMG_ADD_DESTINATION]	= sizeof(struct rtpengine_command_destination),
	[REMG_ADD_CALL]		= sizeof(struct rtpengine_command_add_call),
	[REMG_DEL_CALL]		= sizeof(struct rtpengine_command_del_call),
	[REMG_ADD_STREAM]	= sizeof(struct rtpengine_command_add_stream),
	[REMG_DEL_STREAM]	= sizeof(struct rtpengine_command_del_stream),
	[REMG_PACKET]		= sizeof(struct rtpengine_command_packet) + 65535,
	[REMG_INIT_PLAY_STREAMS]= sizeof(struct rtpengine_command_init_play_streams),
	[REMG_GET_PACKET_STREAM]= sizeof(struct rtpengine_command_get_packet_stream),
	[REMG_PLAY_STREAM_PACKET]= sizeof(struct rtpengine_command_play_stream_packet) + 65535,
	[REMG_PLAY_STREAM]	= sizeof(struct rtpengine_command_play_stream),
	[REMG_STOP_STREAM]	= sizeof(struct rtpengine_command_stop_stream),
	[REMG_FREE_PACKET_STREAM]= sizeof(struct rtpengine_command_free_packet_stream),
};

static int rtpengine_init_table(struct rtpengine_table *t, struct rtpengine_init_info *init) {
	int i;

	if (t->rtpe_stats)
		return -EBUSY;
	t->rtpe_stats = shm_map_resolve(init->rtpe_stats, sizeof(*t->rtpe_stats));
	if (!t->rtpe_stats)
		return -EFAULT;
	if (init->last_cmd != __REMG_LAST)
		return -ERANGE;
	for (i = 0; i < __REMG_LAST; i++)
		if (init->msg_size[i] != min_req_sizes[i])
			return -EMSGSIZE;
	return 0;
}

static inline ssize_t proc_control_read_write(struct file *file, char __user *ubuf, size_t buflen,
		int writeable)
{
	struct inode *inode;
	uint32_t id;
	struct rtpengine_table *t;
	int err;
	enum rtpengine_command cmd;
	char scratchbuf[512];

	union {
		struct rtpengine_command_init *init;
		struct rtpengine_command_add_target *add_target;
		struct rtpengine_command_del_target *del_target;
		struct rtpengine_command_destination *destination;
		struct rtpengine_command_add_call *add_call;
		struct rtpengine_command_del_call *del_call;
		struct rtpengine_command_add_stream *add_stream;
		struct rtpengine_command_del_stream *del_stream;
		struct rtpengine_command_packet *packet;
#ifdef KERNEL_PLAYER
		struct rtpengine_command_init_play_streams *init_play_streams;
		struct rtpengine_command_get_packet_stream *get_packet_stream;
		struct rtpengine_command_play_stream_packet *play_stream_packet;
		struct rtpengine_command_play_stream *play_stream;
		struct rtpengine_command_stop_stream *stop_stream;
		struct rtpengine_command_free_packet_stream *free_packet_stream;
#endif

		char *storage;
	} msg;

	// verify absolute minimum size
	if (buflen < sizeof(cmd))
		return -EIO;

	// copy request header
	if (copy_from_user(&cmd, ubuf, sizeof(cmd)))
		return -EFAULT;

	// verify request
	if (cmd < 1 || cmd >= __REMG_LAST) {
		printk(KERN_WARNING "xt_RTPENGINE unimplemented op %u\n", cmd);
		return -EINVAL;
	}

	// verify request size
	if (buflen < min_req_sizes[cmd])
		return -EMSGSIZE;
	if (buflen > max_req_sizes[cmd])
		return -ERANGE;

	// do we need an extra large storage buffer?
	if (buflen > sizeof(scratchbuf)) {
		msg.storage = kmalloc(buflen, GFP_KERNEL);
		if (!msg.storage)
			return -ENOMEM;
	}
	else
		msg.storage = scratchbuf;

	// get our table
	inode = file->f_path.dentry->d_inode;
	id = (uint32_t) (unsigned long) PDE_DATA(inode);
	t = get_table(id);
	err = -ENOENT;
	if (!t)
		goto err_free;

	// copy in the entire request
	err = -EFAULT;
	if (copy_from_user(msg.storage, ubuf, buflen))
		goto err_table_free;

	// execute command
	err = 0;

	switch (cmd) {
		case REMG_INIT:
			err = rtpengine_init_table(t, &msg.init->init);
			break;

		case REMG_ADD_TARGET:
			err = table_new_target(t, &msg.add_target->target);
			break;

		case REMG_DEL_TARGET:
			err = table_del_target(t, &msg.del_target->local);
			break;

		case REMG_ADD_DESTINATION:
			err = table_add_destination(t, &msg.destination->destination);
			break;

		case REMG_ADD_CALL:
			err = -EINVAL;
			if (writeable)
				err = table_new_call(t, &msg.add_call->call);
			break;

		case REMG_DEL_CALL:
			err = table_del_call(t, msg.del_call->call_idx);
			break;

		case REMG_ADD_STREAM:
			err = -EINVAL;
			if (writeable)
				err = table_new_stream(t, &msg.add_stream->stream);
			break;

		case REMG_DEL_STREAM:
			err = table_del_stream(t, &msg.del_stream->stream);
			break;

		case REMG_PACKET:
			err = stream_packet(t, &msg.packet->packet, buflen - sizeof(*msg.packet));
			break;

#ifdef KERNEL_PLAYER

		case REMG_INIT_PLAY_STREAMS:
			err = init_play_streams(msg.init_play_streams->num_play_streams,
					msg.init_play_streams->num_packet_streams);
			break;

		case REMG_GET_PACKET_STREAM:
			err = -EINVAL;
			if (writeable)
				err = get_packet_stream(t, &msg.get_packet_stream->packet_stream_idx);
			break;

		case REMG_PLAY_STREAM_PACKET:
			err = play_stream_packet(&msg.play_stream_packet->play_stream_packet,
					buflen - sizeof(*msg.play_stream_packet));
			break;

		case REMG_PLAY_STREAM:
			err = -EINVAL;
			if (writeable)
				err = play_stream(t, &msg.play_stream->info, &msg.play_stream->play_idx);
			break;

		case REMG_STOP_STREAM:
			err = stop_stream(t, msg.stop_stream->play_idx);
			break;

		case REMG_FREE_PACKET_STREAM:
			err = cmd_free_packet_stream(t, msg.free_packet_stream->packet_stream_idx);
			break;

#endif

		default:
			printk(KERN_WARNING "xt_RTPENGINE unimplemented op %u\n", cmd);
			err = -EINVAL;
			break;
	}

	table_put(t);

	if (err)
		goto err_free;

	if (writeable) {
		err = -EFAULT;
		if (copy_to_user(ubuf, msg.storage, buflen))
			goto err_free;
	}

	if (msg.storage != scratchbuf)
		kfree(msg.storage);

	return buflen;

err_table_free:
	table_put(t);
err_free:
	if (msg.storage != scratchbuf)
		kfree(msg.storage);
	return err;
}
static ssize_t proc_control_write(struct file *file, const char __user *ubuf, size_t buflen, loff_t *off) {
	return proc_control_read_write(file, (char __user *) ubuf, buflen, 0);
}
static ssize_t proc_control_read(struct file *file, char __user *ubuf, size_t buflen, loff_t *off) {
	return proc_control_read_write(file, ubuf, buflen, 1);
}






// par can be NULL
static int send_proxy_packet4(struct sk_buff *skb, struct re_address *src, struct re_address *dst,
		unsigned char tos, const struct xt_action_param *par)
{
	struct iphdr *ih;
	struct udphdr *uh;
	unsigned int datalen;
	struct net *net;
	struct rtable *rt;

	net = NULL;
	if (par)
		net = PAR_STATE_NET(par);
	if (!net && current && current->nsproxy)
		net = current->nsproxy->net_ns;
	if (!net)
		goto drop;

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
		.ttl		= net->ipv4.sysctl_ip_default_ttl,
		.protocol	= IPPROTO_UDP,
		.saddr		= src->u.ipv4,
		.daddr		= dst->u.ipv4,
	};

	skb->protocol = htons(ETH_P_IP);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,10,0)) || \
		(defined(RHEL_RELEASE_CODE) && LINUX_VERSION_CODE >= KERNEL_VERSION(5,14,0) && \
			RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(9,6))
	rt = ip_route_output(net, dst->u.ipv4, src->u.ipv4, tos, 0, 0);
#else
	rt = ip_route_output(net, dst->u.ipv4, src->u.ipv4, tos, 0);
#endif
	if (IS_ERR(rt))
		goto drop;
	skb_dst_drop(skb);
	skb_dst_set(skb, &rt->dst);

	if (skb_dst(skb)->error)
		goto drop;
	skb->dev = skb_dst(skb)->dev;

	if (skb->dev->features & (NETIF_F_HW_CSUM | NETIF_F_IP_CSUM)) {
		skb->ip_summed = CHECKSUM_PARTIAL;
		skb->csum = 0;
		udp4_hwcsum(skb, ih->saddr, ih->daddr);
	}
	else {
		__wsum csum = skb_checksum(skb, skb_transport_offset(skb), datalen, 0);
		uh->check = csum_tcpudp_magic(src->u.ipv4, dst->u.ipv4, datalen, IPPROTO_UDP,
				csum);
		if (uh->check == 0)
			uh->check = CSUM_MANGLED_0;
		skb->ip_summed = CHECKSUM_COMPLETE;
	}

	ip_select_ident(net, skb, NULL);
	ip_local_out(net, skb->sk, skb);

	return 0;

drop:
	log_err("IPv4 routing failed");
	kfree_skb(skb);
	return -1;
}





// par can be NULL
static int send_proxy_packet6(struct sk_buff *skb, struct re_address *src, struct re_address *dst,
		unsigned char tos, const struct xt_action_param *par)
{
	struct ipv6hdr *ih;
	struct udphdr *uh;
	unsigned int datalen;
	struct net *net;
	struct dst_entry *dst_entry;
	struct flowi6 fl6;

	net = NULL;
	if (par)
		net = PAR_STATE_NET(par);
	if (!net && current && current->nsproxy)
		net = current->nsproxy->net_ns;
	if (!net)
		goto drop;

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
		.hop_limit	= net->ipv6.devconf_dflt->hop_limit,
	};
	memcpy(&ih->saddr, src->u.ipv6, sizeof(ih->saddr));
	memcpy(&ih->daddr, dst->u.ipv6, sizeof(ih->daddr));

	skb->protocol = htons(ETH_P_IPV6);

	memset(&fl6, 0, sizeof(fl6));
	memcpy(&fl6.saddr, src->u.ipv6, sizeof(fl6.saddr));
	memcpy(&fl6.daddr, dst->u.ipv6, sizeof(fl6.daddr));
	fl6.flowi6_mark = skb->mark;

	dst_entry = ip6_route_output(net, NULL, &fl6);
	if (!dst_entry)
		goto drop;
	if (dst_entry->error) {
		dst_release(dst_entry);
		goto drop;
	}
	skb_dst_drop(skb);
	skb_dst_set(skb, dst_entry);
	skb->dev = skb_dst(skb)->dev;

	skb->csum_start = skb_transport_header(skb) - skb->head;
	skb->csum_offset = offsetof(struct udphdr, check);

	if (skb->dev->features & (NETIF_F_HW_CSUM | NETIF_F_IPV6_CSUM)) {
		skb->ip_summed = CHECKSUM_PARTIAL;
		uh->check = ~csum_ipv6_magic(&ih->saddr, &ih->daddr, datalen, IPPROTO_UDP, 0);
	}
	else {
		__wsum csum = skb_checksum(skb, skb_transport_offset(skb), datalen, 0);
		uh->check = csum_ipv6_magic(&ih->saddr, &ih->daddr, datalen, IPPROTO_UDP, csum);
		if (uh->check == 0)
			uh->check = CSUM_MANGLED_0;
		skb->ip_summed = CHECKSUM_COMPLETE;
	}

	ip6_local_out(net, skb->sk, skb);

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

	if (skb->len < sizeof(*rtp->rtp_header))
		goto error;
	rtp->rtp_header = (void *) skb->data;
	if ((rtp->rtp_header->v_p_x_cc & 0xc0) != 0x80) /* version 2 */
		goto error;
	rtp->header_len = sizeof(*rtp->rtp_header);

	/* csrc list */
	rtp->header_len += (rtp->rtp_header->v_p_x_cc & 0xf) * 4;
	if (skb->len < rtp->header_len)
		goto error;
	rtp->payload = skb->data + rtp->header_len;
	rtp->payload_len = skb->len - rtp->header_len;

	if ((rtp->rtp_header->v_p_x_cc & 0x10)) {
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
static uint32_t rtp_packet_index(struct re_crypto_context *c,
		struct rtpengine_srtp *s, struct rtp_header *rtp,
		int ssrc_idx,
		struct ssrc_stats **ssrc_stats)
{
	uint16_t seq;
	uint32_t index;
	unsigned long flags;
	uint16_t s_l;
	uint32_t roc;
	uint32_t v;

	if (ssrc_idx < 0)
		ssrc_idx = 0;

	seq = ntohs(rtp->seq_num);

	spin_lock_irqsave(&c->lock, flags);

	/* rfc 3711 section 3.3.1 */
	if (ssrc_stats[ssrc_idx]) {
		index = atomic_read(&ssrc_stats[ssrc_idx]->ext_seq);
		if (unlikely(!index))
			index = seq;
	}
	else
		index = seq;

	/* rfc 3711 appendix A, modified, and sections 3.3 and 3.3.1 */
	s_l = (index & 0x0000ffffULL);
	roc = (index & 0xffff0000ULL) >> 16;
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
	if (ssrc_stats[ssrc_idx])
		atomic_set(&ssrc_stats[ssrc_idx]->ext_seq, index);

	spin_unlock_irqrestore(&c->lock, flags);

	return index;
}

static void update_packet_index(struct re_crypto_context *c,
		struct rtpengine_srtp *s, uint32_t idx, int ssrc_idx,
		struct ssrc_stats *ssrc_stats[RTPE_NUM_SSRC_TRACKING])
{
	if (ssrc_idx < 0)
		ssrc_idx = 0;

	if (ssrc_stats[ssrc_idx])
		atomic_set(&ssrc_stats[ssrc_idx]->ext_seq, idx);
}

static int srtp_hash(unsigned char *hmac,
		struct re_crypto_context *c,
		struct rtpengine_srtp *s, struct rtp_parsed *r,
		uint32_t pkt_idx)
{
	uint32_t roc;
	struct shash_desc *dsc;
	size_t alloc_size;

	if (!s->rtp_auth_tag_len)
		return 0;

	roc = htonl((pkt_idx & 0xffff0000ULL) >> 16);

	alloc_size = sizeof(*dsc) + crypto_shash_descsize(c->shash);
	dsc = kmalloc(alloc_size, GFP_ATOMIC);
	if (!dsc)
		return -1;
	memset(dsc, 0, alloc_size);

	dsc->tfm = c->shash;

	if (crypto_shash_init(dsc))
		goto error;

	crypto_shash_update(dsc, (void *) r->rtp_header, r->header_len + r->payload_len);
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

static int srtcp_hash(unsigned char *hmac,
		struct re_crypto_context *c,
		struct rtpengine_srtp *s, struct rtp_parsed *r,
		uint32_t pkt_idx)
{
	struct shash_desc *dsc;
	size_t alloc_size;

	if (!s->rtcp_auth_tag_len)
		return 0;

	alloc_size = sizeof(*dsc) + crypto_shash_descsize(c->shash);
	dsc = kmalloc(alloc_size, GFP_ATOMIC);
	if (!dsc)
		return -1;
	memset(dsc, 0, alloc_size);

	dsc->tfm = c->shash;

	if (crypto_shash_init(dsc))
		goto error;

	crypto_shash_update(dsc, (void *) r->rtcp_header, r->header_len + r->payload_len);

	crypto_shash_final(dsc, hmac);

	kfree(dsc);

	DBG("calculated RTCP HMAC %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
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
		uint32_t pkt_idx)
{
	unsigned char hmac[20];

	if (!r->rtp_header)
		return 0;
	if (s->hmac == REH_NULL) {
		rtp_append_mki(r, s);
		return 0;
	}
	if (!c->hmac)
		return 0;
	if (!c->shash)
		return -1;

	if (srtp_hash(hmac, c, s, r, pkt_idx))
		return -1;

	rtp_append_mki(r, s);

	memcpy(r->payload + r->payload_len, hmac, s->rtp_auth_tag_len);
	r->payload_len += s->rtp_auth_tag_len;

	return 0;
}
static int srtcp_authenticate(struct re_crypto_context *c,
		struct rtpengine_srtp *s, struct rtp_parsed *r,
		uint32_t pkt_idx)
{
	unsigned char hmac[20];

	if (!r->rtcp_header)
		return 0;
	if (s->hmac == REH_NULL) {
		rtp_append_mki(r, s);
		return 0;
	}
	if (!c->hmac)
		return 0;
	if (!c->shash)
		return -1;

	if (srtcp_hash(hmac, c, s, r, pkt_idx))
		return -1;

	rtp_append_mki(r, s);

	memcpy(r->payload + r->payload_len, hmac, s->rtcp_auth_tag_len);
	r->payload_len += s->rtp_auth_tag_len;

	return 0;
}

static int srtp_auth_validate(struct re_crypto_context *c,
		struct rtpengine_srtp *s, struct rtp_parsed *r,
		uint32_t *pkt_idx_p, int ssrc_idx, struct ssrc_stats *ssrc_stats[RTPE_NUM_SSRC_TRACKING])
{
	unsigned char *auth_tag;
	unsigned char hmac[20];
	uint32_t pkt_idx = *pkt_idx_p;

	if (s->hmac == REH_NULL)
		return 0;
	if (!c->hmac)
		return 0;
	if (!c->shash)
		return -1;

	if (r->payload_len < s->rtp_auth_tag_len)
		return -1;

	r->payload_len -= s->rtp_auth_tag_len;
	auth_tag = r->payload + r->payload_len;

	if (r->payload_len < s->mki_len)
		return -1;
	r->payload_len -= s->mki_len;

	if (!s->rtp_auth_tag_len)
		return 0;

	DBG("packet auth tag %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
			auth_tag[0], auth_tag[1], auth_tag[2], auth_tag[3],
			auth_tag[4], auth_tag[5], auth_tag[6], auth_tag[7],
			auth_tag[8], auth_tag[9]);

	if (srtp_hash(hmac, c, s, r, pkt_idx))
		return -1;
	if (!memcmp(auth_tag, hmac, s->rtp_auth_tag_len))
		goto ok;

	/* possible ROC mismatch, attempt to guess */
	/* first, let's see if we missed a rollover */
	pkt_idx += 0x10000;
	if (srtp_hash(hmac, c, s, r, pkt_idx))
		return -1;
	if (!memcmp(auth_tag, hmac, s->rtp_auth_tag_len))
		goto ok_update;
	/* or maybe we did a rollover too many */
	if (pkt_idx >= 0x20000) {
		pkt_idx -= 0x20000;
		if (srtp_hash(hmac, c, s, r, pkt_idx))
			return -1;
		if (!memcmp(auth_tag, hmac, s->rtp_auth_tag_len))
			goto ok_update;
	}
	/* last guess: reset ROC to zero */
	pkt_idx &= 0xffff;
	if (srtp_hash(hmac, c, s, r, pkt_idx))
		return -1;
	if (!memcmp(auth_tag, hmac, s->rtp_auth_tag_len))
		goto ok_update;

	return -1;

ok_update:
	*pkt_idx_p = pkt_idx;
	update_packet_index(c, s, pkt_idx, ssrc_idx, ssrc_stats);
ok:
	return 0;
}
static int srtcp_auth_validate(struct re_crypto_context *c,
		struct rtpengine_srtp *s, struct rtp_parsed *r,
		uint32_t *pkt_idx_p)
{
	uint32_t idx;
	unsigned char *auth_tag = NULL;
	unsigned char hmac[20];

	if (!c->cipher->decrypt_rtcp)
		return 0;

	if (s->rtcp_auth_tag_len) {
		// we have an auth tag to verify
		if (s->hmac == REH_NULL)
			return -1;
		if (!c->hmac)
			return -1;
		if (!c->shash)
			return -1;

		// extract auth tag
		if (r->payload_len < s->rtcp_auth_tag_len)
			return -1;
		auth_tag = r->payload + r->payload_len - s->rtcp_auth_tag_len;
		r->payload_len -= s->rtcp_auth_tag_len;
	}

	// skip MKI
	if (r->payload_len < s->mki_len)
		return -1;
	r->payload_len -= s->mki_len;

	// extract index
	if (r->payload_len < sizeof(idx))
		return -1;
	memcpy(&idx, r->payload + r->payload_len - sizeof(idx), sizeof(idx));
	idx = ntohl(idx);

	if (auth_tag) {
		if (srtcp_hash(hmac, c, s, r, idx))
			return -1;
		if (memcmp(auth_tag, hmac, s->rtcp_auth_tag_len))
			return -1;
	}

	r->payload_len -= sizeof(idx);

	if ((idx & 0x80000000ULL)) {
		*pkt_idx_p = idx & ~0x80000000ULL;
		return 1; // decrypt
	}

	*pkt_idx_p = idx;
	return 0;
}


/* XXX shared code */
static int srtXp_encrypt_aes_cm(struct re_crypto_context *c,
		struct rtpengine_srtp *s, uint32_t ssrc,
		char *out, const char *in, size_t len,
		uint32_t *pkt_idxp)
{
	uint32_t pkt_idx = *pkt_idxp;
	unsigned char iv[16];
	uint32_t *ivi;
	uint32_t idxh, idxl;

	memcpy(iv, c->session_salt, 14);
	iv[14] = iv[15] = '\0';
	ivi = (void *) iv;
	idxh = htonl((pkt_idx & 0xffff0000ULL) >> 16);
	idxl = htonl((pkt_idx & 0x0000ffffULL) << 16);

	ivi[1] ^= ssrc;
	ivi[2] ^= idxh;
	ivi[3] ^= idxl;

	aes_ctr(out, in, len, c->tfm[0], iv);

	return 0;
}
static int srtp_encrypt_aes_cm(struct re_crypto_context *c,
		struct rtpengine_srtp *s, struct rtp_parsed *r,
		uint32_t *pkt_idx)
{
	return srtXp_encrypt_aes_cm(c, s, r->rtp_header->ssrc, r->payload, r->payload, r->payload_len, pkt_idx);
}
static int srtcp_encrypt_aes_cm(struct re_crypto_context *c,
		struct rtpengine_srtp *s, struct rtp_parsed *r,
		uint32_t *pkt_idx)
{
	return srtXp_encrypt_aes_cm(c, s, r->rtcp_header->ssrc, r->payload, r->payload, r->payload_len, pkt_idx);
}

static int srtp_encrypt_aes_f8(struct re_crypto_context *c,
		struct rtpengine_srtp *s, struct rtp_parsed *r,
		uint32_t *pkt_idxp)
{
	uint64_t pkt_idx = *pkt_idxp;
	unsigned char iv[16];
	uint32_t roc;

	iv[0] = 0;
	memcpy(&iv[1], &r->rtp_header->m_pt, 11);
	roc = htonl((pkt_idx & 0xffff0000ULL) >> 16);
	memcpy(&iv[12], &roc, sizeof(roc));

	aes_f8(r->payload, r->payload_len, c->tfm[0], c->tfm[1], iv);

	return 0;
}

static int srtcp_encrypt_aes_f8(struct re_crypto_context *c,
		struct rtpengine_srtp *s, struct rtp_parsed *r,
		uint32_t *pkt_idx)
{
	unsigned char iv[16];
	uint32_t i;

	memset(iv, 0, 4);
        i = htonl(0x80000000ULL | *pkt_idx);
        memcpy(&iv[4], &i, 4);
        memcpy(&iv[8], r->rtcp_header, 8); /* v, p, rc, pt, length, ssrc */

	aes_f8(r->payload, r->payload_len, c->tfm[0], c->tfm[1], iv);

	return 0;
}

union aes_gcm_rtp_iv {
	unsigned char bytes[12];
	struct {
		uint16_t zeros;
		uint32_t ssrc;
		uint32_t roq;
		uint16_t seq;
	} __attribute__((__packed__));
} __attribute__((__packed__));

static int srtp_encrypt_aes_gcm(struct re_crypto_context *c,
		struct rtpengine_srtp *s, struct rtp_parsed *r,
		uint32_t *pkt_idxp)
{
	uint32_t pkt_idx = *pkt_idxp;
	union aes_gcm_rtp_iv iv;
	struct aead_request *req;
	struct scatterlist sg[2];
	int ret;

	if (s->session_salt_len != 12)
		return -EINVAL;

	memcpy(iv.bytes, c->session_salt, 12);

	iv.ssrc ^= r->rtp_header->ssrc;
	iv.roq ^= htonl((pkt_idx & 0xffff0000ULL) >> 16);
	iv.seq ^= htons( pkt_idx & 0x0000ffffULL);

	req = aead_request_alloc(c->aead, GFP_ATOMIC);
	if (!req)
		return -ENOMEM;
	if (IS_ERR(req))
		return PTR_ERR(req);

	sg_init_table(sg, ARRAY_SIZE(sg));
	sg_set_buf(&sg[0], r->rtp_header, r->header_len);
	sg_set_buf(&sg[1], r->payload, r->payload_len + 16); // guaranteed to have space after skb_copy_expand

	aead_request_set_callback(req, 0, NULL, NULL);
	aead_request_set_ad(req, r->header_len);
	aead_request_set_crypt(req, sg, sg, r->payload_len, iv.bytes);

	ret = crypto_aead_encrypt(req);
	aead_request_free(req);

	if (ret == 0)
		r->payload_len += 16;

	return ret;
}

union aes_gcm_rtcp_iv {
	unsigned char bytes[12];
	struct {
		uint16_t zeros_a;
		uint32_t ssrc;
		uint16_t zeros_b;
		uint32_t srtcp;
	} __attribute__((__packed__));
} __attribute__((__packed__));

static int srtcp_encrypt_aes_gcm(struct re_crypto_context *c,
		struct rtpengine_srtp *s, struct rtp_parsed *r,
		uint32_t *pkt_idx)
{
	union aes_gcm_rtcp_iv iv;
	struct aead_request *req;
	struct scatterlist sg[3];
	int ret;
	uint32_t e_idx;

	if (s->session_salt_len != 12)
		return -EINVAL;

	memcpy(iv.bytes, c->session_salt, 12);

	iv.ssrc ^= r->rtcp_header->ssrc;
	iv.srtcp ^= htonl(*pkt_idx & 0x007fffffffULL);
	e_idx = htonl((*pkt_idx & 0x007fffffffULL) | 0x80000000ULL);

	req = aead_request_alloc(c->aead, GFP_ATOMIC);
	if (!req)
		return -ENOMEM;
	if (IS_ERR(req))
		return PTR_ERR(req);

	sg_init_table(sg, ARRAY_SIZE(sg));
	sg_set_buf(&sg[0], r->rtcp_header, r->header_len);
	sg_set_buf(&sg[1], &e_idx, sizeof(e_idx));
	sg_set_buf(&sg[2], r->payload, r->payload_len + 16); // guaranteed to have space after skb_copy_expand

	aead_request_set_callback(req, 0, NULL, NULL);
	aead_request_set_ad(req, r->header_len + sizeof(e_idx));
	aead_request_set_crypt(req, sg, sg, r->payload_len, iv.bytes);

	ret = crypto_aead_encrypt(req);
	aead_request_free(req);

	if (ret == 0)
		r->payload_len += 16;

	return ret;
}
static int srtp_decrypt_aes_gcm(struct re_crypto_context *c,
		struct rtpengine_srtp *s, struct rtp_parsed *r,
		uint32_t *pkt_idxp)
{
	uint32_t pkt_idx = *pkt_idxp;
	union aes_gcm_rtp_iv iv;
	struct aead_request *req;
	struct scatterlist sg[2];
	int ret;
	int guess = 0;
	char *copy = NULL;

	if (s->session_salt_len != 12)
		return -EINVAL;
	if (r->payload_len < 16)
		return -EINVAL;

	do {
		memcpy(iv.bytes, c->session_salt, 12);

		iv.ssrc ^= r->rtp_header->ssrc;
		iv.roq ^= htonl((pkt_idx & 0x00ffffffff0000ULL) >> 16);
		iv.seq ^= htons(pkt_idx & 0x00ffffULL);

		req = aead_request_alloc(c->aead, GFP_ATOMIC);
		if (!req) {
			if (copy)
				kfree(copy);
			return -ENOMEM;
		}
		if (IS_ERR(req)) {
			if (copy)
				kfree(copy);
			return PTR_ERR(req);
		}

		sg_init_table(sg, ARRAY_SIZE(sg));
		sg_set_buf(&sg[0], r->rtp_header, r->header_len);
		sg_set_buf(&sg[1], r->payload, r->payload_len);

		// make copy of payload in case the decyption clobbers it
		if (!copy)
			copy = kmalloc(r->payload_len, GFP_ATOMIC);

		if (copy)
			memcpy(copy, r->payload, r->payload_len);

		aead_request_set_callback(req, 0, NULL, NULL);
		aead_request_set_ad(req, r->header_len);
		aead_request_set_crypt(req, sg, sg, r->payload_len, iv.bytes);

		ret = crypto_aead_decrypt(req);
		aead_request_free(req);

		if (ret == 0) {
			r->payload_len -= 16;
			break;
		}
		if (ret != -EBADMSG)
			break;

		// authentication failed: restore payload and do some ROC guessing
		if (!copy)
			break;
		memcpy(r->payload, copy, r->payload_len);

		if (guess == 0)
			pkt_idx += 0x10000;
		else if (guess == 1)
			pkt_idx -= 0x20000;
		else if (guess == 2)
			pkt_idx &= 0xffff;
		else
			break;

		guess++;
	} while (1);

	if (copy)
		kfree(copy);

	if (ret == 0 && guess != 0) {
		*pkt_idxp = pkt_idx;
		ret = 1;
	}

	return ret;
}

static int srtcp_decrypt_aes_gcm(struct re_crypto_context *c,
		struct rtpengine_srtp *s, struct rtp_parsed *r,
		uint32_t *pkt_idx)
{
	union aes_gcm_rtcp_iv iv;
	struct aead_request *req;
	struct scatterlist sg[3];
	int ret;
	uint32_t e_idx;

	if (s->session_salt_len != 12)
		return -EINVAL;
	if (r->payload_len < 16)
		return -EINVAL;

	memcpy(iv.bytes, c->session_salt, 12);

	iv.ssrc ^= r->rtcp_header->ssrc;
	iv.srtcp ^= htonl(*pkt_idx & 0x007fffffffULL);
	e_idx = htonl((*pkt_idx & 0x007fffffffULL) | 0x80000000ULL);

	req = aead_request_alloc(c->aead, GFP_ATOMIC);
	if (!req)
		return -ENOMEM;
	if (IS_ERR(req))
		return PTR_ERR(req);

	sg_init_table(sg, ARRAY_SIZE(sg));
	sg_set_buf(&sg[0], r->rtcp_header, r->header_len);
	sg_set_buf(&sg[1], &e_idx, sizeof(e_idx));
	sg_set_buf(&sg[2], r->payload, r->payload_len);

	aead_request_set_callback(req, 0, NULL, NULL);
	aead_request_set_ad(req, r->header_len + sizeof(e_idx));
	aead_request_set_crypt(req, sg, sg, r->payload_len, iv.bytes);

	ret = crypto_aead_decrypt(req);
	aead_request_free(req);

	if (ret == 0)
		r->payload_len -= 16;

	return ret;
}

static inline int srtp_encrypt(struct re_crypto_context *c,
		struct rtpengine_srtp *s, struct rtp_parsed *r,
		uint32_t pkt_idx)
{
	if (!r->rtp_header)
		return 0;
	if (!c->cipher->encrypt_rtp)
		return 0;
	return c->cipher->encrypt_rtp(c, s, r, &pkt_idx);
}
static inline int srtcp_encrypt(struct re_crypto_context *c,
		struct rtpengine_srtp *s, struct rtp_parsed *r,
		uint32_t *pkt_idxp)
{
	int ret;
	uint32_t idx;

	if (!r->rtcp_header)
		return 0;
	if (!c->cipher->encrypt_rtcp)
		return 0;
	ret = c->cipher->encrypt_rtcp(c, s, r, pkt_idxp);
	if (ret)
		return ret;

	idx = htonl(0x80000000ULL | *pkt_idxp);
	memcpy(r->payload + r->payload_len, &idx, sizeof(idx));
	r->payload_len += sizeof(idx);
	(*pkt_idxp)++;

	return 0;
}

static inline int srtp_decrypt(struct re_crypto_context *c,
		struct rtpengine_srtp *s, struct rtp_parsed *r,
		uint32_t *pkt_idx)
{
	if (!c->cipher->decrypt_rtp)
		return 0;
	return c->cipher->decrypt_rtp(c, s, r, pkt_idx);
}
static inline int srtcp_decrypt(struct re_crypto_context *c,
		struct rtpengine_srtp *s, struct rtp_parsed *r,
		uint32_t pkt_idx)
{
	if (!c->cipher->decrypt_rtcp)
		return 0;
	return c->cipher->decrypt_rtcp(c, s, r, &pkt_idx);
}


static inline int is_muxed_rtcp(struct sk_buff *skb) {
	// XXX shared code
	unsigned char m_pt;
	if (skb->len < 8) // minimum RTCP size
		return 0;
	m_pt = skb->data[1];
	if (m_pt < 194)
		return 0;
	if (m_pt > 223)
		return 0;
	return 1;
}
static inline int is_rtcp_fb_packet(struct sk_buff *skb) {
	unsigned char m_pt;
	size_t left = skb->len;
	size_t offset = 0;
	unsigned int packets = 0;
	uint16_t len;

	while (1) {
		if (left < 8) // minimum RTCP size
			return 0;
		m_pt = skb->data[offset + 1];
		// only RTPFB and PSFB
		if (m_pt != 205 && m_pt != 206)
			return 0;

		// length check
		len = (((unsigned char) skb->data[offset + 2]) << 8)
			| ((unsigned char) skb->data[offset + 3]);
		len++;
		len <<= 2;
		if (len > left) // invalid
			return 0;

		left -= len;
		offset += len;

		if (packets++ >= 8) // limit number of compound packets
			return 0;
	}
	return 1;
}
static inline int is_stun(struct rtpengine_target *g, unsigned int datalen, unsigned char *skb_data) {
	uint32_t *u32;
	if (!g->target.stun)
		return 0;
	if (datalen < 28)
		return 0;
	if ((datalen & 0x3))
		return 0;
	u32 = (void *) skb_data;
	if (u32[1] != htonl(0x2112A442UL)) /* magic cookie */
		return 0;
	if ((u32[0] & htonl(0xc0000003UL))) /* zero bits required by rfc */
		return 0;
	u32 = (void *) &skb_data[datalen - 8];
	if (u32[0] != htonl(0x80280004UL)) /* required fingerprint attribute */
		return 0;
	return 1; // probably STUN
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

static int rtp_payload_match(const void *a, const void *bp) {
	const struct rtp_stats *const *b = bp;
	const struct rtp_stats *A = a, *B = *b;

	if (A->payload_type < B->payload_type)
		return -1;
	if (A->payload_type > B->payload_type)
		return 1;
	return 0;
}

static inline int rtp_payload_type(const struct rtp_header *hdr, const struct rtpengine_target_info *tg,
		int *last_pt)
{
	struct rtp_stats pt;
	struct rtp_stats *const *pmatch;

	pt.payload_type = hdr->m_pt & 0x7f;
	if (*last_pt < tg->num_payload_types) {
		pmatch = &tg->pt_stats[*last_pt];
		if (rtp_payload_match(&pt, pmatch) == 0)
			goto found;
	}
	pmatch = bsearch(&pt, tg->pt_stats, tg->num_payload_types, sizeof(*pmatch), rtp_payload_match);
	if (!pmatch)
		return -1;
found:
	*last_pt = pmatch - tg->pt_stats;
	return *last_pt;
}

static struct sk_buff *intercept_skb_copy(struct sk_buff *oskb, const struct re_address *src) {
	struct sk_buff *ret;
	struct udphdr *uh;
	struct iphdr *ih;
	struct ipv6hdr *ih6;

	ret = skb_copy_expand(oskb, MAX_HEADER, MAX_SKB_TAIL_ROOM, GFP_ATOMIC);
	if (!ret)
		return NULL;
	skb_gso_reset(ret);

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

static void proxy_packet_output_rtcp(struct sk_buff *skb, struct rtpengine_output *o,
		struct rtp_parsed *rtp, int ssrc_idx)
{
	unsigned int pllen;
	uint32_t pkt_idx, tmp_idx;
	unsigned long flags;

	if (!rtp->rtcp)
		return;

	// SRTCP
	if (unlikely(ssrc_idx < 0))
		ssrc_idx = 0;
	if (!o->output.ssrc_stats[ssrc_idx]) // for dummy outputs, could be a problem with SRTP?
		return;

	spin_lock_irqsave(&o->encrypt_rtcp.lock, flags);
	tmp_idx = pkt_idx = atomic_read(&o->output.ssrc_stats[ssrc_idx]->rtcp_seq);
	spin_unlock_irqrestore(&o->encrypt_rtcp.lock, flags);
	pllen = rtp->payload_len;
	srtcp_encrypt(&o->encrypt_rtcp, &o->output.encrypt, rtp, &tmp_idx);
	srtcp_authenticate(&o->encrypt_rtcp, &o->output.encrypt, rtp, pkt_idx);
	skb_put(skb, rtp->payload_len - pllen);
	atomic_set(&o->output.ssrc_stats[ssrc_idx]->rtcp_seq, tmp_idx);
}

static uint32_t proxy_packet_srtp_encrypt(struct sk_buff *skb, struct re_crypto_context *ctx,
		struct rtpengine_srtp *srtp,
		struct rtp_parsed *rtp, int ssrc_idx,
		struct ssrc_stats **ssrc_stats)
{
	uint32_t pkt_idx;
	unsigned int pllen;

	pkt_idx = rtp_packet_index(ctx, srtp, rtp->rtp_header, ssrc_idx, ssrc_stats);
	pllen = rtp->payload_len;
	srtp_encrypt(ctx, srtp, rtp, pkt_idx);
	srtp_authenticate(ctx, srtp, rtp, pkt_idx);
	skb_put(skb, rtp->payload_len - pllen);

	return pkt_idx;
}

static bool proxy_packet_output_rtXp(struct sk_buff *skb, struct rtpengine_output *o,
		int rtp_pt_idx,
		struct rtp_parsed *rtp, int ssrc_idx)
{
	int i;
	uint32_t pkt_idx;

	if (!rtp->ok) {
		proxy_packet_output_rtcp(skb, o, rtp, ssrc_idx);
		return true;
	}

	// pattern rewriting
	if (rtp_pt_idx >= 0) {
		if (o->output.pt_output[rtp_pt_idx].min_payload_len
				&& rtp->payload_len < o->output.pt_output[rtp_pt_idx].min_payload_len)
			return false;

		if (o->output.pt_output[rtp_pt_idx].replace_pattern_len) {
			if (o->output.pt_output[rtp_pt_idx].replace_pattern_len == 1)
				memset(rtp->payload, o->output.pt_output[rtp_pt_idx].replace_pattern[0],
						rtp->payload_len);
			else {
				for (i = 0; i < rtp->payload_len;
						i += o->output.pt_output[rtp_pt_idx].replace_pattern_len)
					memcpy(&rtp->payload[i],
							o->output.pt_output[rtp_pt_idx].replace_pattern,
							o->output.pt_output[rtp_pt_idx].replace_pattern_len);
			}
		}
	}

	// SSRC substitution and seq manipulation
	if (likely(ssrc_idx >= 0)) {
		rtp->rtp_header->seq_num = htons(ntohs(rtp->rtp_header->seq_num)
				+ o->output.seq_offset[ssrc_idx]);
		if (o->output.ssrc_subst && likely(o->output.ssrc_out[ssrc_idx]))
			rtp->rtp_header->ssrc = o->output.ssrc_out[ssrc_idx];
	}

	pkt_idx = proxy_packet_srtp_encrypt(skb, &o->encrypt_rtp, &o->output.encrypt,
			rtp, ssrc_idx, o->output.ssrc_stats);

	if (ssrc_idx >= 0 && o->output.ssrc_stats[ssrc_idx]) {
		atomic64_inc(&o->output.ssrc_stats[ssrc_idx]->packets);
		atomic64_add(rtp->payload_len, &o->output.ssrc_stats[ssrc_idx]->bytes);
		atomic_set(&o->output.ssrc_stats[ssrc_idx]->ext_seq, pkt_idx);
		atomic_set(&o->output.ssrc_stats[ssrc_idx]->timestamp, ntohl(rtp->rtp_header->timestamp));
	}

	return true;
}

static int send_proxy_packet_output(struct sk_buff *skb, struct rtpengine_target *g,
		int rtp_pt_idx,
		struct rtpengine_output *o, struct rtp_parsed *rtp, int ssrc_idx,
		const struct xt_action_param *par)
{
	bool send_or_not = proxy_packet_output_rtXp(skb, o, rtp_pt_idx, rtp, ssrc_idx);
	if (!send_or_not) {
		kfree_skb(skb);
		return 0;
	}
	return send_proxy_packet(skb, &o->output.src_addr, &o->output.dst_addr, o->output.tos, par);
}





static void rtp_stats(struct rtpengine_target *g, struct rtp_parsed *rtp, s64 arrival_time, int pt_idx,
		int ssrc_idx, struct global_stats_counter *rtpe_stats)
{
	unsigned long flags;
	struct ssrc_stats *s = g->target.ssrc_stats[ssrc_idx];
	uint16_t old_seq_trunc;
	uint32_t last_seq;
	uint16_t seq_diff;
	uint32_t clockrate;
	uint32_t transit;
	int32_t d;
	uint32_t new_seq;
	uint16_t seq;
	uint32_t ts;

	if (!s)
		return;

	seq = ntohs(rtp->rtp_header->seq_num);
	ts = ntohl(rtp->rtp_header->timestamp);

	atomic64_inc(&s->packets);
	atomic64_add(rtp->payload_len, &s->bytes);
	atomic_set(&s->timestamp, ts);

	spin_lock_irqsave(&g->ssrc_stats_lock, flags);

	// track sequence numbers and lost frames

	last_seq = atomic_read(&s->ext_seq);
	new_seq = last_seq;

	// old seq or seq reset?
	old_seq_trunc = last_seq & 0xffff;
	seq_diff = seq - old_seq_trunc;
	if (seq_diff == 0 || seq_diff >= 0xfeff) // old/dup seq - ignore
		;
	else if (seq_diff > 0x100) {
		// reset seq and loss tracker
		new_seq = seq;
		atomic_set(&s->ext_seq, seq);
		s->lost_bits = -1;
	}
	else {
		// seq wrap?
		new_seq = (last_seq & 0xffff0000) | seq;
		while (new_seq < last_seq) {
			new_seq += 0x10000;
			if ((new_seq & 0xffff0000) == 0) // ext seq wrapped
				break;
		}
		seq_diff = new_seq - last_seq;
		atomic_set(&s->ext_seq, new_seq);

		// shift loss tracker bit field and count losses
		if (seq_diff >= (sizeof(s->lost_bits) * 8)) {
			// complete loss
			atomic_add(sizeof(s->lost_bits) * 8, &s->total_lost);
			atomic64_add(sizeof(s->lost_bits) * 8, &g->target.iface_stats->s.packets_lost);
			atomic64_add(sizeof(s->lost_bits) * 8, &rtpe_stats->packets_lost);
			s->lost_bits = -1;
		}
		else {
			while (seq_diff) {
				// shift out one bit and see if we lost it
				if ((s->lost_bits & 0x80000000) == 0) {
					atomic_inc(&s->total_lost);
					atomic64_inc(&g->target.iface_stats->s.packets_lost);
					atomic64_inc(&rtpe_stats->packets_lost);
				}
				s->lost_bits <<= 1;
				seq_diff--;
			}
		}
	}

	// track this frame as being seen
	seq_diff = (new_seq & 0xffff) - seq;
	if (seq_diff < (sizeof(s->lost_bits) * 8))
		s->lost_bits |= (1 << seq_diff);

	// jitter
	// RFC 3550 A.8
	clockrate = g->target.pt_stats[pt_idx]->clock_rate;
	transit = ((uint32_t) (div64_s64(arrival_time, 1000) * clockrate) / 1000) - ts;
	d = atomic_read(&s->transit);
	if (d)
		d = transit - d;
	atomic_set(&s->transit, transit);
	if (d < 0)
		d = -d;
	// ignore implausibly large values
	if (d < 100000)
		atomic_add(d - ((atomic_read(&s->jitter) + 8) >> 4), &s->jitter);

	spin_unlock_irqrestore(&g->ssrc_stats_lock, flags);
}


static unsigned int rtpengine46(struct sk_buff *skb, struct sk_buff *oskb,
		struct rtpengine_table *t, struct re_address *src,
		struct re_address *dst, uint8_t in_tos, const struct xt_action_param *par)
{
	struct udphdr *uh;
	struct rtpengine_target *g;
	struct sk_buff *skb2;
	int err;
	int error_nf_action = XT_CONTINUE;
	int nf_action = NF_DROP;
	int rtp_pt_idx = -2;
	int ssrc_idx = -1;
	unsigned int datalen, datalen_out;
	struct rtp_parsed rtp, rtp2;
	ssize_t offset;
	uint32_t pkt_idx;
	struct re_stream *stream;
	struct re_stream_packet *packet;
	const char *errstr = NULL;
	unsigned long flags;
	unsigned int i;
	unsigned int start_idx, end_idx;
	enum {NOT_RTCP = 0, RTCP, RTCP_FORWARD} is_rtcp;
	ktime_t packet_ts;

	skb_reset_transport_header(skb);
	uh = udp_hdr(skb);
	skb_pull(skb, sizeof(*uh));

	datalen = ntohs(uh->len);
	if (datalen < sizeof(*uh))
		goto out_no_target;
	datalen -= sizeof(*uh);
	DBG("udp payload = %u\n", datalen);
	skb_trim(skb, datalen);

	src->port = ntohs(uh->source);
	dst->port = ntohs(uh->dest);

	g = get_target(t, dst);
	if (!g)
		goto out_no_target;

	// all our outputs filled?
	_r_lock(&g->outputs_lock, flags);
	if (g->outputs_unfilled) {
		// pass to application
		_r_unlock(&g->outputs_lock, flags);
		goto out;
	}
	_r_unlock(&g->outputs_lock, flags);

	DBG("target found, local " MIPF "\n", MIPP(g->target.local));
	DBG("target decrypt RTP hmac and cipher are %s and %s", g->decrypt_rtp.hmac->name,
			g->decrypt_rtp.cipher->name);

	if (is_stun(g, datalen, skb->data))
		goto out;

	// source checks;
	if (g->target.src_mismatch == MSM_IGNORE)
		; // source ignored
	else if (!memcmp(&g->target.expected_src, src, sizeof(*src)))
		; // source matched
	else if (g->target.src_mismatch == MSM_PROPAGATE)
		goto out; // source mismatched, pass to userspace
	else {
		/* MSM_DROP */
		error_nf_action = NF_DROP;
		errstr = "source address mismatch";
		goto out_error;
	}

	packet_ts = ktime_divns(skb->tstamp, 1000000000LL);

	if (g->target.dtls && is_dtls(skb))
		goto out;
	if (g->target.non_forwarding && !g->target.do_intercept) {
		if (g->target.blackhole)
			goto do_stats; // and drop
		goto out; // pass to userspace
	}

	// RTP processing
	rtp.ok = 0;
	rtp.rtcp = 0;
	is_rtcp = NOT_RTCP;
	if (g->target.rtp) {
		if (g->target.rtcp) {
			if (g->target.rtcp_mux) {
				if (is_muxed_rtcp(skb))
					is_rtcp = RTCP;
			}
			else
				is_rtcp = RTCP;
		}

		if (is_rtcp == NOT_RTCP) {
			parse_rtp(&rtp, skb);
			if (!rtp.ok && g->target.rtp_only)
				goto out; // pass to userspace
		}
		else {
			if (g->target.rtcp_fb_fw && is_rtcp_fb_packet(skb))
				; // forward and then drop
			else if (g->target.rtcp_fw)
				is_rtcp = RTCP_FORWARD; // forward, mark, and pass to userspace
			else
				goto out; // just pass to userspace

			parse_rtcp(&rtp, skb);
			if (!rtp.rtcp)
				goto out;
		}
	}
	if (rtp.ok) {
		// RTP ok
		rtp_pt_idx = rtp_payload_type(rtp.rtp_header, &g->target, &g->last_pt);

		// Pass to userspace if SSRC has changed.
		// Look for matching SSRC index if any SSRC were given
		ssrc_idx = target_find_ssrc(g, rtp.rtp_header->ssrc);
		errstr = "SSRC mismatch";
		if (ssrc_idx == -2 || (ssrc_idx == -1 && g->target.ssrc_req))
			goto out_error;

		pkt_idx = rtp_packet_index(&g->decrypt_rtp, &g->target.decrypt, rtp.rtp_header, ssrc_idx,
				g->target.ssrc_stats);
		errstr = "SRTP authentication tag mismatch";
		if (srtp_auth_validate(&g->decrypt_rtp, &g->target.decrypt, &rtp, &pkt_idx, ssrc_idx,
					g->target.ssrc_stats))
			goto out_error;

		// if RTP, only forward packets of known/passthrough payload types
		if (rtp_pt_idx < 0) {
			if (g->target.pt_filter)
				goto out;
		}
		else if (ssrc_idx >= 0 && g->target.ssrc_stats[ssrc_idx]) {
			atomic_set(&g->target.ssrc_stats[ssrc_idx]->last_pt,
					g->target.pt_stats[rtp_pt_idx]->payload_type);
			atomic64_set(&g->target.ssrc_stats[ssrc_idx]->last_packet, packet_ts);
		}

		errstr = "SRTP decryption failed";
		err = srtp_decrypt(&g->decrypt_rtp, &g->target.decrypt, &rtp, &pkt_idx);
		if (err < 0)
			goto out_error;
		if (err == 1)
			update_packet_index(&g->decrypt_rtp, &g->target.decrypt, pkt_idx, ssrc_idx,
					g->target.ssrc_stats);

		skb_trim(skb, rtp.header_len + rtp.payload_len);

		if (g->target.rtp_stats && ssrc_idx != -1 && rtp_pt_idx >= 0)
			rtp_stats(g, &rtp, ktime_to_us(skb->tstamp), rtp_pt_idx, ssrc_idx, t->rtpe_stats);

		DBG("packet payload decrypted as %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x...\n",
				rtp.payload[0], rtp.payload[1], rtp.payload[2], rtp.payload[3],
				rtp.payload[4], rtp.payload[5], rtp.payload[6], rtp.payload[7],
				rtp.payload[8], rtp.payload[9], rtp.payload[10], rtp.payload[11],
				rtp.payload[12], rtp.payload[13], rtp.payload[14], rtp.payload[15],
				rtp.payload[16], rtp.payload[17], rtp.payload[18], rtp.payload[19]);
	}
	else if (is_rtcp != NOT_RTCP && rtp.rtcp) {
		pkt_idx = 0;
		err = srtcp_auth_validate(&g->decrypt_rtcp, &g->target.decrypt, &rtp, &pkt_idx);
		errstr = "SRTCP authentication tag mismatch";
		if (err == -1)
			goto out_error;
		if (err == 1) {
			// decrypt
			errstr = "SRTCP decryption failed";
			if (srtcp_decrypt(&g->decrypt_rtcp, &g->target.decrypt, &rtp, pkt_idx))
				goto out_error;
		}
		skb_trim(skb, rtp.header_len + rtp.payload_len);
		if (is_rtcp == RTCP_FORWARD) {
			// mark packet as "handled" with negative timestamp
			oskb->tstamp = (ktime_t) {-ktime_to_ns(oskb->tstamp)};
			nf_action = XT_CONTINUE;
		}
	}

	if (g->target.do_intercept) {
		DBG("do_intercept is set\n");
		stream = get_stream_lock(NULL, g->target.intercept_stream_idx);
		if (stream) {
			packet = kzalloc(sizeof(*packet), GFP_ATOMIC);
			if (packet) {
				packet->skbuf = intercept_skb_copy(skb, src);
				if (packet->skbuf)
					add_stream_packet(stream, packet);
				else
					free_packet(packet);
			}
			stream_put(stream);
		}
	}

	// output
	start_idx = (is_rtcp != NOT_RTCP) ? g->num_rtp_destinations : 0;
	end_idx = (is_rtcp != NOT_RTCP) ? g->target.num_destinations : g->num_rtp_destinations;

	if (start_idx == end_idx)
		goto out; // pass to userspace

	for (i = start_idx; i < end_idx; i++) {
		struct rtpengine_output *o = &g->outputs[i];
		DBG("output src " MIPF " -> dst " MIPF "\n", MIPP(o->output.src_addr), MIPP(o->output.dst_addr));
		// do we need a copy?
		if (i == (end_idx - 1)) {
			skb2 = skb; // last iteration - use original
			skb = NULL;
			offset = 0;
		}
		else {
			// make copy
			skb2 = skb_copy_expand(skb, MAX_HEADER, MAX_SKB_TAIL_ROOM, GFP_ATOMIC);
			if (!skb2) {
				log_err("out of memory while creating skb copy");
				atomic64_inc(&g->target.stats->errors);
				atomic64_inc(&g->target.iface_stats->in.errors);
				atomic64_inc(&t->rtpe_stats->errors_kernel);
				continue;
			}
			skb_gso_reset(skb2);
			offset = skb2->data - skb->data;
		}
		// adjust RTP pointers
		rtp2 = rtp;
		if (rtp.rtp_header)
			rtp2.rtp_header = (void *) (((char *) rtp2.rtp_header) + offset);
		rtp2.payload = (void *) (((char *) rtp2.payload) + offset);

		datalen_out = skb2->len;

		err = send_proxy_packet_output(skb2, g, rtp_pt_idx, o, &rtp2, ssrc_idx, par);
		if (err) {
			atomic64_inc(&g->target.stats->errors);
			atomic64_inc(&g->target.iface_stats->in.errors);
			atomic64_inc(&o->output.stats->errors);
			atomic64_inc(&o->output.iface_stats->out.errors);
			atomic64_inc(&t->rtpe_stats->errors_kernel);
		}
		else {
			atomic64_inc(&o->output.stats->packets);
			atomic64_add(datalen_out, &o->output.stats->bytes);
			atomic64_inc(&o->output.iface_stats->out.packets);
			atomic64_add(datalen_out, &o->output.iface_stats->out.bytes);
		}
	}

do_stats:
	atomic_set(&g->target.stats->tos, in_tos);
	atomic64_set(&g->target.stats->last_packet, packet_ts);

	atomic64_inc(&g->target.stats->packets);
	atomic64_add(datalen, &g->target.stats->bytes);
	atomic64_inc(&g->target.iface_stats->in.packets);
	atomic64_add(datalen, &g->target.iface_stats->in.bytes);
	atomic64_inc(&t->rtpe_stats->packets_kernel);
	atomic64_add(datalen, &t->rtpe_stats->bytes_kernel);

	if (rtp_pt_idx >= 0) {
		atomic64_inc(&g->target.pt_stats[rtp_pt_idx]->packets);
		atomic64_add(datalen, &g->target.pt_stats[rtp_pt_idx]->bytes);
	}
	else if (rtp_pt_idx == -2)
		/* not RTP */ ;
	else if (rtp_pt_idx == -1) {
		atomic64_inc(&g->target.stats->errors);
		atomic64_inc(&g->target.iface_stats->in.errors);
	}

	target_put(g);
	table_put(t);
	if (skb)
		kfree_skb(skb);

	return nf_action;

out_error:
	log_err("x_tables action failed: %s", errstr);
	atomic64_inc(&g->target.stats->errors);
	atomic64_inc(&g->target.iface_stats->in.errors);
	atomic64_inc(&t->rtpe_stats->errors_kernel);
out:
	target_put(g);
out_no_target:
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

	skb_gso_reset(skb);
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

	return rtpengine46(skb, oskb, t, &src, &dst, (uint8_t)ih->tos, par);

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

	skb_gso_reset(skb);
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

	return rtpengine46(skb, oskb, t, &src, &dst, ipv6_get_dsfield(ih), par);

skip2:
	kfree_skb(skb);
skip3:
	table_put(t);
skip:
	return XT_CONTINUE;
}


static int check(const struct xt_tgchk_param *par) {
	const struct xt_rtpengine_info *pinfo = par->targinfo;

	if (!my_proc_root) {
		printk(KERN_WARNING "xt_RTPENGINE check() without proc_root\n");
		return -EINVAL;
	}
	if (pinfo->id >= MAX_ID) {
		printk(KERN_WARNING "xt_RTPENGINE ID too high (%u >= %u)\n", pinfo->id, MAX_ID);
		return -EINVAL;
	}

	return 0;
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
	DBG("using uid %u, gid %d\n", proc_uid, proc_gid);
	proc_kuid = KUIDT_INIT(proc_uid);
	proc_kgid = KGIDT_INIT(proc_gid);
	rwlock_init(&table_lock);
	auto_array_init(&calls);
	auto_array_init(&streams);

	ret = -ENOMEM;
	err = "could not register /proc/ entries";
	my_proc_root = proc_mkdir_user("rtpengine", 0555, NULL);
	if (!my_proc_root)
		goto fail;
	/* my_proc_root->owner = THIS_MODULE; */

	proc_control = proc_create_user("control", S_IFREG | 0220, my_proc_root,
			&proc_main_control_ops, NULL);
	if (!proc_control)
		goto fail;

	proc_list = proc_create_user("list", S_IFREG | 0444, my_proc_root, &proc_main_list_ops, NULL);
	if (!proc_list)
		goto fail;

	err = "could not register xtables target";
	ret = xt_register_targets(xt_rtpengine_regs, ARRAY_SIZE(xt_rtpengine_regs));
	if (ret)
		goto fail;

#ifdef KERNEL_PLAYER
	rwlock_init(&media_player_lock);
#endif

	return 0;

fail:
#ifdef KERNEL_PLAYER
	shut_all_threads();
#endif
	clear_proc(&proc_control);
	clear_proc(&proc_list);
	clear_proc(&my_proc_root);

	printk(KERN_ERR "Failed to load xt_RTPENGINE module: %s\n", err);

	return ret;
}

static void __exit fini(void) {
	printk(KERN_NOTICE "Unregistering xt_RTPENGINE module\n");
	xt_unregister_targets(xt_rtpengine_regs, ARRAY_SIZE(xt_rtpengine_regs));

#ifdef KERNEL_PLAYER
	shut_all_threads();
#endif
	clear_proc(&proc_control);
	clear_proc(&proc_list);
	clear_proc(&my_proc_root);

	auto_array_free(&streams);
	auto_array_free(&calls);

#ifdef KERNEL_PLAYER
	// these should be empty
	kfree(play_streams);
	kfree(stream_packets);
#endif
}

module_init(init);
module_exit(fini);
