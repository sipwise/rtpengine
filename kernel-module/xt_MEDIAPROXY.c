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
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/netfilter/x_tables.h>
#ifndef __MP_EXTERNAL
#include <linux/netfilter/xt_MEDIAPROXY.h>
#else
#include "xt_MEDIAPROXY.h"
#endif

MODULE_LICENSE("GPL");




#define MAX_ID 64 /* - 1 */
#define MAX_SKB_TAIL_ROOM (sizeof(((struct mediaproxy_srtp *) 0)->mki) + 20)

#define MIPF		"%i:%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x:%u"
#define MIPP(x)		(x).family,		\
			(x).u8[0],		\
			(x).u8[1],		\
			(x).u8[2],		\
			(x).u8[3],		\
			(x).u8[4],		\
			(x).u8[5],		\
			(x).u8[6],		\
			(x).u8[7],		\
			(x).u8[8],		\
			(x).u8[9],		\
			(x).u8[10],		\
			(x).u8[11],		\
			(x).u8[12],		\
			(x).u8[13],		\
			(x).u8[14],		\
			(x).u8[15],		\
			(x).port

#if 0
#define DBG(x...) printk(KERN_DEBUG x)
#else
#define DBG(x...) ((void)0)
#endif



#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
#define PDE_DATA(i) (PDE(i)->data)
#endif




struct mp_hmac;
struct mp_cipher;
struct rtp_parsed;
struct mp_crypto_context;




static struct proc_dir_entry *my_proc_root;
static struct proc_dir_entry *proc_list;
static struct proc_dir_entry *proc_control;
static struct mediaproxy_table *table[MAX_ID];
static rwlock_t table_lock;




static ssize_t proc_control_write(struct file *, const char __user *, size_t, loff_t *);
static int proc_control_open(struct inode *, struct file *);
static int proc_control_close(struct inode *, struct file *);

static ssize_t proc_status(struct file *, char __user *, size_t, loff_t *);

static ssize_t proc_main_control_write(struct file *, const char __user *, size_t, loff_t *);
static int proc_main_control_open(struct inode *, struct file *);
static int proc_main_control_close(struct inode *, struct file *);

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

static void table_push(struct mediaproxy_table *);
static struct mediaproxy_target *get_target(struct mediaproxy_table *, u_int16_t);

static int aes_f8_session_key_init(struct mp_crypto_context *, struct mediaproxy_srtp *);
static int srtp_encrypt_aes_cm(struct mp_crypto_context *, struct mediaproxy_srtp *,
		struct rtp_parsed *, u_int64_t);
static int srtp_encrypt_aes_f8(struct mp_crypto_context *, struct mediaproxy_srtp *,
		struct rtp_parsed *, u_int64_t);






struct mp_crypto_context {
	spinlock_t			lock; /* protects roc and last_index */
	unsigned char			session_key[16];
	unsigned char			session_salt[14];
	unsigned char			session_auth_key[20];
	u_int32_t			roc;
	struct crypto_cipher		*tfm[2];
	struct crypto_shash		*shash;
	const struct mp_cipher		*cipher;
	const struct mp_hmac		*hmac;
};

struct mediaproxy_target {
	atomic_t			refcnt;
	u_int32_t			table;
	struct mediaproxy_target_info	target;

	spinlock_t			stats_lock;
	struct mediaproxy_stats		stats;

	struct mp_crypto_context	decrypt;
	struct mp_crypto_context	encrypt;
};

struct mp_bitfield {
	unsigned long			b[256 / (sizeof(unsigned long) * 8)];
	unsigned int			used;
};

struct mp_bucket {
	struct mp_bitfield		targets;
	struct mediaproxy_target	*target[256];
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

	struct mp_bitfield		buckets;
	struct mp_bucket		*bucket[256];

	unsigned int			targets;
};

struct mp_cipher {
	enum mediaproxy_cipher		id;
	const char			*name;
	const char			*tfm_name;
	int				(*decrypt)(struct mp_crypto_context *, struct mediaproxy_srtp *,
			struct rtp_parsed *, u_int64_t);
	int				(*encrypt)(struct mp_crypto_context *, struct mediaproxy_srtp *,
			struct rtp_parsed *, u_int64_t);
	int				(*session_key_init)(struct mp_crypto_context *, struct mediaproxy_srtp *);
};

struct mp_hmac {
	enum mediaproxy_hmac		id;
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








static const struct file_operations proc_control_ops = {
	.write			= proc_control_write,
	.open			= proc_control_open,
	.release		= proc_control_close,
};

static const struct file_operations proc_main_control_ops = {
	.write			= proc_main_control_write,
	.open			= proc_main_control_open,
	.release		= proc_main_control_close,
};

static const struct file_operations proc_status_ops = {
	.read			= proc_status,
};

static const struct file_operations proc_list_ops = {
	.open			= proc_list_open,
	.read			= seq_read,
	.llseek			= seq_lseek,
	.release		= seq_release,
};

static const struct file_operations proc_blist_ops = {
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
	.open			= proc_main_list_open,
	.read			= seq_read,
	.llseek			= seq_lseek,
	.release		= seq_release,
};

static const struct seq_operations proc_main_list_seq_ops = {
	.start			= proc_main_list_start,
	.next			= proc_main_list_next,
	.stop			= proc_main_list_stop,
	.show			= proc_main_list_show,
};

static const struct mp_cipher mp_ciphers[] = {
	[MPC_INVALID] = {
		.id		= MPC_INVALID,
		.name		= NULL,
	},
	[MPC_NULL] = {
		.id		= MPC_NULL,
		.name		= "NULL",
	},
	[MPC_AES_CM] = {
		.id		= MPC_AES_CM,
		.name		= "AES-CM",
		.tfm_name	= "aes",
		.decrypt	= srtp_encrypt_aes_cm,
		.encrypt	= srtp_encrypt_aes_cm,
	},
	[MPC_AES_F8] = {
		.id		= MPC_AES_F8,
		.name		= "AES-F8",
		.tfm_name	= "aes",
		.decrypt	= srtp_encrypt_aes_f8,
		.encrypt	= srtp_encrypt_aes_f8,
		.session_key_init = aes_f8_session_key_init,
	},
};

static const struct mp_hmac mp_hmacs[] = {
	[MPH_INVALID] = {
		.id		= MPH_INVALID,
		.name		= NULL,
	},
	[MPH_NULL] = {
		.id		= MPH_NULL,
		.name		= "NULL",
	},
	[MPH_HMAC_SHA1] = {
		.id		= MPH_HMAC_SHA1,
		.name		= "HMAC-SHA1",
		.tfm_name	= "hmac(sha1)",
	},
};

static const char *mp_msm_strings[] = {
	[MSM_IGNORE]		= "",
	[MSM_DROP]		= "drop",
	[MSM_PROPAGATE]		= "propagate",
};





static struct mediaproxy_table *new_table(void) {
	struct mediaproxy_table *t;

	DBG("Creating new table\n");

	if (!try_module_get(THIS_MODULE))
		return NULL;

	t = kmalloc(sizeof(*t), GFP_KERNEL);
	if (!t) {
		module_put(THIS_MODULE);
		return NULL;
	}

	memset(t, 0, sizeof(*t));

	atomic_set(&t->refcnt, 1);
	rwlock_init(&t->target_lock);
	t->id = -1;

	return t;
}




static void table_hold(struct mediaproxy_table *t) {
	atomic_inc(&t->refcnt);
}





static int table_create_proc(struct mediaproxy_table *t, u_int32_t id) {
	char num[10];

	sprintf(num, "%u", id);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
	t->proc = create_proc_entry(num, S_IFDIR | S_IRUGO | S_IXUGO, my_proc_root);
#else
	t->proc = proc_mkdir_mode(num, S_IRUGO | S_IXUGO, my_proc_root);
#endif
	if (!t->proc)
		return -1;

	t->status = proc_create_data("status", S_IFREG | S_IRUGO, t->proc, &proc_status_ops,
		(void *) (unsigned long) id);
	if (!t->status)
		return -1;

	t->control = proc_create_data("control", S_IFREG | S_IWUSR | S_IWGRP, t->proc,
			&proc_control_ops, (void *) (unsigned long) id);
	if (!t->control)
		return -1;

	t->list = proc_create_data("list", S_IFREG | S_IRUGO, t->proc,
			&proc_list_ops, (void *) (unsigned long) id);
	if (!t->list)
		return -1;

	t->blist = proc_create_data("blist", S_IFREG | S_IRUGO, t->proc,
			&proc_blist_ops, (void *) (unsigned long) id);
	if (!t->blist)
		return -1;

	return 0;
}




static struct mediaproxy_table *new_table_link(u_int32_t id) {
	struct mediaproxy_table *t;
	unsigned long flags;

	if (id >= MAX_ID)
		return NULL;

	t = new_table();
	if (!t) {
		printk(KERN_WARNING "xt_MEDIAPROXY out of memory\n");
		return NULL;
	}

	write_lock_irqsave(&table_lock, flags);
	if (table[id]) {
		write_unlock_irqrestore(&table_lock, flags);
		table_push(t);
		printk(KERN_WARNING "xt_MEDIAPROXY duplicate ID %u\n", id);
		return NULL;
	}

	table_hold(t);
	table[id] = t;
	t->id = id;
	write_unlock_irqrestore(&table_lock, flags);

	if (table_create_proc(t, id))
		printk(KERN_WARNING "xt_MEDIAPROXY failed to create /proc entry for ID %u\n", id);


	return t;
}





static void free_crypto_context(struct mp_crypto_context *c) {
	int i;

	for (i = 0; i < ARRAY_SIZE(c->tfm); i++) {
		if (c->tfm[i])
			crypto_free_cipher(c->tfm[i]);
	}
	if (c->shash)
		crypto_free_shash(c->shash);
}

static void target_push(struct mediaproxy_target *t) {
	if (!t)
		return;

	if (!atomic_dec_and_test(&t->refcnt))
		return;

	DBG("Freeing target\n");

	free_crypto_context(&t->decrypt);
	free_crypto_context(&t->encrypt);

	kfree(t);
}






static void target_hold(struct mediaproxy_target *t) {
	atomic_inc(&t->refcnt);
}






static void clear_proc(struct proc_dir_entry **e) {
	if (!e || !*e)
		return;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
	remove_proc_entry((*e)->name, (*e)->parent);
#else
	proc_remove(*e);
#endif
	*e = NULL;
}





static void table_push(struct mediaproxy_table *t) {
	int i, j;
	struct mp_bucket *b;

	if (!t)
		return;

	if (!atomic_dec_and_test(&t->refcnt))
		return;

	DBG("Freeing table\n");

	for (i = 0; i < 256; i++) {
		b = t->bucket[i];
		if (!b)
			continue;

		for (j = 0; j < 256; j++) {
			if (!b->target[j])
				continue;
			b->target[j]->table = -1;
			target_push(b->target[j]);
			b->target[j] = NULL;
		}

		kfree(b);
		t->bucket[i] = NULL;
	}

	clear_proc(&t->status);
	clear_proc(&t->control);
	clear_proc(&t->list);
	clear_proc(&t->blist);
	clear_proc(&t->proc);

	kfree(t);

	module_put(THIS_MODULE);
}




static int unlink_table(struct mediaproxy_table *t) {
	unsigned long flags;

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

	clear_proc(&t->status);
	clear_proc(&t->control);
	clear_proc(&t->list);
	clear_proc(&t->blist);
	clear_proc(&t->proc);

	table_push(t);

	return 0;
}




static struct mediaproxy_table *get_table(u_int32_t id) {
	struct mediaproxy_table *t;
	unsigned long flags;

	if (id >= MAX_ID)
		return NULL;

	read_lock_irqsave(&table_lock, flags);
	t = table[id];
	if (t)
		table_hold(t);
	read_unlock_irqrestore(&table_lock, flags);

	return t;
}




static ssize_t proc_status(struct file *f, char __user *b, size_t l, loff_t *o) {
	struct inode *inode;
	char buf[256];
	struct mediaproxy_table *t;
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
	len += sprintf(buf + len, "Targets:     %u\n", t->targets);
	len += sprintf(buf + len, "Buckets:     %u\n", t->buckets.used);
	read_unlock_irqrestore(&t->target_lock, flags);

	table_push(t);

	if (copy_to_user(b, buf, len))
		return -EFAULT;
	*o += len;

	return len;
}



static int proc_main_list_open(struct inode *i, struct file *f) {
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
	struct mediaproxy_table *t = NULL;
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
	struct mediaproxy_table *g = v;

	seq_printf(f, "%u\n", g->id);
	table_push(g);

	return 0;
}





static inline unsigned char bitfield_next_slot(unsigned int slot) {
	unsigned char c;
	c = slot * (sizeof(unsigned long) * 8);
	c += sizeof(unsigned long) * 8;
	return c;
}
static inline unsigned int bitfield_slot(unsigned char i) {
	return i / (sizeof(unsigned long) * 8);
}
static inline unsigned int bitfield_bit(unsigned char i) {
	return i % (sizeof(unsigned long) * 8);
}
static inline void bitfield_set(struct mp_bitfield *bf, unsigned char i) {
	unsigned int b, m;
	unsigned long k;

	b = bitfield_slot(i);
	m = bitfield_bit(i);
	k = 1UL << m;
	if ((bf->b[b] & k))
		return;
	bf->b[b] |= k;
	bf->used++;
}
static inline void bitfield_clear(struct mp_bitfield *bf, unsigned char i) {
	unsigned int b, m;
	unsigned long k;

	b = bitfield_slot(i);
	m = bitfield_bit(i);
	k = 1UL << m;
	if (!(bf->b[b] & k))
		return;
	bf->b[b] &= ~k;
	bf->used--;
}
static inline struct mediaproxy_target *find_next_target(struct mediaproxy_table *t, int *port) {
	unsigned long flags;
	struct mp_bucket *b;
	unsigned char hi, lo;
	unsigned int hi_b, lo_b;
	struct mediaproxy_target *g;

	if (*port < 0 || *port > 0xffff)
		return NULL;

	hi = (*port & 0xff00) >> 8;
	lo = *port & 0xff;

	read_lock_irqsave(&t->target_lock, flags);

	for (;;) {
		hi_b = bitfield_slot(hi);
		if (!t->buckets.b[hi_b]) {
			hi = bitfield_next_slot(hi_b);
			lo = 0;
			goto next;
		}

		b = t->bucket[hi];
		if (!b) {
			hi++;
			lo = 0;
			goto next;
		}

		lo_b = bitfield_slot(lo);
		if (!b->targets.b[lo_b]) {
			lo = bitfield_next_slot(lo_b);
			goto next_lo;
		}

		g = b->target[lo];
		if (!g) {
			lo++;
			goto next_lo;
		}

		target_hold(g);
		break;

next_lo:
		if (!lo)
			hi++;
next:
		if (!hi && !lo)
			break;
	}

	read_unlock_irqrestore(&t->target_lock, flags);

	*port = (hi << 8) | lo;
	(*port)++;

	return g;
}



static int proc_blist_open(struct inode *i, struct file *f) {
	u_int32_t id;
	struct mediaproxy_table *t;

	id = (u_int32_t) (unsigned long) PDE_DATA(i);
	t = get_table(id);
	if (!t)
		return -ENOENT;

	table_push(t);

	return 0;
}

static int proc_blist_close(struct inode *i, struct file *f) {
	u_int32_t id;
	struct mediaproxy_table *t;

	id = (u_int32_t) (unsigned long) PDE_DATA(i);
	t = get_table(id);
	if (!t)
		return 0;

	table_push(t);

	return 0;
}

static ssize_t proc_blist_read(struct file *f, char __user *b, size_t l, loff_t *o) {
	struct inode *inode;
	u_int32_t id;
	struct mediaproxy_table *t;
	struct mediaproxy_list_entry op;
	int err;
	struct mediaproxy_target *g;
	unsigned long flags;
	int port;

	if (l != sizeof(op))
		return -EINVAL;
	if (*o < 0)
		return -EINVAL;

	inode = f->f_path.dentry->d_inode;
	id = (u_int32_t) (unsigned long) PDE_DATA(inode);
	t = get_table(id);
	if (!t)
		return -ENOENT;

	port = (int) *o;
	g = find_next_target(t, &port);
	*o = port;
	err = 0;
	if (!g)
		goto err;

	memset(&op, 0, sizeof(op));
	memcpy(&op.target, &g->target, sizeof(op.target));

	spin_lock_irqsave(&g->stats_lock, flags);
	memcpy(&op.stats, &g->stats, sizeof(op.stats));
	spin_unlock_irqrestore(&g->stats_lock, flags);

	spin_lock_irqsave(&g->decrypt.lock, flags);
	op.target.decrypt.last_index = g->target.decrypt.last_index;
	spin_unlock_irqrestore(&g->decrypt.lock, flags);

	spin_lock_irqsave(&g->encrypt.lock, flags);
	op.target.encrypt.last_index = g->target.encrypt.last_index;
	spin_unlock_irqrestore(&g->encrypt.lock, flags);

	target_push(g);

	err = -EFAULT;
	if (copy_to_user(b, &op, sizeof(op)))
		goto err;

	table_push(t);
	return l;

err:
	table_push(t);
	return err;
}





static int proc_list_open(struct inode *i, struct file *f) {
	int err;
	struct seq_file *p;
	u_int32_t id;
	struct mediaproxy_table *t;

	id = (u_int32_t) (unsigned long) PDE_DATA(i);
	t = get_table(id);
	if (!t)
		return -ENOENT;
	table_push(t);

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
	struct mediaproxy_table *t;
	struct mediaproxy_target *g;
	int port;

	port = (int) *o;

	t = get_table(id);
	if (!t)
		return NULL;

	g = find_next_target(t, &port);

	*o = port;
	table_push(t);

	return g;
}

static void proc_list_addr_print(struct seq_file *f, const char *s, const struct mp_address *a) {
	if (!a->family)
		return;

	seq_printf(f, "    %6s ", s);
	switch (a->family) {
		case AF_INET:
			seq_printf(f, "inet4 %u.%u.%u.%u:%u\n", a->u.u8[0], a->u.u8[1], a->u.u8[2],
					a->u.u8[3], a->port);
			break;
		case AF_INET6:
			seq_printf(f, "inet6 [%x:%x:%x:%x:%x:%x:%x:%x]:%u\n",
				htons(a->u.u16[0]), htons(a->u.u16[1]),
				htons(a->u.u16[2]), htons(a->u.u16[3]), htons(a->u.u16[4]), htons(a->u.u16[5]),
				htons(a->u.u16[6]), htons(a->u.u16[7]), a->port);
			break;
		default:
			seq_printf(f, "<unknown>\n");
			break;
	}
}

static void proc_list_crypto_print(struct seq_file *f, struct mp_crypto_context *c,
		struct mediaproxy_srtp *s, const char *label)
{
	int hdr = 0;

	if (c->cipher && c->cipher->id != MPC_NULL) {
		if (!hdr++)
			seq_printf(f, "    SRTP %s parameters:\n", label);
		seq_printf(f, "        cipher: %s\n", c->cipher->name ? : "<invalid>");
		if (s->mki_len)
			seq_printf(f, "            MKI: length %u, %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x...\n",
					s->mki_len,
					s->mki[0], s->mki[1], s->mki[2], s->mki[3],
					s->mki[4], s->mki[5], s->mki[6], s->mki[7]);
	}
	if (c->hmac && c->hmac->id != MPH_NULL) {
		if (!hdr++)
			seq_printf(f, "    SRTP %s parameters:\n", label);
		seq_printf(f, "        HMAC: %s\n", c->hmac->name ? : "<invalid>");
		seq_printf(f, "            auth tag length: %u\n", s->auth_tag_len);
	}
}

static int proc_list_show(struct seq_file *f, void *v) {
	struct mediaproxy_target *g = v;
	unsigned long flags;

	seq_printf(f, "port %5u:\n", g->target.target_port);
	proc_list_addr_print(f, "src", &g->target.src_addr);
	proc_list_addr_print(f, "dst", &g->target.dst_addr);
	proc_list_addr_print(f, "mirror", &g->target.mirror_addr);
	proc_list_addr_print(f, "expect", &g->target.expected_src);
	if (g->target.src_mismatch > 0 && g->target.src_mismatch <= ARRAY_SIZE(mp_msm_strings))
		seq_printf(f, "    src mismatch action: %s\n", mp_msm_strings[g->target.src_mismatch]);
	spin_lock_irqsave(&g->stats_lock, flags);
	seq_printf(f, "    stats: %20llu bytes, %20llu packets, %20llu errors\n",
		g->stats.bytes, g->stats.packets, g->stats.errors);
	spin_unlock_irqrestore(&g->stats_lock, flags);
	proc_list_crypto_print(f, &g->decrypt, &g->target.decrypt, "decryption (incoming)");
	proc_list_crypto_print(f, &g->encrypt, &g->target.encrypt, "encryption (outgoing)");
	if (g->target.rtcp_mux)
		seq_printf(f, "    option: rtcp-mux\n");
	if (g->target.dtls)
		seq_printf(f, "    option: dtls\n");

	target_push(g);

	return 0;
}





static int table_del_target(struct mediaproxy_table *t, u_int16_t port) {
	unsigned char hi, lo;
	struct mp_bucket *b;
	struct mediaproxy_target *g = NULL;
	unsigned long flags;

	if (!port)
		return -EINVAL;

	hi = (port & 0xff00) >> 8;
	lo = port & 0xff;

	write_lock_irqsave(&t->target_lock, flags);
	b = t->bucket[hi];
	if (!b)
		goto out;
	g = b->target[lo];
	if (!g)
		goto out;

	b->target[lo] = NULL;
	bitfield_clear(&b->targets, lo);
	t->targets--;
	if (!b->targets.used) {
		t->bucket[hi] = NULL;
		bitfield_clear(&t->buckets, hi);
	}
	else
		b = NULL;

out:
	write_unlock_irqrestore(&t->target_lock, flags);

	if (!g)
		return -ENOENT;
	if (b)
		kfree(b);

	target_push(g);

	return 0;
}




static int is_valid_address(struct mp_address *mpa) {
	switch (mpa->family) {
		case AF_INET:
			if (!mpa->u.ipv4)
				return 0;
			break;

		case AF_INET6:
			if (!mpa->u.u32[0] && !mpa->u.u32[1] && !mpa->u.u32[2] && !mpa->u.u32[3])
				return 0;
			break;

		default:
			return 0;
	}

	if (!mpa->port)
		return 0;

	return 1;
}




static int validate_srtp(struct mediaproxy_srtp *s) {
	if (s->cipher <= MPC_INVALID)
		return -1;
	if (s->cipher >= __MPC_LAST)
		return -1;
	if (s->hmac <= MPH_INVALID)
		return -1;
	if (s->hmac >= __MPH_LAST)
		return -1;
	if (s->auth_tag_len > 20)
		return -1;
	if (s->mki_len > sizeof(s->mki))
		return -1;
	return 0;
}



/* XXX shared code */
static void aes_ctr_128(unsigned char *out, const unsigned char *in, int in_len,
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
		const unsigned char *key, const unsigned char *iv)
{
	struct crypto_cipher *tfm;

	tfm = crypto_alloc_cipher("aes", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	crypto_cipher_setkey(tfm, key, 16);
	aes_ctr_128(out, in, in_len, tfm, iv);

	crypto_free_cipher(tfm);
	return 0;
}

static int prf_n(unsigned char *out, int len, const unsigned char *key, const unsigned char *x) {
	unsigned char iv[16];
	unsigned char o[32];
	unsigned char in[32];
	int in_len, ret;

	memcpy(iv, x, 14);
	iv[14] = iv[15] = 0;
	in_len = len > 16 ? 32 : 16;
	memset(in, 0, in_len);

	ret = aes_ctr_128_no_ctx(o, in, in_len, key, iv);
	if (ret)
		return ret;

	memcpy(out, o, len);

	return 0;
}

static int gen_session_key(unsigned char *out, int len, struct mediaproxy_srtp *s, unsigned char label) {
	unsigned char key_id[7];
	unsigned char x[14];
	int i, ret;

	memset(key_id, 0, sizeof(key_id));

	key_id[0] = label;

	memcpy(x, s->master_salt, 14);
	for (i = 13 - 6; i < 14; i++)
		x[i] = key_id[i - (13 - 6)] ^ x[i];

	ret = prf_n(out, len, s->master_key, x);
	if (ret)
		return ret;
	return 0;
}




static int aes_f8_session_key_init(struct mp_crypto_context *c, struct mediaproxy_srtp *s) {
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

static int gen_session_keys(struct mp_crypto_context *c, struct mediaproxy_srtp *s) {
	int ret;
	const char *err;

	if (s->cipher == MPC_NULL && s->hmac == MPH_NULL)
		return 0;
	err = "failed to generate session key";
	ret = gen_session_key(c->session_key, 16, s, 0x00);
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
		crypto_cipher_setkey(c->tfm[0], c->session_key, 16);
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

	DBG("master key %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
			s->master_key[0], s->master_key[1], s->master_key[2], s->master_key[3],
			s->master_key[4], s->master_key[5], s->master_key[6], s->master_key[7],
			s->master_key[8], s->master_key[9], s->master_key[10], s->master_key[11],
			s->master_key[12], s->master_key[13], s->master_key[14], s->master_key[15]);
	DBG("master salt %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
			s->master_salt[0], s->master_salt[1], s->master_salt[2], s->master_salt[3],
			s->master_salt[4], s->master_salt[5], s->master_salt[6], s->master_salt[7],
			s->master_salt[8], s->master_salt[9], s->master_salt[10], s->master_salt[11],
			s->master_salt[12], s->master_salt[13]);
	DBG("session key %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
			c->session_key[0], c->session_key[1], c->session_key[2], c->session_key[3],
			c->session_key[4], c->session_key[5], c->session_key[6], c->session_key[7],
			c->session_key[8], c->session_key[9], c->session_key[10], c->session_key[11],
			c->session_key[12], c->session_key[13], c->session_key[14], c->session_key[15]);
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




static void crypto_context_init(struct mp_crypto_context *c, struct mediaproxy_srtp *s) {
	c->cipher = &mp_ciphers[s->cipher];
	c->hmac = &mp_hmacs[s->hmac];
}

static int table_new_target(struct mediaproxy_table *t, struct mediaproxy_target_info *i, int update) {
	unsigned char hi, lo;
	struct mediaproxy_target *g;
	struct mp_bucket *b, *ba = NULL;
	struct mediaproxy_target *og = NULL;
	int err;
	unsigned long flags;

	if (!i->target_port)
		return -EINVAL;
	if (!is_valid_address(&i->src_addr))
		return -EINVAL;
	if (!is_valid_address(&i->dst_addr))
		return -EINVAL;
	if (i->src_addr.family != i->dst_addr.family)
		return -EINVAL;
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

	err = -ENOMEM;
	g = kmalloc(sizeof(*g), GFP_KERNEL);
	if (!g)
		goto fail1;
	memset(g, 0, sizeof(*g));
	g->table = t->id;
	atomic_set(&g->refcnt, 1);
	spin_lock_init(&g->stats_lock);
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

	hi = (i->target_port & 0xff00) >> 8;
	lo = i->target_port & 0xff;

	write_lock_irqsave(&t->target_lock, flags);
	if (!(b = t->bucket[hi])) {
		err = -ENOENT;
		if (update)
			goto fail4;

		write_unlock_irqrestore(&t->target_lock, flags);

		b = kmalloc(sizeof(*b), GFP_KERNEL);
		err = -ENOMEM;
		if (!b)
			goto fail2;
		memset(b, 0, sizeof(*b));

		write_lock_irqsave(&t->target_lock, flags);

		if (!t->bucket[hi]) {
			t->bucket[hi] = b;
			bitfield_set(&t->buckets, hi);
		}
		else {
			ba = b;
			b = t->bucket[hi];
		}
	}
	if (update) {
		err = -ENOENT;
		og = b->target[lo];
		if (!og)
			goto fail4;

		spin_lock(&og->stats_lock);	/* nested lock! irqs are disabled already */
		memcpy(&g->stats, &og->stats, sizeof(g->stats));
		spin_unlock(&og->stats_lock);
	}
	else {
		err = -EEXIST;
		if (b->target[lo])
			goto fail4;
		bitfield_set(&b->targets, lo);
		t->targets++;
	}

	b->target[lo] = g;
	g = NULL;
	write_unlock_irqrestore(&t->target_lock, flags);

	if (ba)
		kfree(ba);
	if (og)
		target_push(og);

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





static struct mediaproxy_target *get_target(struct mediaproxy_table *t, u_int16_t port) {
	unsigned char hi, lo;
	struct mediaproxy_target *r;
	unsigned long flags;

	if (!t)
		return NULL;
	if (!port)
		return NULL;

	hi = (port & 0xff00) >> 8;
	lo = port & 0xff;

	read_lock_irqsave(&t->target_lock, flags);
	r = t->bucket[hi] ? t->bucket[hi]->target[lo] : NULL;
	if (r)
		target_hold(r);
	read_unlock_irqrestore(&t->target_lock, flags);

	return r;
}





static int proc_main_control_open(struct inode *inode, struct file *file) {
	if (!try_module_get(THIS_MODULE))
		return -ENXIO;
	return 0;
}

static int proc_main_control_close(struct inode *inode, struct file *file) {
	module_put(THIS_MODULE);
	return 0;
}

static ssize_t proc_main_control_write(struct file *file, const char __user *buf, size_t buflen, loff_t *off) {
	char b[30];
	unsigned long id;
	char *endp;
	struct mediaproxy_table *t;
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
		table_push(t);
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
		table_push(t);
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
	struct mediaproxy_table *t;
	unsigned long flags;

	id = (u_int32_t) (unsigned long) PDE_DATA(inode);
	t = get_table(id);
	if (!t)
		return -ENOENT;

	write_lock_irqsave(&table_lock, flags);
	if (t->pid) {
		write_unlock_irqrestore(&table_lock, flags);
		table_push(t);
		return -EBUSY;
	}
	t->pid = current->tgid;
	write_unlock_irqrestore(&table_lock, flags);

	table_push(t);
	return 0;
}

static int proc_control_close(struct inode *inode, struct file *file) {
	u_int32_t id;
	struct mediaproxy_table *t;
	unsigned long flags;

	id = (u_int32_t) (unsigned long) PDE_DATA(inode);
	t = get_table(id);
	if (!t)
		return 0;

	write_lock_irqsave(&table_lock, flags);
	t->pid = 0;
	write_unlock_irqrestore(&table_lock, flags);

	table_push(t);

	return 0;
}

static ssize_t proc_control_write(struct file *file, const char __user *buf, size_t buflen, loff_t *off) {
	struct inode *inode;
	u_int32_t id;
	struct mediaproxy_table *t;
	struct mediaproxy_message msg;
	int err;

	if (buflen != sizeof(msg))
		return -EIO;

	inode = file->f_path.dentry->d_inode;
	id = (u_int32_t) (unsigned long) PDE_DATA(inode);
	t = get_table(id);
	if (!t)
		return -ENOENT;

	err = -EFAULT;
	if (copy_from_user(&msg, buf, sizeof(msg)))
		goto err;

	switch (msg.cmd) {
		case MMG_NOOP:
			DBG("noop.\n");
			break;

		case MMG_ADD:
			err = table_new_target(t, &msg.target, 0);
			if (err)
				goto err;
			break;

		case MMG_DEL:
			err = table_del_target(t, msg.target.target_port);
			if (err)
				goto err;
			break;

		case MMG_UPDATE:
			err = table_new_target(t, &msg.target, 1);
			if (err)
				goto err;
			break;

		default:
			printk(KERN_WARNING "xt_MEDIAPROXY unimplemented op %u\n", msg.cmd);
			err = -EINVAL;
			goto err;
	}

	table_push(t);

	return buflen;

err:
	table_push(t);
	return err;
}





static int send_proxy_packet4(struct sk_buff *skb, struct mp_address *src, struct mp_address *dst, unsigned char tos) {
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
	if (ip_route_me_harder(skb, RTN_UNSPEC))
		goto drop;

	skb->ip_summed = CHECKSUM_NONE;

	ip_local_out(skb);

	return 0;

drop:
	kfree_skb(skb);
	return -1;
}





static int send_proxy_packet6(struct sk_buff *skb, struct mp_address *src, struct mp_address *dst, unsigned char tos) {
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
	if (ip6_route_me_harder(skb))
		goto drop;

	skb->ip_summed = CHECKSUM_NONE;

	ip6_local_out(skb);

	return 0;

drop:
	kfree_skb(skb);
	return -1;
}




static int send_proxy_packet(struct sk_buff *skb, struct mp_address *src, struct mp_address *dst, unsigned char tos) {
	if (src->family != dst->family)
		goto drop;

	switch (src->family) {
		case AF_INET:
			return send_proxy_packet4(skb, src, dst, tos);
			break;

		case AF_INET6:
			return send_proxy_packet6(skb, src, dst, tos);
			break;

		default:
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
	}

	DBG("rtp header parsed, payload length is %u\n", rtp->payload_len);

	rtp->ok = 1;
	return;

error:
	rtp->ok = 0;
}

/* XXX shared code */
static u_int64_t packet_index(struct mp_crypto_context *c,
		struct mediaproxy_srtp *s, struct rtp_header *rtp)
{
	u_int16_t seq;
	u_int64_t index;
	long long int diff;
	unsigned long flags;

	seq = ntohs(rtp->seq_num);

	spin_lock_irqsave(&c->lock, flags);

	/* rfc 3711 section 3.3.1 */
	if (unlikely(!s->last_index))
		s->last_index = seq;

	/* rfc 3711 appendix A, modified, and sections 3.3 and 3.3.1 */
	index = ((u_int64_t) c->roc << 16) | seq;
	diff = index - s->last_index;
	if (diff >= 0) {
		if (diff < 0x8000)
			s->last_index = index;
		else if (index >= 0x10000)
			index -= 0x10000;
	}
	else {
		if (diff >= -0x8000)
			;
		else {
			index += 0x10000;
			c->roc++;
			s->last_index = index;
		}
	}

	spin_unlock_irqrestore(&c->lock, flags);

	return index;
}

static int srtp_hash(unsigned char *hmac,
		struct mp_crypto_context *c,
		struct mediaproxy_srtp *s, struct rtp_parsed *r,
		u_int64_t pkt_idx)
{
	u_int32_t roc;
	struct shash_desc *dsc;

	if (!s->auth_tag_len)
		return 0;

	roc = htonl((pkt_idx & 0xffffffff0000ULL) >> 16);

	dsc = kmalloc(sizeof(*dsc) + crypto_shash_descsize(c->shash), GFP_ATOMIC);
	if (!dsc)
		return -1;

	dsc->tfm = c->shash;
	dsc->flags = 0;

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
static void rtp_append_mki(struct rtp_parsed *r, struct mediaproxy_srtp *c) {
	unsigned char *p;

	if (!c->mki_len)
		return;

	p = r->payload + r->payload_len;
	memcpy(p, c->mki, c->mki_len);
	r->payload_len += c->mki_len;
}

static int srtp_authenticate(struct mp_crypto_context *c,
		struct mediaproxy_srtp *s, struct rtp_parsed *r,
		u_int64_t pkt_idx)
{
	unsigned char hmac[20];

	if (!r->header)
		return 0;
	if (s->hmac == MPH_NULL)
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

static int srtp_auth_validate(struct mp_crypto_context *c,
		struct mediaproxy_srtp *s, struct rtp_parsed *r,
		u_int64_t pkt_idx)
{
	unsigned char *auth_tag;
	unsigned char hmac[20];

	if (s->hmac == MPH_NULL)
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

	if (memcmp(auth_tag, hmac, s->auth_tag_len))
		return -1;

	return 0;

}


/* XXX shared code */
static int srtp_encrypt_aes_cm(struct mp_crypto_context *c,
		struct mediaproxy_srtp *s, struct rtp_parsed *r,
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

	aes_ctr_128(r->payload, r->payload, r->payload_len, c->tfm[0], iv);

	return 0;
}

static int srtp_encrypt_aes_f8(struct mp_crypto_context *c,
		struct mediaproxy_srtp *s, struct rtp_parsed *r,
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


static inline int srtp_encrypt(struct mp_crypto_context *c,
		struct mediaproxy_srtp *s, struct rtp_parsed *r,
		u_int64_t pkt_idx)
{
	if (!r->header)
		return 0;
	if (!c->cipher->encrypt)
		return 0;
	return c->cipher->encrypt(c, s, r, pkt_idx);
}

static inline int srtp_decrypt(struct mp_crypto_context *c,
		struct mediaproxy_srtp *s, struct rtp_parsed *r,
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

static inline int is_dtls(struct rtp_parsed *r) {
	if (r->header->m_pt < 20)
		return 0;
	if (r->header->m_pt > 63)
		return 0;
	return 1;
}

static unsigned int mediaproxy46(struct sk_buff *skb, struct mediaproxy_table *t, struct mp_address *src) {
	struct udphdr *uh;
	struct mediaproxy_target *g;
	struct sk_buff *skb2;
	int err;
	unsigned int datalen;
	unsigned long flags;
	u_int32_t *u32;
	struct rtp_parsed rtp;
	u_int64_t pkt_idx = 0;

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

	g = get_target(t, ntohs(uh->dest));
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
	if ((u32[0] & htonl(0xb0000003UL))) /* zero bits required by rfc */
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
	err = -1;
	goto out;

src_check_ok:
	parse_rtp(&rtp, skb);
	if (!rtp.ok) {
		if (g->target.rtp_only)
			goto skip1;
		goto not_rtp;
	}
	if (g->target.rtcp_mux && is_muxed_rtcp(&rtp))
		goto skip1;
	if (g->target.dtls && is_dtls(&rtp))
		goto skip1;
	pkt_idx = packet_index(&g->decrypt, &g->target.decrypt, rtp.header);
	if (srtp_auth_validate(&g->decrypt, &g->target.decrypt, &rtp, pkt_idx))
		goto skip_error;
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
		skb2 = skb_copy(skb, GFP_ATOMIC);
		err = send_proxy_packet(skb2, &g->target.src_addr, &g->target.mirror_addr, g->target.tos);
		if (err) {
			spin_lock_irqsave(&g->stats_lock, flags);
			g->stats.errors++;
			spin_unlock_irqrestore(&g->stats_lock, flags);
		}
	}

	if (rtp.ok) {
		srtp_encrypt(&g->encrypt, &g->target.encrypt, &rtp, pkt_idx);
		skb_put(skb, g->target.encrypt.mki_len + g->target.encrypt.auth_tag_len);
		srtp_authenticate(&g->encrypt, &g->target.encrypt, &rtp, pkt_idx);
	}

	err = send_proxy_packet(skb, &g->target.src_addr, &g->target.dst_addr, g->target.tos);

out:
	spin_lock_irqsave(&g->stats_lock, flags);
	if (err)
		g->stats.errors++;
	else {
		g->stats.packets++;
		g->stats.bytes += skb->len;
	}
	spin_unlock_irqrestore(&g->stats_lock, flags);

	target_push(g);
	table_push(t);

	return NF_DROP;

skip_error:
	spin_lock_irqsave(&g->stats_lock, flags);
	g->stats.errors++;
	spin_unlock_irqrestore(&g->stats_lock, flags);
skip1:
	target_push(g);
skip2:
	kfree_skb(skb);
	table_push(t);
	return XT_CONTINUE;
}






#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
static unsigned int mediaproxy4(struct sk_buff *oskb, const struct xt_target_param *par) {
#else
static unsigned int mediaproxy4(struct sk_buff *oskb, const struct xt_action_param *par) {
#endif
	const struct xt_mediaproxy_info *pinfo = par->targinfo;
	struct sk_buff *skb;
	struct iphdr *ih;
	struct mediaproxy_table *t;
	struct mp_address src;

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
	src.family = AF_INET;
	src.u.ipv4 = ih->saddr;

	return mediaproxy46(skb, t, &src);

skip2:
	kfree_skb(skb);
skip3:
	table_push(t);
skip:
	return XT_CONTINUE;
}




#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
static unsigned int mediaproxy6(struct sk_buff *oskb, const struct xt_target_param *par) {
#else
static unsigned int mediaproxy6(struct sk_buff *oskb, const struct xt_action_param *par) {
#endif
	const struct xt_mediaproxy_info *pinfo = par->targinfo;
	struct sk_buff *skb;
	struct ipv6hdr *ih;
	struct mediaproxy_table *t;
	struct mp_address src;

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
	src.family = AF_INET6;
	memcpy(&src.u.ipv6, &ih->saddr, sizeof(src.u.ipv6));

	return mediaproxy46(skb, t, &src);

skip2:
	kfree_skb(skb);
skip3:
	table_push(t);
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
	const struct xt_mediaproxy_info *pinfo = par->targinfo;

	if (!my_proc_root) {
		printk(KERN_WARNING "xt_MEDIAPROXY check() without proc_root\n");
		return CHECK_ERR;
	}
	if (pinfo->id >= MAX_ID) {
		printk(KERN_WARNING "xt_MEDIAPROXY ID too high (%u >= %u)\n", pinfo->id, MAX_ID);
		return CHECK_ERR;
	}

	return CHECK_SCC;
}




static struct xt_target xt_mediaproxy_regs[] = {
	{
		.name		= "MEDIAPROXY",
		.family		= NFPROTO_IPV4,
		.target		= mediaproxy4,
		.targetsize	= sizeof(struct xt_mediaproxy_info),
		.table		= "filter",
		.hooks		= (1 << NF_INET_LOCAL_IN),
		.checkentry	= check,
		.me		= THIS_MODULE,
	},
	{
		.name		= "MEDIAPROXY",
		.family		= NFPROTO_IPV6,
		.target		= mediaproxy6,
		.targetsize	= sizeof(struct xt_mediaproxy_info),
		.table		= "filter",
		.hooks		= (1 << NF_INET_LOCAL_IN),
		.checkentry	= check,
		.me		= THIS_MODULE,
	},
};

static int __init init(void) {
	int ret;
	const char *err;

	printk(KERN_NOTICE "Registering xt_MEDIAPROXY module - version %s\n", MEDIAPROXY_VERSION);

	rwlock_init(&table_lock);

	ret = -ENOMEM;
	err = "could not register /proc/ entries";
	my_proc_root = proc_mkdir("mediaproxy", NULL);
	if (!my_proc_root)
		goto fail;
	/* my_proc_root->owner = THIS_MODULE; */

	proc_control = proc_create("control", S_IFREG | S_IWUSR | S_IWGRP, my_proc_root,
			&proc_main_control_ops);
	if (!proc_control)
		goto fail;

	proc_list = proc_create("list", S_IFREG | S_IRUGO, my_proc_root, &proc_main_list_ops);
	if (!proc_list)
		goto fail;

	err = "could not register xtables target";
	ret = xt_register_targets(xt_mediaproxy_regs, ARRAY_SIZE(xt_mediaproxy_regs));
	if (ret)
		goto fail;

	return 0;

fail:
	clear_proc(&proc_control);
	clear_proc(&proc_list);
	clear_proc(&my_proc_root);

	printk(KERN_ERR "Failed to load xt_MEDIAPROXY module: %s\n", err);

	return ret;
}

static void __exit fini(void) {
	printk(KERN_NOTICE "Unregistering xt_MEDIAPROXY module\n");
	xt_unregister_targets(xt_mediaproxy_regs, ARRAY_SIZE(xt_mediaproxy_regs));

	clear_proc(&proc_control);
	clear_proc(&proc_list);
	clear_proc(&my_proc_root);
}

module_init(init);
module_exit(fini);
