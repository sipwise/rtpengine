#include "kernel.h"

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <glib.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/eventfd.h>

#include "helpers.h"
#include "log.h"
#include "bufferpool.h"
#include "main.h"
#include "statistics.h"
#include "uring.h"

#include "nft_rtpengine.h"

#define PREFIX "/proc/rtpengine"

struct kernel_interface kernel;

static bool kernel_action_table(const char *action, unsigned int id) {
	char s[64];
	int saved_errno;
	int fd;
	int i;
	ssize_t ret;

	fd = open(PREFIX "/control", O_WRONLY | O_TRUNC);
	if (fd == -1)
		return false;
	i = snprintf(s, sizeof(s), "%s %u\n", action, id);
	if (i >= sizeof(s))
		goto fail;
	ret = write(fd, s, strlen(s));
	if (ret == -1)
		goto fail;
	close(fd);

	return true;

fail:
	saved_errno = errno;
	close(fd);
	errno = saved_errno;
	return false;
}

static bool kernel_create_table(unsigned int id) {
	return kernel_action_table("add", id);
}

static bool kernel_delete_table(unsigned int id) {
	return kernel_action_table("del", id);
}

static void kernel_pin_memory(void *b, size_t len) {
	struct rtpengine_command_pin_memory pmc = {
		.cmd = REMG_PIN_MEMORY,
		.pin_memory = {
			.addr = b,
			.size = len,
		},
	};

	ssize_t ret = write(kernel.fd, &pmc, sizeof(pmc));
	if (ret != sizeof(pmc)) {
		ilog(LOG_CRIT, "Failed to pin shared kernel memory: %s", strerror(errno));
		abort();
	}
}

static void *kernel_alloc(void) {
	// Since we can't really request memory at a specific location that we know
	// will be correctly aligned, request twice as much, which we know must be
	// enough to contain at least one correctly aligned block. This may seem like
	// a waste, but the extra pages won't ever be used, and so usually won't even
	// be mapped.
	void *b = mmap(NULL, BUFFERPOOL_SHARD_SIZE * 2, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, 0, 0);

	if (b == NULL || b == MAP_FAILED) {
		ilog(LOG_CRIT, "Failed to allocate shared kernel memory: %s", strerror(errno));
		abort();
	}

	// find the aligned block
	void *aligned = (void *) (((intptr_t) b + BUFFERPOOL_SHARD_SIZE - 1) & BUFFERPOOL_TOP_MASK);

	// place a pointer to the real beginning of the block just past the end, so we
	// know what to free
	void **back_ptr = aligned + BUFFERPOOL_SHARD_SIZE;
	// make sure there is enough extra space to store our back pointer (there should be, unless
	// our page size is really tiny)
	assert((void *) back_ptr + sizeof(void *) < b + BUFFERPOOL_SHARD_SIZE * 2);

	*back_ptr = b;

	// register it with the kernel
	kernel_pin_memory(aligned, BUFFERPOOL_SHARD_SIZE);

	return aligned;
}
static void kernel_free(void *p) {
	// restore saved pointer to read beginning of the block
	void **back_ptr = p + BUFFERPOOL_SHARD_SIZE;
	p = *back_ptr;
	munmap(p, BUFFERPOOL_SHARD_SIZE * 2);
}

static int kernel_open_table(unsigned int id) {
	char s[64];
	int fd;

	sprintf(s, PREFIX "/%u/control", id);
	fd = open(s, O_RDWR | O_TRUNC);
	if (fd == -1)
		return -1;

	return fd;
}

bool kernel_init_table(void) {
	if (!kernel.is_open)
		return true;

	ssize_t ret;

	struct rtpengine_command_init cmd = {
		.cmd = REMG_INIT,
		.init = {
			.last_cmd = __REMG_LAST,
			.msg_size = {
				[REMG_INIT] = sizeof(struct rtpengine_command_init),
				[REMG_ADD_TARGET] = sizeof(struct rtpengine_command_add_target),
				[REMG_DEL_TARGET] = sizeof(struct rtpengine_command_del_target),
				[REMG_ADD_DESTINATION] = sizeof(struct rtpengine_command_destination),
				[REMG_ADD_CALL] = sizeof(struct rtpengine_command_add_call),
				[REMG_DEL_CALL] = sizeof(struct rtpengine_command_del_call),
				[REMG_ADD_STREAM] = sizeof(struct rtpengine_command_add_stream),
				[REMG_DEL_STREAM] = sizeof(struct rtpengine_command_del_stream),
				[REMG_PACKET] = sizeof(struct rtpengine_command_packet),
				[REMG_INIT_PLAY_STREAMS] = sizeof(struct rtpengine_command_init_play_streams),
				[REMG_GET_PACKET_STREAM] = sizeof(struct rtpengine_command_get_packet_stream),
				[REMG_PLAY_STREAM_PACKET] = sizeof(struct rtpengine_command_play_stream_packet),
				[REMG_PLAY_STREAM] = sizeof(struct rtpengine_command_play_stream),
				[REMG_STOP_STREAM] = sizeof(struct rtpengine_command_stop_stream),
				[REMG_FREE_PACKET_STREAM] = sizeof(struct rtpengine_command_free_packet_stream),
				[REMG_PIN_MEMORY] = sizeof(struct rtpengine_command_pin_memory),
				[REMG_RING_BUFFER] = sizeof(struct rtpengine_command_ring_buf),
			},
			.rtpe_stats = rtpe_stats,
		},
	};

	ret = write(kernel.fd, &cmd, sizeof(cmd));
	if (ret <= 0)
		return false;

	return true;
}

bool kernel_setup_table(unsigned int id) {
	if (kernel.is_wanted)
		abort();

	kernel.is_wanted = true;

	if (!kernel_delete_table(id) && errno != ENOENT) {
		ilog(LOG_ERR, "FAILED TO DELETE KERNEL TABLE %i (%s), KERNEL FORWARDING DISABLED",
				id, strerror(errno));
		return false;
	}
	if (!kernel_create_table(id)) {
		ilog(LOG_ERR, "FAILED TO CREATE KERNEL TABLE %i (%s), KERNEL FORWARDING DISABLED",
				id, strerror(errno));
		return false;
	}
	int fd = kernel_open_table(id);
	if (fd == -1) {
		ilog(LOG_ERR, "FAILED TO OPEN KERNEL TABLE %i (%s), KERNEL FORWARDING DISABLED",
				id, strerror(errno));
		return false;
	}

	kernel.fd = fd;
	kernel.table = id;
	kernel.is_open = true;

	shm_bufferpool = bufferpool_new(kernel_alloc, kernel_free);
	static_bufferpool = bufferpool_new(kernel_alloc, kernel_free);

	return true;
}

void *kernel_shm_alloc(size_t s) {
	return bufferpool_alloc(shm_bufferpool, s);
}
void *kernel_shm_alloc0(size_t s) {
	return bufferpool_alloc0(shm_bufferpool, s);
}

void kernel_shutdown_table(void) {
	if (!kernel.is_open)
		return;
	// ignore errors
	close(kernel.fd);
	kernel_delete_table(kernel.table);
}


bool kernel_add_stream(struct rtpengine_command_add_target *cmd) {
	ssize_t ret;

	if (!kernel.is_open)
		return false;

	cmd->cmd = REMG_ADD_TARGET;

	ret = write(kernel.fd, cmd, sizeof(*cmd));
	if (ret == sizeof(*cmd))
		return true;

	ilog(LOG_ERROR, "Failed to push relay stream to kernel: %s", strerror(errno));
	return false;
}

void kernel_add_destination(struct rtpengine_command_destination *cmd) {
	ssize_t ret;

	if (!kernel.is_open)
		return;

	cmd->cmd = REMG_ADD_DESTINATION;

	ret = write(kernel.fd, cmd, sizeof(*cmd));
	if (ret == sizeof(*cmd))
		return;

	ilog(LOG_ERROR, "Failed to push relay stream destination to kernel: %s", strerror(errno));
}


bool kernel_del_stream(struct rtpengine_command_del_target *cmd) {
	ssize_t ret;

	if (!kernel.is_open)
		return false;

	cmd->cmd = REMG_DEL_TARGET;

	ret = write(kernel.fd, cmd, sizeof(*cmd));
	if (ret == sizeof(*cmd))
		return true;

	ilog(LOG_ERROR, "Failed to delete relay stream from kernel: %s", strerror(errno));
	return false;
}

unsigned int kernel_add_call(const char *id) {
	ssize_t ret;

	if (!kernel.is_open)
		return UNINIT_IDX;

	struct rtpengine_command_add_call cmd = {
		.cmd = REMG_ADD_CALL,
	};
	snprintf(cmd.call.call_id, sizeof(cmd.call.call_id), "%s", id);

	ret = read(kernel.fd, &cmd, sizeof(cmd));
	if (ret != sizeof(cmd))
		return UNINIT_IDX;
	return cmd.call.call_idx;
}

void kernel_del_call(unsigned int idx) {
	ssize_t ret;

	if (!kernel.is_open)
		return;

	struct rtpengine_command_del_call cmd = {
		.cmd = REMG_DEL_CALL,
		.call_idx = idx,
	};

	ret = write(kernel.fd, &cmd, sizeof(cmd));
	if (ret == sizeof(cmd))
		return;

	ilog(LOG_ERROR, "Failed to delete intercept call from kernel: %s", strerror(errno));
}

unsigned int kernel_add_intercept_stream(unsigned int call_idx, const char *id) {
	ssize_t ret;

	if (!kernel.is_open)
		return UNINIT_IDX;

	struct rtpengine_command_add_stream cmd = {
		.cmd = REMG_ADD_STREAM,
		.stream.idx.call_idx = call_idx,
	};
	snprintf(cmd.stream.stream_name, sizeof(cmd.stream.stream_name), "%s", id);

	ret = read(kernel.fd, &cmd, sizeof(cmd));
	if (ret != sizeof(cmd))
		return UNINIT_IDX;
	return cmd.stream.idx.stream_idx;
}

bool kernel_init_player(int num_media, int num_sessions) {
	if (num_media <= 0 || num_sessions <= 0)
		return false;
	if (!kernel.is_open)
		return false;

	struct rtpengine_command_init_play_streams ips = {
		.cmd = REMG_INIT_PLAY_STREAMS,
		.num_packet_streams = num_media,
		.num_play_streams = num_sessions,
	};
	ssize_t ret = write(kernel.fd, &ips, sizeof(ips));
	if (ret != sizeof(ips))
		return false;

	kernel.use_player = true;

	return true;
}

unsigned int kernel_get_packet_stream(void) {
	if (!kernel.use_player)
		return -1;

	struct rtpengine_command_get_packet_stream gps = { .cmd = REMG_GET_PACKET_STREAM };
	ssize_t ret = read(kernel.fd, &gps, sizeof(gps));
	if (ret != sizeof(gps))
		return -1;
	return gps.packet_stream_idx;
}

bool kernel_add_stream_packet(unsigned int idx, const char *buf, size_t len, unsigned long delay_ms,
		uint32_t ts, uint32_t dur)
{
	if (!kernel.use_player)
		return false;

	size_t total_len = len + sizeof(struct rtpengine_command_play_stream_packet);
	struct rtpengine_command_play_stream_packet *cmd = alloca(total_len);

	*cmd = (__typeof__(*cmd)) {
		.cmd = REMG_PLAY_STREAM_PACKET,
		.play_stream_packet.packet_stream_idx = idx,
		.play_stream_packet.delay_ms = delay_ms,
		.play_stream_packet.delay_ts = ts,
		.play_stream_packet.duration_ts = dur,
	};

	memcpy(&cmd->play_stream_packet.data, buf, len);

	ssize_t ret = write(kernel.fd, cmd, total_len);
	if (ret != total_len)
		return false;
	return true;
}

unsigned int kernel_start_stream_player(struct rtpengine_play_stream_info *info) {
	if (!kernel.use_player)
		return -1;

	struct rtpengine_command_play_stream ps = {
		.cmd = REMG_PLAY_STREAM,
		.info = *info,
	};
	ssize_t ret = read(kernel.fd, &ps, sizeof(ps));
	if (ret == sizeof(ps))
		return ps.play_idx;
	return -1;
}

bool kernel_stop_stream_player(unsigned int idx) {
	if (!kernel.use_player)
		return false;

	struct rtpengine_command_stop_stream ss = {
		.cmd = REMG_STOP_STREAM,
		.play_idx = idx,
	};
	ssize_t ret = write(kernel.fd, &ss, sizeof(ss));
	if (ret == sizeof(ss))
		return true;
	return false;
}

bool kernel_free_packet_stream(unsigned int idx) {
	if (!kernel.use_player)
		return false;

	struct rtpengine_command_free_packet_stream fps = {
		.cmd = REMG_FREE_PACKET_STREAM,
		.packet_stream_idx = idx,
	};
	ssize_t ret = write(kernel.fd, &fps, sizeof(fps));
	if (ret == sizeof(fps))
		return true;
	return false;
}


static unsigned int ring_buffer_idx; // single threaded manipulation only


unsigned int kernel_poller_start_idx;
unsigned int kernel_pollers_num;

unsigned int kernel_sender_start_idx;
unsigned int kernel_senders_num;
unsigned int kernel_sender_cur_idx;

static const size_t rtp_buffer_size_per_slot = RTP_BUFFER_SIZE;
static size_t rtp_buffer_size_per_ring;

struct kernel_ring_buf *kernel_ring_bufs;
struct poller_thread *kernel_poller_threads;


#define POW2_ROUND(x, y) (((x) + (y) - 1) & ~((y) - 1))
#define ALIGN(x) POW2_ROUND(x, 8)

void kernel_init_pollers(unsigned int num) {
	if (!num)
		return;

	// how much memory do we need?
	size_t buf_size = 0;
	// RTP buffer itself
	rtp_buffer_size_per_ring = ALIGN(rtpe_config.kernel_slots * rtp_buffer_size_per_slot);
	buf_size += rtp_buffer_size_per_ring * 2;
	// slot entries
	size_t slot_size_per_ring = ALIGN(rtpe_config.kernel_slots * sizeof(struct rtpengine_buf_slot));
	buf_size += slot_size_per_ring * 2;
	// metadata
	size_t metadata_size_per_ring = ALIGN(rtpe_config.kernel_slots * sizeof(struct rtpengine_buf_metadata));
	buf_size += metadata_size_per_ring * 2;
	// tracker
	buf_size += ALIGN(sizeof(struct rtpengine_ring_buf_shm)) * 2;
	// 0/1 index
	buf_size += ALIGN(sizeof(atomic_t));

	buf_size *= num + num; // pollers + senders

	// round up to page size
	long page_size = sysconf(_SC_PAGESIZE);
	if (page_size <= 0) {
		ilog(LOG_CRIT, "Unknown page size (%s)", strerror(errno));
		abort();
	}

	buf_size = POW2_ROUND(buf_size, page_size);

	// allocate and pin
	void *b = mmap(NULL, buf_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, 0, 0);
	if (b == NULL || b == MAP_FAILED) {
		ilog(LOG_CRIT, "Failed to mmap memory for kernel pollers: %s", strerror(errno));
		abort();
	}

	kernel_pin_memory(b, buf_size);

	// create objects
	kernel_ring_bufs = g_new0(struct kernel_ring_buf, num + num); // pollers + senders
	kernel_pollers_num = num;
	kernel_senders_num = num;
	kernel_poller_threads = g_new0(__typeof(*kernel_poller_threads), num);

	// register buffers
	void *buf_head = b;
	kernel_sender_start_idx = ring_buffer_idx;
	kernel_poller_start_idx = ring_buffer_idx + num;

	for (unsigned int i = 0; i < num + num; i++) {
		unsigned int ring_idx = ring_buffer_idx++;

		struct kernel_ring_buf *kbuf = &kernel_ring_bufs[i];

		kbuf->eventfd = eventfd(0, 0);
		if (kbuf->eventfd == -1) {
			ilog(LOG_CRIT, "Failed to create eventfd: %s", strerror(errno));
			abort();
		}

		kbuf->buf[0] = buf_head;
		buf_head += rtp_buffer_size_per_ring;
		kbuf->buf[1] = buf_head;
		buf_head += rtp_buffer_size_per_ring;

		kbuf->slots[0] = buf_head;
		buf_head += slot_size_per_ring;
		kbuf->slots[1] = buf_head;
		buf_head += slot_size_per_ring;

		kbuf->metadata[0] = buf_head;
		buf_head += metadata_size_per_ring;
		kbuf->metadata[1] = buf_head;
		buf_head += metadata_size_per_ring;

		kbuf->shm[0] = buf_head;
		buf_head += ALIGN(sizeof(struct rtpengine_ring_buf_shm));
		kbuf->shm[1] = buf_head;
		buf_head += ALIGN(sizeof(struct rtpengine_ring_buf_shm));

		kbuf->buf_idx = buf_head;
		buf_head += ALIGN(sizeof(atomic_t));

		atomic_set_na(kbuf->buf_idx, 0);

		struct rtpengine_command_ring_buf rbc = {
			.cmd = REMG_RING_BUFFER,
			.buf = {
				.idx = ring_idx,
				.num_steps = 1,
				.sizes[0] = rtp_buffer_size_per_ring,
				.num_slots = rtpe_config.kernel_slots,
				.buf = {
					{
						.head = kbuf->buf[0],
						.slots = kbuf->slots[0],
						.metadata = kbuf->metadata[0],
						.shm = kbuf->shm[0],
					},
					{
						.head = kbuf->buf[1],
						.slots = kbuf->slots[1],
						.metadata = kbuf->metadata[1],
						.shm = kbuf->shm[1],
					},
				},
				.buf_idx = kbuf->buf_idx,
				.run_now_event = kbuf->eventfd,
				.writers_done_event = -1,
			},
		};

		if (i < num)
			rbc.buf.sender = true;

		ssize_t ret = write(kernel.fd, &rbc, sizeof(rbc));
		if (ret != sizeof(rbc)) {
			ilog(LOG_CRIT, "Failed to register ring buffer: %s", strerror(errno));
			abort();
		}
	}
}

static void wake_eventfd(struct thread_waker *wk) {
	int64_t a = 1;
	(void) write(GPOINTER_TO_INT(wk->arg), &a, sizeof(a));
}

static void wait_eventfd(int fd) {
	while (true) {
		int64_t evs;
		int ret = read(fd, &evs, sizeof(evs));
		if (ret != sizeof(evs))
			continue;
		return;
	}
}

void kernel_poller_loop(void *pidx) {
	unsigned int idx = GPOINTER_TO_UINT(pidx);
	assert(idx < kernel_pollers_num);
	unsigned int bidx = idx + kernel_poller_start_idx;
	assert(bidx < kernel_poller_start_idx + kernel_pollers_num);

	struct kernel_ring_buf *p = &kernel_ring_bufs[bidx];
	struct poller_thread *pt = &kernel_poller_threads[idx];

	pt->pid = gettid();
	int e = p->eventfd;

	struct thread_waker waker = { .func = wake_eventfd, .arg = GINT_TO_POINTER(e) };
	thread_waker_add_generic(&waker);

	unsigned int buf_idx = 0;

	while (!rtpe_shutdown) {
		void *buf = p->buf[buf_idx];
		struct rtpengine_ring_buf_shm *shm = p->shm[buf_idx];
		struct rtpengine_buf_slot *slots = p->slots[buf_idx];
		struct rtpengine_buf_metadata *metadata = p->metadata[buf_idx];

		unsigned int num_slots = atomic_get_na(&shm->slots_filled);
		if (!num_slots)
			wait_eventfd(e);

		rtpe_now = now_us();

		atomic64_inc_na(&pt->wakeups);

		// register as reader
		atomic_inc(&shm->readers);

		// switch 0/1 buffer to alternate
		buf_idx = buf_idx ^ 1;
		atomic_set_na(p->buf_idx, buf_idx);

		// wait until there are no more writers
		while (atomic_get(&shm->writers))
			wait_eventfd(e);

		num_slots = atomic_get_na(&shm->slots_filled);
		atomic64_add_na(&pt->items, num_slots);

		for (unsigned int s = 0; s < num_slots; s++) {
			struct rtpengine_buf_slot *slot = &slots[s];
			struct rtpengine_buf_metadata *metaslot = &metadata[s];

			stream_fd_kernel_input(metaslot->opaque, buf + slot->steps[0].offset,
					slot->steps[0].length,
					&metaslot->src, &metaslot->dst, metaslot->ts);
		}

		// reset
		atomic_set_na(&shm->slots_filled, 0);
		atomic64_set_na(&shm->filled[0], 0);

		atomic_dec(&shm->readers);
	}

	thread_waker_del(&waker);
}

void kernel_cleanup_pollers(void) {
	for (unsigned int i = 0; i < kernel_pollers_num + kernel_senders_num; i++)
		close(kernel_ring_bufs[i].eventfd);

	g_free(kernel_ring_bufs);
	g_free(kernel_poller_threads);
}

void kernel_thread_init(void) {
	if (!kernel_senders_num)
		return;
	uring_methods.sendmsg = kernel_sendmsg;
}

ssize_t kernel_sendmsg(socket_t *s, struct msghdr *msg, const endpoint_t *dst,
			struct sockaddr_storage *ss, struct uring_req *req)
{
	size_t skblen = 0;
	for (size_t i = 0; i < msg->msg_iovlen; i++)
		skblen += msg->msg_iov[i].iov_len;

	unsigned int cur_idx = atomic_get_na(&kernel_sender_cur_idx);

	struct kernel_ring_buf *p = NULL;
	void *buf;
	struct rtpengine_ring_buf_shm *shm;
	struct rtpengine_buf_slot *slots;
	struct rtpengine_buf_metadata *metadata;

	for (unsigned int iter = 0; iter < kernel_senders_num; iter++) {
		unsigned int idx = (iter + cur_idx) % kernel_senders_num + kernel_sender_start_idx;
		struct kernel_ring_buf *pp = &kernel_ring_bufs[idx];

		int buf_idx = atomic_get_na(pp->buf_idx);
		if (buf_idx != 0 && buf_idx != 1) {
			atomic_inc(&pp->errors);
			req->handler(req, 0, 0);
			return -1;
		}

		buf = pp->buf[buf_idx];
		shm = pp->shm[buf_idx];
		slots = pp->slots[buf_idx];
		metadata = pp->metadata[buf_idx];

		if (atomic_get_na(&shm->readers)) {
			atomic_inc(&pp->read_preempt);
			continue;
		}

		atomic_inc(&shm->writers);
		if (atomic_get_na(&shm->readers)) {
			atomic_inc(&pp->write_preempt);
			atomic_add_na(&shm->writers, -1);
			continue;
		}

		p = pp;
		atomic_set(&kernel_sender_cur_idx, idx);
		break;
	}

	if (!p)
		return -1;

	unsigned int slot_idx = atomic_inc(&shm->slots_filled);
	if (slot_idx >= rtpe_config.kernel_slots) {
		atomic_inc(&p->slots_full);
		atomic_add_na(&shm->slots_filled, -1);
		atomic_dec(&shm->writers);
		req->handler(req, 0, 0);
		return -1;
	}

	struct rtpengine_buf_slot *slot = &slots[slot_idx];
	struct rtpengine_buf_metadata *metaslot = &metadata[slot_idx];

	size_t fill = atomic64_add(&shm->filled[0], skblen);
	if (fill >= rtp_buffer_size_per_ring) {
		atomic_inc(&p->buf_full);
		atomic_add_na(&shm->slots_filled, -1);
		atomic_dec(&shm->writers);
		req->handler(req, 0, 0);
		return -1;
	}

	slot->steps[0].offset = fill;
	slot->steps[0].length = skblen;

	dst->address.family->endpoint2kernel(&metaslot->dst, dst);
	s->local.address.family->endpoint2kernel(&metaslot->src, &s->local);
	metaslot->tos = s->tos;

	buf += fill;
	for (size_t i = 0; i < msg->msg_iovlen; i++) {
		memcpy(buf, msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len);
		buf += msg->msg_iov[i].iov_len;
	}

	int writers = atomic_dec(&shm->writers) - 1;

	if (writers == 0) {
		int64_t one = 1;
		ssize_t ret = write(p->eventfd, &one, sizeof(one));
		assert(ret == sizeof(one));
	}

	req->handler(req, 0, 0);

	return skblen;
}
