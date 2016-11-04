#include "recording.h"
#include <stdio.h>
#include <stdlib.h>
#include <glib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <time.h>
#include <pcap.h>
#include <inttypes.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <stdarg.h>

#include "xt_RTPENGINE.h"

#include "call.h"
#include "kernel.h"
#include "bencode.h"



static int check_main_spool_dir(const char *spoolpath);
static char *recording_setup_file(struct recording *recording);
static char *meta_setup_file(struct recording *recording);

// pcap methods
static int pcap_create_spool_dir(const char *dirpath);
static void pcap_init(struct call *);
static void sdp_after_pcap(struct recording *, struct iovec *sdp_iov, int iovcnt,
		       unsigned int str_len, struct call_monologue *, enum call_opmode opmode);
static void dump_packet_pcap(struct recording *recording, struct packet_stream *sink, const str *s);
static void finish_pcap(struct call *);
static void response_pcap(struct recording *, bencode_item_t *);

// proc methods
static void proc_init(struct call *);
static void sdp_before_proc(struct recording *, const str *, struct call_monologue *, enum call_opmode);
static void sdp_after_proc(struct recording *, struct iovec *sdp_iov, int iovcnt,
		       unsigned int str_len, struct call_monologue *, enum call_opmode opmode);
static void meta_chunk_proc(struct recording *, const char *, const str *);
static void finish_proc(struct call *);
static void dump_packet_proc(struct recording *recording, struct packet_stream *sink, const str *s);
static void init_stream_proc(struct packet_stream *);
static void setup_stream_proc(struct packet_stream *);
static void kernel_info_proc(struct packet_stream *, struct rtpengine_target_info *);



static const struct recording_method methods[] = {
	{
		.name = "pcap",
		.kernel_support = 0,
		.create_spool_dir = pcap_create_spool_dir,
		.init_struct = pcap_init,
		.sdp_after = sdp_after_pcap,
		.dump_packet = dump_packet_pcap,
		.finish = finish_pcap,
		.response = response_pcap,
	},
	{
		.name = "proc",
		.kernel_support = 1,
		.create_spool_dir = check_main_spool_dir,
		.init_struct = proc_init,
		.sdp_before = sdp_before_proc,
		.sdp_after = sdp_after_proc,
		.meta_chunk = meta_chunk_proc,
		.dump_packet = dump_packet_proc,
		.finish = finish_proc,
		.init_stream_struct = init_stream_proc,
		.setup_stream = setup_stream_proc,
		.stream_kernel_info = kernel_info_proc,
	},
};


// Global file reference to the spool directory.
static char *spooldir = NULL;

const struct recording_method *selected_recording_method;




/**
 * Initialize RTP Engine filesystem settings and structure.
 * Check for or create the RTP Engine spool directory.
 */
void recording_fs_init(const char *spoolpath, const char *method_str) {
	int i;

	// Whether or not to fail if the spool directory does not exist.
	if (spoolpath == NULL || spoolpath[0] == '\0')
		return;

	for (i = 0; i < G_N_ELEMENTS(methods); i++) {
		if (!strcmp(methods[i].name, method_str)) {
			selected_recording_method = &methods[i];
			goto found;
		}
	}

	ilog(LOG_ERROR, "Recording method '%s' not supported", method_str);
	return;

found:
	spooldir = strdup(spoolpath);

	int path_len = strlen(spooldir);
	// Get rid of trailing "/" if it exists. Other code adds that in when needed.
	if (spooldir[path_len-1] == '/') {
		spooldir[path_len-1] = '\0';
	}
	if (!_rm_ret(create_spool_dir, spooldir)) {
		ilog(LOG_ERR, "Error while setting up spool directory \"%s\".", spooldir);
		ilog(LOG_ERR, "Please run `mkdir %s` and start rtpengine again.", spooldir);
		exit(-1);
	}
}

static int check_create_dir(const char *dir, const char *desc, int creat) {
	struct stat info;

	if (stat(dir, &info) != 0) {
		if (!creat) {
			ilog(LOG_WARN, "%s directory \"%s\" does not exist.", desc, dir);
			return FALSE;
		}
		ilog(LOG_INFO, "Creating %s directory \"%s\".", desc, dir);
		if (mkdir(dir, 0777) == 0)
			return TRUE;
		ilog(LOG_ERR, "Failed to create %s directory \"%s\": %s", desc, dir, strerror(errno));
		return FALSE;
	}
	if(!S_ISDIR(info.st_mode)) {
		ilog(LOG_ERR, "%s file exists, but \"%s\" is not a directory.", desc, dir);
		return FALSE;
	}
	return TRUE;
}

static int check_main_spool_dir(const char *spoolpath) {
	return check_create_dir(spoolpath, "spool", 0);
}

/**
 * Sets up the spool directory for RTP Engine.
 * If the directory does not exist, return FALSE.
 * If the directory exists, but "$spoolpath/metadata" or "$spoolpath/pcaps"
 * exist as non-directory files, return FALSE.
 * Otherwise, return TRUE.
 *
 * Create the "metadata" and "pcaps" directories if they are not there.
 */
static int pcap_create_spool_dir(const char *spoolpath) {
	int spool_good = TRUE;

	if (!check_main_spool_dir(spoolpath))
		return FALSE;

	// Spool directory exists. Make sure it has inner directories.
	int path_len = strlen(spoolpath);
	char meta_path[path_len + 10];
	char rec_path[path_len + 7];
	char tmp_path[path_len + 5];
	snprintf(meta_path, sizeof(meta_path), "%s/metadata", spoolpath);
	snprintf(rec_path, sizeof(rec_path), "%s/pcaps", spoolpath);
	snprintf(tmp_path, sizeof(tmp_path), "%s/tmp", spoolpath);

	if (!check_create_dir(meta_path, "metadata", 1))
		spool_good = FALSE;
	if (!check_create_dir(rec_path, "pcaps", 1))
		spool_good = FALSE;
	if (!check_create_dir(tmp_path, "tmp", 1))
		spool_good = FALSE;

	return spool_good;
}

// lock must be held
void recording_start(struct call *call, const char *prefix) {
	if (call->recording) // already active
		return;

	if (!spooldir) {
		ilog(LOG_ERR, "Call recording requested, but no spool directory configured");
		return;
	}
	ilog(LOG_NOTICE, "Turning on call recording.");

	call->recording = g_slice_alloc0(sizeof(struct recording));
	struct recording *recording = call->recording;
	recording->escaped_callid = g_uri_escape_string(call->callid.s, NULL, 0);
	if (!prefix) {
		const int rand_bytes = 8;
		char rand_str[rand_bytes * 2 + 1];
		rand_hex_str(rand_str, rand_bytes);
		if (asprintf(&recording->meta_prefix, "%s-%s", recording->escaped_callid, rand_str) < 0)
			abort();
	}
	else
		recording->meta_prefix = strdup(prefix);

	_rm(init_struct, call);

	// if recording has been turned on after initial call setup, we must walk
	// through all related objects and initialize the recording stuff. if this
	// function is called right at the start of the call, all of the following
	// is essentially a no-op
	GList *l;
	for (l = call->streams.head; l; l = l->next) {
		struct packet_stream *ps = l->data;
		recording_setup_stream(ps);
		__unkernelize(ps);
		ps->handler = NULL;
	}
}
void recording_stop(struct call *call) {
	if (!call->recording)
		return;

	ilog(LOG_NOTICE, "Turning off call recording.");
	recording_finish(call);
}

/**
 *
 * Controls the setting of recording variables on a `struct call *`.
 * Sets the `record_call` value on the `struct call`, initializing the
 * recording struct if necessary.
 * If we do not yet have a PCAP file associated with the call, create it
 * and write its file URL to the metadata file.
 *
 * Returns a boolean for whether or not the call is being recorded.
 */
void detect_setup_recording(struct call *call, const str *recordcall) {
	if (!recordcall || !recordcall->s)
		return;

	if (!str_cmp(recordcall, "yes") || !str_cmp(recordcall, "on"))
		recording_start(call, NULL);
	else if (!str_cmp(recordcall, "no") || !str_cmp(recordcall, "off"))
		recording_stop(call);
	else
		ilog(LOG_INFO, "\"record-call\" flag "STR_FORMAT" is invalid flag.", STR_FMT(recordcall));
}

static void pcap_init(struct call *call) {
	struct recording *recording = call->recording;

	// Wireshark starts at packet index 1, so we start there, too
	recording->pcap.packet_num = 1;
	mutex_init(&recording->pcap.recording_lock);
	meta_setup_file(recording);

	// set up pcap file
	char *pcap_path = recording_setup_file(recording);
	if (pcap_path != NULL && recording->pcap.recording_pdumper != NULL
	    && recording->pcap.meta_fp) {
		// Write the location of the PCAP file to the metadata file
		fprintf(recording->pcap.meta_fp, "%s\n\n", pcap_path);
	}
}

static char *file_path_str(const char *id, const char *prefix, const char *suffix) {
	char *ret;
	if (asprintf(&ret, "%s%s%s%s", spooldir, prefix, id, suffix) < 0)
		abort();
	return ret;
}

/**
 * Create a call metadata file in a temporary location.
 * Attaches the filepath and the file pointer to the call struct.
 */
static char *meta_setup_file(struct recording *recording) {
	if (spooldir == NULL) {
		// No spool directory was created, so we cannot have metadata files.
		return NULL;
	}

	char *meta_filepath = file_path_str(recording->meta_prefix, "/tmp/rtpengine-meta-", ".tmp");
	recording->meta_filepath = meta_filepath;
	FILE *mfp = fopen(meta_filepath, "w");
	chmod(meta_filepath, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
	if (mfp == NULL) {
		ilog(LOG_ERROR, "Could not open metadata file: %s", meta_filepath);
		free(meta_filepath);
		recording->meta_filepath = NULL;
		return NULL;
	}
	recording->pcap.meta_fp = mfp;
	ilog(LOG_DEBUG, "Wrote metadata file to temporary path: %s", meta_filepath);
	return meta_filepath;
}

/**
 * Write out a block of SDP to the metadata file.
 */
static void sdp_after_pcap(struct recording *recording, struct iovec *sdp_iov, int iovcnt,
		       unsigned int str_len, struct call_monologue *ml, enum call_opmode opmode)
{
	FILE *meta_fp = recording->pcap.meta_fp;
	if (!meta_fp)
		return;

	int meta_fd = fileno(meta_fp);
	// File pointers buffer data, whereas direct writing using the file
	// descriptor does not. Make sure to flush any unwritten contents
	// so the file contents appear in order.
	fprintf(meta_fp, "\nSDP mode: ");
	fprintf(meta_fp, "%s", get_opmode_text(opmode));
	fprintf(meta_fp, "\nSDP before RTP packet: %" PRIu64 "\n\n", recording->pcap.packet_num);
	fflush(meta_fp);
	if (writev(meta_fd, sdp_iov, iovcnt) <= 0)
		ilog(LOG_WARN, "Error writing SDP body to metadata file: %s", strerror(errno));
}

/**
 * Writes metadata to metafile, closes file, and renames it to finished location.
 * Returns non-zero for failure.
 */
static int pcap_meta_finish_file(struct call *call) {
	// This should usually be called from a place that has the call->master_lock
	struct recording *recording = call->recording;
	int return_code = 0;

	if (recording != NULL && recording->pcap.meta_fp != NULL) {
		// Print start timestamp and end timestamp
		// YYYY-MM-DDThh:mm:ss
		time_t start = call->created;
		time_t end = g_now.tv_sec;
		char timebuffer[20];
		struct tm *timeinfo;
		timeinfo = localtime(&start);
		strftime(timebuffer, 20, "%FT%T", timeinfo);
		fprintf(recording->pcap.meta_fp, "\n\ncall start time: %s\n", timebuffer);
		timeinfo = localtime(&end);
		strftime(timebuffer, 20, "%FT%T", timeinfo);
		fprintf(recording->pcap.meta_fp, "call end time: %s\n", timebuffer);

		// Print metadata
		if (recording->metadata.len)
			fprintf(recording->pcap.meta_fp, "\n\n"STR_FORMAT"\n", STR_FMT(&recording->metadata));
		fclose(recording->pcap.meta_fp);

		// Get the filename (in between its directory and the file extension)
		// and move it to the finished file location.
		// Rename extension to ".txt".
		int fn_len;
		char *meta_filename = strrchr(recording->meta_filepath, '/');
		char *meta_ext = NULL;
		if (meta_filename == NULL) {
			meta_filename = recording->meta_filepath;
		}
		else {
			meta_filename = meta_filename + 1;
		}
		// We can always expect a file extension
		meta_ext = strrchr(meta_filename, '.');
		fn_len = meta_ext - meta_filename;
		int prefix_len = strlen(spooldir) + 10; // constant for "/metadata/" suffix
		int ext_len = 4;     // for ".txt"
		char new_metapath[prefix_len + fn_len + ext_len + 1];
		snprintf(new_metapath, prefix_len+fn_len+1, "%s/metadata/%s", spooldir, meta_filename);
		snprintf(new_metapath + prefix_len+fn_len, ext_len+1, ".txt");
		return_code = return_code || rename(recording->meta_filepath, new_metapath);
		if (return_code != 0) {
			ilog(LOG_ERROR, "Could not move metadata file \"%s\" to \"%s/metadata/\"",
					 recording->meta_filepath, spooldir);
		} else {
			ilog(LOG_INFO, "Moved metadata file \"%s\" to \"%s/metadata\"",
					 recording->meta_filepath, spooldir);
		}
	} else {
		ilog(LOG_INFO, "Trying to clean up recording meta file without a file pointer opened.");
	}
	mutex_destroy(&recording->pcap.recording_lock);

	return return_code;
}

/**
 * Generate a random PCAP filepath to write recorded RTP stream.
 * Returns path to created file.
 */
static char *recording_setup_file(struct recording *recording) {
	char *recording_path = NULL;

	if (!spooldir)
		return NULL;
	if (recording->pcap.recording_pd || recording->pcap.recording_pdumper)
		return NULL;

	recording_path = file_path_str(recording->meta_prefix, "/pcaps/", ".pcap");
	recording->pcap.recording_path = recording_path;

	recording->pcap.recording_pd = pcap_open_dead(DLT_RAW, 65535);
	recording->pcap.recording_pdumper = pcap_dump_open(recording->pcap.recording_pd, recording_path);
	if (recording->pcap.recording_pdumper == NULL) {
		pcap_close(recording->pcap.recording_pd);
		recording->pcap.recording_pd = NULL;
		ilog(LOG_INFO, "Failed to write recording file: %s", recording_path);
	} else {
		ilog(LOG_INFO, "Writing recording file: %s", recording_path);
	}

	return recording_path;
}

/**
 * Flushes PCAP file, closes the dumper and descriptors, and frees object memory.
 */
static void pcap_recording_finish_file(struct recording *recording) {
	if (recording->pcap.recording_pdumper != NULL) {
		pcap_dump_flush(recording->pcap.recording_pdumper);
		pcap_dump_close(recording->pcap.recording_pdumper);
		free(recording->pcap.recording_path);
	}
	if (recording->pcap.recording_pd != NULL) {
		pcap_close(recording->pcap.recording_pd);
	}
}

// "out" must be at least inp->len + MAX_PACKET_HEADER_LEN bytes
static unsigned int fake_ip_header(unsigned char *out, struct packet_stream *stream, const str *inp) {
	endpoint_t *src_endpoint = &stream->advertised_endpoint;
	endpoint_t *dst_endpoint = &stream->selected_sfd->socket.local;

	unsigned int hdr_len =
		endpoint_packet_header(out, src_endpoint, dst_endpoint, inp->len);

	assert(hdr_len <= MAX_PACKET_HEADER_LEN);

	// payload
	memcpy(out + hdr_len, inp->s, inp->len);

	return hdr_len + inp->len;
}

/**
 * Write out a PCAP packet with payload string.
 * A fair amount extraneous of packet data is spoofed.
 */
static void stream_pcap_dump(pcap_dumper_t *pdumper, struct packet_stream *stream, const str *s) {
	if (!pdumper)
		return;

	unsigned char pkt[s->len + MAX_PACKET_HEADER_LEN];
	unsigned int pkt_len = fake_ip_header(pkt, stream, s);

	// Set up PCAP packet header
	struct pcap_pkthdr header;
	ZERO(header);
	header.ts = g_now;
	header.caplen = pkt_len;
	header.len = pkt_len;

	// Write the packet to the PCAP file
	// Casting quiets compiler warning.
	pcap_dump((unsigned char *)pdumper, &header, pkt);
}

static void dump_packet_pcap(struct recording *recording, struct packet_stream *stream, const str *s) {
	mutex_lock(&recording->pcap.recording_lock);
	stream_pcap_dump(recording->pcap.recording_pdumper, stream, s);
	recording->pcap.packet_num++;
	mutex_unlock(&recording->pcap.recording_lock);
}

static void finish_pcap(struct call *call) {
	pcap_recording_finish_file(call->recording);
	pcap_meta_finish_file(call);
}

static void response_pcap(struct recording *recording, bencode_item_t *output) {
	if (!recording->pcap.recording_path)
		return;

	bencode_item_t *recordings = bencode_dictionary_add_list(output, "recordings");
	bencode_list_add_string(recordings, recording->pcap.recording_path);
}







void recording_finish(struct call *call) {
	if (!call || !call->recording)
		return;

	struct recording *recording = call->recording;

	_rm(finish, call);

	free(recording->meta_prefix);
	free(recording->escaped_callid);
	free(recording->meta_filepath);

	g_slice_free1(sizeof(*(recording)), recording);
	call->recording = NULL;
}








static int open_proc_meta_file(struct recording *recording) {
	int fd;
	fd = open(recording->meta_filepath, O_WRONLY | O_APPEND | O_CREAT, 0666);
	if (fd == -1) {
		ilog(LOG_ERR, "Failed to open recording metadata file '%s' for writing: %s",
				recording->meta_filepath, strerror(errno));
		return -1;
	}
	return fd;
}

static int vappend_meta_chunk_iov(struct recording *recording, struct iovec *in_iov, int iovcnt,
		unsigned int str_len, const char *label_fmt, va_list ap)
{
	int fd = open_proc_meta_file(recording);
	if (fd == -1)
		return -1;

	char label[128];
	int lablen = vsnprintf(label, sizeof(label), label_fmt, ap);
	char infix[128];
	int inflen = snprintf(infix, sizeof(infix), "\n%u:\n", str_len);

	// use writev for an atomic write
	struct iovec iov[iovcnt + 3];
	iov[0].iov_base = label;
	iov[0].iov_len = lablen;
	iov[1].iov_base = infix;
	iov[1].iov_len = inflen;
	memcpy(&iov[2], in_iov, iovcnt * sizeof(*iov));
	iov[iovcnt + 2].iov_base = "\n\n";
	iov[iovcnt + 2].iov_len = 2;

	if (writev(fd, iov, iovcnt + 3) != (str_len + lablen + inflen + 2))
		ilog(LOG_WARN, "writev return value incorrect");

	close(fd); // this triggers the inotify

	return 0;
}

static int append_meta_chunk_iov(struct recording *recording, struct iovec *iov, int iovcnt,
		unsigned int str_len, const char *label_fmt, ...)
	__attribute__((format(printf,5,6)));

static int append_meta_chunk_iov(struct recording *recording, struct iovec *iov, int iovcnt,
		unsigned int str_len, const char *label_fmt, ...)
{
	va_list ap;
	va_start(ap, label_fmt);
	int ret = vappend_meta_chunk_iov(recording, iov, iovcnt, str_len, label_fmt, ap);
	va_end(ap);

	return ret;
}

static int append_meta_chunk(struct recording *recording, const char *buf, unsigned int buflen,
		const char *label_fmt, ...)
	__attribute__((format(printf,4,5)));

static int append_meta_chunk(struct recording *recording, const char *buf, unsigned int buflen,
		const char *label_fmt, ...)
{
	struct iovec iov;
	iov.iov_base = (void *) buf;
	iov.iov_len = buflen;

	va_list ap;
	va_start(ap, label_fmt);
	int ret = vappend_meta_chunk_iov(recording, &iov, 1, buflen, label_fmt, ap);
	va_end(ap);

	return ret;
}
#define append_meta_chunk_str(r, str, f...) append_meta_chunk(r, (str)->s, (str)->len, f)
#define append_meta_chunk_s(r, str, f...) append_meta_chunk(r, (str), strlen(str), f)

static void proc_init(struct call *call) {
	struct recording *recording = call->recording;

	recording->proc.call_idx = UNINIT_IDX;
	if (!kernel.is_open) {
		ilog(LOG_WARN, "Call recording through /proc interface requested, but kernel table not open");
		return;
	}
	recording->proc.call_idx = kernel_add_call(recording->meta_prefix);
	if (recording->proc.call_idx == UNINIT_IDX) {
		ilog(LOG_ERR, "Failed to add call to kernel recording interface: %s", strerror(errno));
		return;
	}
	ilog(LOG_DEBUG, "kernel call idx is %u", recording->proc.call_idx);

	recording->meta_filepath = file_path_str(recording->meta_prefix, "/", ".meta");
	unlink(recording->meta_filepath); // start fresh XXX good idea?

	append_meta_chunk_str(recording, &call->callid, "CALL-ID");
	append_meta_chunk_s(recording, recording->meta_prefix, "PARENT");
}

static void sdp_before_proc(struct recording *recording, const str *sdp, struct call_monologue *ml,
		enum call_opmode opmode)
{
	append_meta_chunk_str(recording, &ml->tag, "TAG %u", ml->unique_id);
	append_meta_chunk_str(recording, sdp,
			"SDP from %u before %s", ml->unique_id, get_opmode_text(opmode));
}

static void sdp_after_proc(struct recording *recording, struct iovec *sdp_iov, int iovcnt,
		       unsigned int str_len, struct call_monologue *ml, enum call_opmode opmode)
{
	append_meta_chunk_iov(recording, sdp_iov, iovcnt, str_len,
			"SDP from %u after %s", ml->unique_id, get_opmode_text(opmode));
}

static void finish_proc(struct call *call) {
	struct recording *recording = call->recording;
	if (!kernel.is_open)
		return;
	if (recording->proc.call_idx != UNINIT_IDX)
		kernel_del_call(recording->proc.call_idx);
	unlink(recording->meta_filepath);
}

static void init_stream_proc(struct packet_stream *stream) {
	stream->recording.proc.stream_idx = UNINIT_IDX;
}

static void setup_stream_proc(struct packet_stream *stream) {
	struct call_media *media = stream->media;
	struct call_monologue *ml = media->monologue;
	struct call *call = stream->call;
	struct recording *recording = call->recording;
	char buf[128];
	int len;

	if (!recording)
		return;
	if (!kernel.is_open)
		return;
	if (stream->recording.proc.stream_idx != UNINIT_IDX)
		return;

	len = snprintf(buf, sizeof(buf), "TAG %u MEDIA %u COMPONENT %u FLAGS %u",
			ml->unique_id, media->index, stream->component,
			stream->ps_flags);
	append_meta_chunk(recording, buf, len, "STREAM %u details", stream->unique_id);

	len = snprintf(buf, sizeof(buf), "tag-%u-media-%u-component-%u-%s-id-%u",
			ml->unique_id, media->index, stream->component,
			(PS_ISSET(stream, RTCP) && !PS_ISSET(stream, RTP)) ? "RTCP" : "RTP",
			stream->unique_id);
	stream->recording.proc.stream_idx = kernel_add_intercept_stream(recording->proc.call_idx, buf);
	if (stream->recording.proc.stream_idx == UNINIT_IDX) {
		ilog(LOG_ERR, "Failed to add stream to kernel recording interface: %s", strerror(errno));
		return;
	}
	ilog(LOG_DEBUG, "kernel stream idx is %u", stream->recording.proc.stream_idx);
	append_meta_chunk(recording, buf, len, "STREAM %u interface", stream->unique_id);
}

static void dump_packet_proc(struct recording *recording, struct packet_stream *stream, const str *s) {
	if (stream->recording.proc.stream_idx == UNINIT_IDX)
		return;

	struct rtpengine_message *remsg;
	unsigned char pkt[sizeof(*remsg) + s->len + MAX_PACKET_HEADER_LEN];
	remsg = (void *) pkt;

	ZERO(*remsg);
	remsg->cmd = REMG_PACKET;
	//remsg->u.packet.call_idx = stream->call->recording->proc.call_idx; // unused
	remsg->u.packet.stream_idx = stream->recording.proc.stream_idx;

	unsigned int pkt_len = fake_ip_header(remsg->data, stream, s);
	pkt_len += sizeof(*remsg);

	int ret = write(kernel.fd, pkt, pkt_len);
	if (ret < 0)
		ilog(LOG_ERR, "Failed to submit packet to kernel intercepted stream: %s", strerror(errno));
}

static void kernel_info_proc(struct packet_stream *stream, struct rtpengine_target_info *reti) {
	if (!stream->call->recording)
		return;
	if (stream->recording.proc.stream_idx == UNINIT_IDX)
		return;
	ilog(LOG_DEBUG, "enabling kernel intercept with stream idx %u", stream->recording.proc.stream_idx);
	reti->do_intercept = 1;
	reti->intercept_stream_idx = stream->recording.proc.stream_idx;
}

static void meta_chunk_proc(struct recording *recording, const char *label, const str *data) {
	append_meta_chunk_str(recording, data, "%s", label);
}
