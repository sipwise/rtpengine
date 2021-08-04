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
#include "rtplib.h"
#include "cdr.h"
#include "log.h"



struct rec_pcap_format {
	int linktype;
	int headerlen;
	void (*header)(unsigned char *, struct packet_stream *);
};



static int check_main_spool_dir(const char *spoolpath);
static char *recording_setup_file(struct recording *recording);
static char *meta_setup_file(struct recording *recording);
static int append_meta_chunk(struct recording *recording, const char *buf, unsigned int buflen,
		const char *label_fmt, ...)
	__attribute__((format(printf,4,5)));

// pcap methods
static int rec_pcap_create_spool_dir(const char *dirpath);
static void rec_pcap_init(struct call *);
static void sdp_after_pcap(struct recording *, GString *str, struct call_monologue *, enum call_opmode opmode);
static void dump_packet_pcap(struct media_packet *mp, const str *s);
static void finish_pcap(struct call *);
static void response_pcap(struct recording *, bencode_item_t *);

// proc methods
static void proc_init(struct call *);
static void sdp_before_proc(struct recording *, const str *, struct call_monologue *, enum call_opmode);
static void sdp_after_proc(struct recording *, GString *str, struct call_monologue *, enum call_opmode opmode);
static void meta_chunk_proc(struct recording *, const char *, const str *);
static void update_flags_proc(struct call *call);
static void finish_proc(struct call *);
static void dump_packet_proc(struct media_packet *mp, const str *s);
static void init_stream_proc(struct packet_stream *);
static void setup_stream_proc(struct packet_stream *);
static void setup_media_proc(struct call_media *);
static void setup_monologue_proc(struct call_monologue *);
static void kernel_info_proc(struct packet_stream *, struct rtpengine_target_info *);

static void rec_pcap_eth_header(unsigned char *, struct packet_stream *);

#define append_meta_chunk_str(r, str, f...) append_meta_chunk(r, (str)->s, (str)->len, f)
#define append_meta_chunk_s(r, str, f...) append_meta_chunk(r, (str), strlen(str), f)
#define append_meta_chunk_null(r,f...) append_meta_chunk(r, "", 0, f)


static const struct recording_method methods[] = {
	{
		.name = "pcap",
		.kernel_support = 0,
		.create_spool_dir = rec_pcap_create_spool_dir,
		.init_struct = rec_pcap_init,
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
		.update_flags = update_flags_proc,
		.dump_packet = dump_packet_proc,
		.finish = finish_proc,
		.init_stream_struct = init_stream_proc,
		.setup_stream = setup_stream_proc,
		.setup_media = setup_media_proc,
		.setup_monologue = setup_monologue_proc,
		.stream_kernel_info = kernel_info_proc,
	},
};

static const struct rec_pcap_format rec_pcap_format_raw = {
	.linktype = DLT_RAW,
	.headerlen = 0,
};
static const struct rec_pcap_format rec_pcap_format_eth = {
	.linktype = DLT_EN10MB,
	.headerlen = 14,
	.header = rec_pcap_eth_header,
};


// Global file reference to the spool directory.
static char *spooldir = NULL;

const struct recording_method *selected_recording_method;
static const struct rec_pcap_format *rec_pcap_format;



/**
 * Free RTP Engine filesystem settings and structure.
 * Check for and free the RTP Engine spool directory.
 */

void recording_fs_free(void) {
	if (spooldir)
		free(spooldir);

	spooldir = NULL;
}

/**
 * Initialize RTP Engine filesystem settings and structure.
 * Check for or create the RTP Engine spool directory.
 */
void recording_fs_init(const char *spoolpath, const char *method_str, const char *format_str) {
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
	if(!strcmp("raw", format_str))
		rec_pcap_format = &rec_pcap_format_raw;
	else if(!strcmp("eth", format_str))
		rec_pcap_format = &rec_pcap_format_eth;
	else {
		ilog(LOG_ERR, "Invalid value for recording format \"%s\".", format_str);
		exit(-1);
	}

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

static int check_create_dir(const char *dir, const char *desc, mode_t creat_mode) {
	struct stat info;

	if (stat(dir, &info) != 0) {
		if (!creat_mode) {
			ilog(LOG_WARN, "%s directory \"%s\" does not exist.", desc, dir);
			return FALSE;
		}
		ilog(LOG_INFO, "Creating %s directory \"%s\".", desc, dir);
		// coverity[toctou : FALSE]
		if (mkdir(dir, creat_mode) == 0)
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
	return check_create_dir(spoolpath, "spool", 0700);
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
static int rec_pcap_create_spool_dir(const char *spoolpath) {
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

	if (!check_create_dir(meta_path, "metadata", 0777))
		spool_good = FALSE;
	if (!check_create_dir(rec_path, "pcaps", 0777))
		spool_good = FALSE;
	if (!check_create_dir(tmp_path, "tmp", 0777))
		spool_good = FALSE;

	return spool_good;
}

// lock must be held
static void update_metadata(struct call *call, str *metadata) {
	if (!metadata || !metadata->s)
		return;

	if (str_cmp_str(metadata, &call->metadata)) {
		call_str_cpy(call, &call->metadata, metadata);
		if (call->recording)
			recording_meta_chunk(call->recording, "METADATA", metadata);
	}
}

static void update_output_dest(struct call *call, str *output_dest) {
	if (!output_dest || !output_dest->s || !call->recording)
		return;
	recording_meta_chunk(call->recording, "OUTPUT_DESTINATION", output_dest);
}

// lock must be held
static void update_flags_proc(struct call *call) {
	append_meta_chunk_null(call->recording, "RECORDING %u", call->recording_on ? 1 : 0);
	append_meta_chunk_null(call->recording, "FORWARDING %u", call->rec_forwarding ? 1 : 0);
	for (GList *l = call->streams.head; l; l = l->next) {
		struct packet_stream *ps = l->data;
		append_meta_chunk_null(call->recording, "STREAM %u FORWARDING %u",
				ps->unique_id, ps->media->monologue->rec_forwarding ? 1 : 0);
	}
}
static void recording_update_flags(struct call *call) {
	_rm(update_flags, call);
}

// lock must be held
void recording_start(struct call *call, const char *prefix, str *metadata, str *output_dest) {
	update_metadata(call, metadata);

	update_output_dest(call, output_dest);

	if (call->recording) {
		// already active
		recording_update_flags(call);
		return;
	}

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
	for (l = call->monologues.head; l; l = l->next) {
		struct call_monologue *ml = l->data;
		recording_setup_monologue(ml);
	}
	for (l = call->medias.head; l; l = l->next) {
		struct call_media *m = l->data;
		recording_setup_media(m);
	}
	for (l = call->streams.head; l; l = l->next) {
		struct packet_stream *ps = l->data;
		recording_setup_stream(ps);
		__unkernelize(ps);
		__reset_sink_handlers(ps);
	}

	recording_update_flags(call);
}
void recording_stop(struct call *call, str *metadata) {
	if (!call->recording)
		return;

	if (metadata)
		update_metadata(call, metadata);

	// check if all recording options are disabled
	if (call->recording_on || call->rec_forwarding) {
		recording_update_flags(call);
		return;
	}

	for (GList *l = call->monologues.head; l; l = l->next) {
		struct call_monologue *ml = l->data;
		if (ml->rec_forwarding) {
			recording_update_flags(call);
			return;
		}
	}

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
void detect_setup_recording(struct call *call, const str *recordcall, str *metadata) {
	update_metadata(call, metadata);

	if (!recordcall || !recordcall->s)
		return;

	if (!str_cmp(recordcall, "yes") || !str_cmp(recordcall, "on")) {
		call->recording_on = 1;
		recording_start(call, NULL, NULL, NULL);
	}
	else if (!str_cmp(recordcall, "no") || !str_cmp(recordcall, "off")) {
		call->recording_on = 0;
		recording_stop(call, NULL);
	}
	else
		ilog(LOG_INFO, "\"record-call\" flag "STR_FORMAT" is invalid flag.", STR_FMT(recordcall));
}

static void rec_pcap_init(struct call *call) {
	struct recording *recording = call->recording;

	// Wireshark starts at packet index 1, so we start there, too
	recording->u.pcap.packet_num = 1;
	mutex_init(&recording->u.pcap.recording_lock);
	meta_setup_file(recording);

	// set up pcap file
	char *pcap_path = recording_setup_file(recording);
	if (pcap_path != NULL && recording->u.pcap.recording_pdumper != NULL
	    && recording->u.pcap.meta_fp) {
		// Write the location of the PCAP file to the metadata file
		fprintf(recording->u.pcap.meta_fp, "%s\n\n", pcap_path);
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
	// coverity[check_return : FALSE]
	chmod(meta_filepath, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
	if (mfp == NULL) {
		ilog(LOG_ERROR, "Could not open metadata file: %s%s%s", FMT_M(meta_filepath));
		free(meta_filepath);
		recording->meta_filepath = NULL;
		return NULL;
	}
	recording->u.pcap.meta_fp = mfp;
	ilog(LOG_DEBUG, "Wrote metadata file to temporary path: %s%s%s", FMT_M(meta_filepath));
	return meta_filepath;
}

/**
 * Write out a block of SDP to the metadata file.
 */
static void sdp_after_pcap(struct recording *recording, GString *str, struct call_monologue *ml,
		enum call_opmode opmode)
{
	FILE *meta_fp = recording->u.pcap.meta_fp;
	if (!meta_fp)
		return;

	int meta_fd = fileno(meta_fp);
	// File pointers buffer data, whereas direct writing using the file
	// descriptor does not. Make sure to flush any unwritten contents
	// so the file contents appear in order.
	if (ml->label.len) {
		fprintf(meta_fp, "\nLabel: " STR_FORMAT, STR_FMT(&ml->label));
	}
	fprintf(meta_fp, "\nTimestamp started ms: ");
	fprintf(meta_fp, "%.3lf", ml->started.tv_sec*1000.0+ml->started.tv_usec/1000.0);
	fprintf(meta_fp, "\nSDP mode: ");
	fprintf(meta_fp, "%s", get_opmode_text(opmode));
	fprintf(meta_fp, "\nSDP before RTP packet: %" PRIu64 "\n\n", recording->u.pcap.packet_num);
	fflush(meta_fp);
	if (write(meta_fd, str->str, str->len) <= 0)
		ilog(LOG_WARN, "Error writing SDP body to metadata file: %s", strerror(errno));
}

/**
 * Writes metadata to metafile, closes file, and renames it to finished location.
 * Returns non-zero for failure.
 */
static int rec_pcap_meta_finish_file(struct call *call) {
	// This should usually be called from a place that has the call->master_lock
	struct recording *recording = call->recording;
	int return_code = 0;

	if (recording == NULL || recording->u.pcap.meta_fp == NULL) {
		ilog(LOG_INFO, "Trying to clean up recording meta file without a file pointer opened.");
		return 0;
	}

	// Print start timestamp and end timestamp
	// YYYY-MM-DDThh:mm:ss
	time_t start = call->created.tv_sec;
	time_t end = rtpe_now.tv_sec;
	char timebuffer[20];
	struct tm timeinfo;
	struct timeval *terminate;
	terminate = &(((struct call_monologue *)call->monologues.head->data)->terminated);
	fprintf(recording->u.pcap.meta_fp, "\nTimestamp terminated ms(first monologue): %.3lf", terminate->tv_sec*1000.0 + terminate->tv_usec/1000.0);
	if (localtime_r(&start, &timeinfo) == NULL) {
		ilog(LOG_ERROR, "Cannot get start local time, while cleaning up recording meta file: %s", strerror(errno));
	} else {
		strftime(timebuffer, 20, "%FT%T", &timeinfo);
		fprintf(recording->u.pcap.meta_fp, "\n\ncall start time: %s\n", timebuffer);
	}
	if (localtime_r(&end, &timeinfo) == NULL) {
		ilog(LOG_ERROR, "Cannot get end local time, while cleaning up recording meta file: %s", strerror(errno));
	} else {
		strftime(timebuffer, 20, "%FT%T", &timeinfo);
		fprintf(recording->u.pcap.meta_fp, "call end time: %s\n", timebuffer);
	}

	// Print metadata
	if (call->metadata.len)
		fprintf(recording->u.pcap.meta_fp, "\n\n"STR_FORMAT"\n", STR_FMT(&call->metadata));
	fclose(recording->u.pcap.meta_fp);
	recording->u.pcap.meta_fp = NULL;

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

	mutex_destroy(&recording->u.pcap.recording_lock);

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
	if (recording->u.pcap.recording_pd || recording->u.pcap.recording_pdumper)
		return NULL;

	recording_path = file_path_str(recording->meta_prefix, "/pcaps/", ".pcap");
	recording->u.pcap.recording_path = recording_path;

	recording->u.pcap.recording_pd = pcap_open_dead(rec_pcap_format->linktype, 65535);
	recording->u.pcap.recording_pdumper = pcap_dump_open(recording->u.pcap.recording_pd, recording_path);
	if (recording->u.pcap.recording_pdumper == NULL) {
		pcap_close(recording->u.pcap.recording_pd);
		recording->u.pcap.recording_pd = NULL;
		ilog(LOG_INFO, "Failed to write recording file: %s", recording_path);
	} else {
		ilog(LOG_INFO, "Writing recording file: %s", recording_path);
	}

	return recording_path;
}

/**
 * Flushes PCAP file, closes the dumper and descriptors, and frees object memory.
 */
static void rec_pcap_recording_finish_file(struct recording *recording) {
	if (recording->u.pcap.recording_pdumper != NULL) {
		pcap_dump_flush(recording->u.pcap.recording_pdumper);
		pcap_dump_close(recording->u.pcap.recording_pdumper);
		free(recording->u.pcap.recording_path);
	}
	if (recording->u.pcap.recording_pd != NULL) {
		pcap_close(recording->u.pcap.recording_pd);
	}
}

// "out" must be at least inp->len + MAX_PACKET_HEADER_LEN bytes
static unsigned int fake_ip_header(unsigned char *out, struct media_packet *mp, const str *inp) {
	endpoint_t *src_endpoint = &mp->fsin;
	endpoint_t *dst_endpoint = &mp->sfd->socket.local;

	unsigned int hdr_len =
		endpoint_packet_header(out, src_endpoint, dst_endpoint, inp->len);

	assert(hdr_len <= MAX_PACKET_HEADER_LEN);

	// payload
	memcpy(out + hdr_len, inp->s, inp->len);

	return hdr_len + inp->len;
}

static void rec_pcap_eth_header(unsigned char *pkt, struct packet_stream *stream) {
	memset(pkt, 0, 14);
	uint16_t *hdr16 = (void *) pkt;
	hdr16[6] = htons(stream->selected_sfd->socket.local.address.family->ethertype);
}

/**
 * Write out a PCAP packet with payload string.
 * A fair amount extraneous of packet data is spoofed.
 */
static void stream_pcap_dump(struct media_packet *mp, const str *s) {
	pcap_dumper_t *pdumper = mp->call->recording->u.pcap.recording_pdumper;
	if (!pdumper)
		return;

	unsigned char pkt[s->len + MAX_PACKET_HEADER_LEN + rec_pcap_format->headerlen];
	unsigned int pkt_len = fake_ip_header(pkt + rec_pcap_format->headerlen, mp, s) + rec_pcap_format->headerlen;
	if (rec_pcap_format->header)
		rec_pcap_format->header(pkt, mp->stream);

	// Set up PCAP packet header
	struct pcap_pkthdr header;
	ZERO(header);
	header.ts = rtpe_now;
	header.caplen = pkt_len;
	header.len = pkt_len;

	// Write the packet to the PCAP file
	// Casting quiets compiler warning.
	pcap_dump((unsigned char *)pdumper, &header, pkt);
}

static void dump_packet_pcap(struct media_packet *mp, const str *s) {
	struct recording *recording = mp->call->recording;
	mutex_lock(&recording->u.pcap.recording_lock);
	stream_pcap_dump(mp, s);
	recording->u.pcap.packet_num++;
	mutex_unlock(&recording->u.pcap.recording_lock);
}

static void finish_pcap(struct call *call) {
	rec_pcap_recording_finish_file(call->recording);
	rec_pcap_meta_finish_file(call);
}

static void response_pcap(struct recording *recording, bencode_item_t *output) {
	if (!recording->u.pcap.recording_path)
		return;

	bencode_item_t *recordings = bencode_dictionary_add_list(output, "recordings");
	bencode_list_add_string(recordings, recording->u.pcap.recording_path);
}







void recording_finish(struct call *call) {
	if (!call || !call->recording)
		return;

	__call_unkernelize(call);

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

static void proc_init(struct call *call) {
	struct recording *recording = call->recording;

	recording->u.proc.call_idx = UNINIT_IDX;
	if (!kernel.is_open) {
		ilog(LOG_WARN, "Call recording through /proc interface requested, but kernel table not open");
		return;
	}
	recording->u.proc.call_idx = kernel_add_call(recording->meta_prefix);
	if (recording->u.proc.call_idx == UNINIT_IDX) {
		ilog(LOG_ERR, "Failed to add call to kernel recording interface: %s", strerror(errno));
		return;
	}
	ilog(LOG_DEBUG, "kernel call idx is %u", recording->u.proc.call_idx);

	recording->meta_filepath = file_path_str(recording->meta_prefix, "/", ".meta");
	unlink(recording->meta_filepath); // start fresh XXX good idea?

	append_meta_chunk_str(recording, &call->callid, "CALL-ID");
	append_meta_chunk_s(recording, recording->meta_prefix, "PARENT");
	if (call->metadata.len)
		recording_meta_chunk(recording, "METADATA", &call->metadata);
}

static void sdp_before_proc(struct recording *recording, const str *sdp, struct call_monologue *ml,
		enum call_opmode opmode)
{
	append_meta_chunk_str(recording, sdp,
			"SDP from %u before %s", ml->unique_id, get_opmode_text(opmode));
}

static void sdp_after_proc(struct recording *recording, GString *str, struct call_monologue *ml,
		enum call_opmode opmode)
{
	append_meta_chunk(recording, str->str, str->len,
			"SDP from %u after %s", ml->unique_id, get_opmode_text(opmode));
}

static void finish_proc(struct call *call) {
	struct recording *recording = call->recording;
	if (!kernel.is_open)
		return;
	if (recording->u.proc.call_idx != UNINIT_IDX) {
		kernel_del_call(recording->u.proc.call_idx);
		recording->u.proc.call_idx = UNINIT_IDX;
	}
	for (GList *l = call->streams.head; l; l = l->next) {
		struct packet_stream *ps = l->data;
		ps->recording.u.proc.stream_idx = UNINIT_IDX;
	}
	unlink(recording->meta_filepath);
}

static void init_stream_proc(struct packet_stream *stream) {
	stream->recording.u.proc.stream_idx = UNINIT_IDX;
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
	if (stream->recording.u.proc.stream_idx != UNINIT_IDX)
		return;

	len = snprintf(buf, sizeof(buf), "TAG %u MEDIA %u TAG-MEDIA %u COMPONENT %u FLAGS %u",
			ml->unique_id, media->unique_id, media->index, stream->component,
			stream->ps_flags);
	append_meta_chunk(recording, buf, len, "STREAM %u details", stream->unique_id);

	len = snprintf(buf, sizeof(buf), "tag-%u-media-%u-component-%u-%s-id-%u",
			ml->unique_id, media->index, stream->component,
			(PS_ISSET(stream, RTCP) && !PS_ISSET(stream, RTP)) ? "RTCP" : "RTP",
			stream->unique_id);
	stream->recording.u.proc.stream_idx = kernel_add_intercept_stream(recording->u.proc.call_idx, buf);
	if (stream->recording.u.proc.stream_idx == UNINIT_IDX) {
		ilog(LOG_ERR, "Failed to add stream to kernel recording interface: %s", strerror(errno));
		return;
	}
	ilog(LOG_DEBUG, "kernel stream idx is %u", stream->recording.u.proc.stream_idx);
	append_meta_chunk(recording, buf, len, "STREAM %u interface", stream->unique_id);
}

static void setup_monologue_proc(struct call_monologue *ml) {
	struct call *call = ml->call;
	struct recording *recording = call->recording;

	if (!recording)
		return;

	append_meta_chunk_str(recording, &ml->tag, "TAG %u", ml->unique_id);
	if (ml->label.len)
		append_meta_chunk_str(recording, &ml->label, "LABEL %u", ml->unique_id);
}

static void setup_media_proc(struct call_media *media) {
	struct call *call = media->call;
	struct recording *recording = call->recording;

	if (!recording)
		return;

	append_meta_chunk_null(recording, "MEDIA %u PTIME %i", media->unique_id, media->ptime);

	GList *pltypes = g_hash_table_get_values(media->codecs.codecs);

	for (GList *l = pltypes; l; l = l->next) {
		struct rtp_payload_type *pt = l->data;
		append_meta_chunk(recording, pt->encoding_with_params.s, pt->encoding_with_params.len,
				"MEDIA %u PAYLOAD TYPE %u", media->unique_id, pt->payload_type);
		append_meta_chunk(recording, pt->format_parameters.s, pt->format_parameters.len,
				"MEDIA %u FMTP %u", media->unique_id, pt->payload_type);
	}

	g_list_free(pltypes);
}



static void dump_packet_proc(struct media_packet *mp, const str *s) {
	struct packet_stream *stream = mp->stream;
	if (stream->recording.u.proc.stream_idx == UNINIT_IDX)
		return;

	struct rtpengine_message *remsg;
	unsigned char pkt[sizeof(*remsg) + s->len + MAX_PACKET_HEADER_LEN];
	remsg = (void *) pkt;

	ZERO(*remsg);
	remsg->cmd = REMG_PACKET;
	//remsg->u.packet.call_idx = stream->call->recording->u.proc.call_idx; // unused
	remsg->u.packet.stream_idx = stream->recording.u.proc.stream_idx;

	unsigned int pkt_len = fake_ip_header(remsg->data, mp, s);
	pkt_len += sizeof(*remsg);

	int ret = write(kernel.fd, pkt, pkt_len);
	if (ret < 0)
		ilog(LOG_ERR, "Failed to submit packet to kernel intercepted stream: %s", strerror(errno));
}

static void kernel_info_proc(struct packet_stream *stream, struct rtpengine_target_info *reti) {
	if (!stream->call->recording)
		return;
	if (stream->recording.u.proc.stream_idx == UNINIT_IDX)
		return;
	ilog(LOG_DEBUG, "enabling kernel intercept with stream idx %u", stream->recording.u.proc.stream_idx);
	reti->do_intercept = 1;
	reti->intercept_stream_idx = stream->recording.u.proc.stream_idx;
}

static void meta_chunk_proc(struct recording *recording, const char *label, const str *data) {
	append_meta_chunk_str(recording, data, "%s", label);
}
