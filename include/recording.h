/**
 * recording.h
 *
 * Handles call recording to PCAP files and recording metadata.
 * Mostly filesystem operations
 */

#ifndef __RECORDING_H__
#define __RECORDING_H__

#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <pcap.h>
#include "str.h"
#include "aux.h"
#include "bencode.h"


struct packet_stream;
struct media_packet;
struct call;
enum call_opmode;
struct rtpengine_target_info;
struct call_monologue;
struct call_media;


struct recording_pcap {
	FILE          *meta_fp;
	pcap_t        *recording_pd;
	pcap_dumper_t *recording_pdumper;
	uint64_t      packet_num;
	char          *recording_path;

	mutex_t       recording_lock;
};

struct recording_proc {
	unsigned int call_idx;
};
struct recording_stream_proc {
	unsigned int stream_idx;
};

struct recording {
	struct {
		struct recording_pcap pcap;
		struct recording_proc proc;
	} u;

	char		*escaped_callid; // call-id with dangerous characters escaped
	char		*meta_prefix; // escaped call-id plus random suffix
	char		*meta_filepath_proc; // full file path
	char		*meta_filepath_pcap; // full file path
};

struct recording_stream {
	union {
		struct recording_stream_proc proc;
	} u;
};

struct recording_method {
	const char *name;
	int kernel_support;

	int (*create_spool_dir)(const char *);
	void (*init_struct)(struct call *);

	void (*sdp_before)(struct recording *, const str *, struct call_monologue *, enum call_opmode);
	void (*sdp_after)(struct recording *, GString *, struct call_monologue *,
			enum call_opmode);
	void (*meta_chunk)(struct recording *, const char *, const str *);
	void (*update_flags)(struct call *call, bool streams);

	void (*dump_packet)(struct media_packet *, const str *s);
	void (*finish)(struct call *);
	void (*response)(struct recording *, bencode_item_t *);

	void (*init_stream_struct)(struct packet_stream *);
	void (*setup_stream)(struct packet_stream *);
	void (*setup_media)(struct call_media *);
	void (*setup_monologue)(struct call_monologue *);
	void (*stream_kernel_info)(struct packet_stream *, struct rtpengine_target_info *);
};

extern const struct recording_method *selected_recording_method;

#define _rm_ret(method, args...) selected_recording_method->method(args)
#define _rm(method, args...) do { \
		if (selected_recording_method && selected_recording_method->method) \
			selected_recording_method->method(args); \
	} while (0)
#define _rm_chk(method, recording, ...) do { \
		if (recording) \
			_rm(method, recording, ##__VA_ARGS__); \
	} while (0)



/**
 * Initialize RTP Engine filesystem settings and structure.
 * Check for or create the RTP Engine spool directory.
 */
void recording_fs_init(const char *spooldir, const char *method, const char *format);
void recording_fs_free(void);


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
void detect_setup_recording(struct call *call, const str *recordcall);
void update_metadata_call(struct call *call, str *metadata);
void update_metadata_monologue(struct call_monologue *ml, str *metadata);

void recording_start(struct call *call, const char *prefix, str *output_dest);
void recording_pause(struct call *call);
void recording_stop(struct call *call);


/**
 * Create a call metadata file in a temporary location.
 * Attaches the filepath and the file pointer to the call struct.
 * Returns path to created file.
 *
 * Metadata file format is (with trailing newline):
 *
 *     /path/to/recording-pcap.pcap
 *
 *
 *     first SDP answer
 *
 *     second SDP answer
 *
 *     ...
 *
 *     n-th and final SDP answer
 *
 *
 *     start timestamp (YYYY-MM-DDThh:mm:ss)
 *     end timestamp   (YYYY-MM-DDThh:mm:ss)
 *
 *
 *     generic metadata
 *
 * There are two empty lines between each logic block of metadata.
 * The generic metadata at the end can be any length with any number of lines.
 * Temporary files go in /tmp/. They will end up in
 * ${RECORDING_DIR}/metadata/. They are named like:
 * ${CALL_ID}-${RAND-HEX}.pcap
 *
 */
//str *meta_setup_file(struct recording *recording, str callid);

/**
 * Write out a block of SDP to the metadata file.
 */
//ssize_t meta_write_sdp(struct recording *, struct iovec *sdp_iov, int iovcnt,
//		       enum call_opmode opmode);
#define meta_write_sdp_before(args...) _rm(sdp_before, args)
#define meta_write_sdp_after(args...) _rm(sdp_after, args)

/**
 * Writes metadata to metafile, closes file, and moves it to finished location.
 * Returns non-zero for failure.
 *
 * Metadata files are moved to ${RECORDING_DIR}/metadata/
 */
// int meta_finish_file(struct call *call);

/**
 * Flushes PCAP file, closes the dumper and descriptors, and frees object memory.
 */
// void recording_finish_file(struct recording *recording);

// combines the two calls above
void recording_finish(struct call *);

/**
 * Write out a PCAP packet with payload string.
 * A fair amount extraneous of packet data is spoofed.
 */
// void dump_packet(struct recording *, struct packet_stream *, str *s);
#define dump_packet(args...) _rm_chk(dump_packet, args)



#define recording_setup_stream(args...) _rm(setup_stream, args)
#define recording_setup_media(args...) _rm(setup_media, args)
#define recording_setup_monologue(args...) _rm(setup_monologue, args)
#define recording_init_stream(args...) _rm(init_stream_struct, args)
#define recording_stream_kernel_info(args...) _rm(stream_kernel_info, args)
#define recording_meta_chunk(args...) _rm(meta_chunk, args)
#define recording_response(args...) _rm(response, args)

#endif
