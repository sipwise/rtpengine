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
#include "helpers.h"
#include "bencode.h"
#include "types.h"

struct packet_stream;
struct media_packet;
enum ng_opmode;
struct rtpengine_target_info;
struct call_monologue;
struct call_media;


struct recording_pcap {
	char          *meta_filepath; // full file path
	FILE          *meta_fp;
	pcap_t        *recording_pd;
	pcap_dumper_t *recording_pdumper;
	uint64_t      packet_num;
	char          *recording_path;

	mutex_t       recording_lock;
};

struct recording_proc {
	unsigned int call_idx;
	char *meta_filepath; // full file path
};
struct recording_stream_proc {
	unsigned int stream_idx;
};

struct recording {
	struct recording_pcap pcap;
	struct recording_proc proc;
};

struct recording_stream {
	union {
		struct recording_stream_proc proc;
	};
};

struct recording_method {
	const char *name;
	int kernel_support;

	int (*create_spool_dir)(const char *);
	void (*init_struct)(call_t *);

	void (*sdp_before)(struct recording *, const str *, struct call_monologue *, enum ng_opmode);
	void (*sdp_after)(struct recording *, const str *, struct call_monologue *,
			enum ng_opmode);
	void (*meta_chunk)(struct recording *, const char *, const str *);
	void (*update_flags)(call_t *call, bool streams);

	void (*dump_packet)(struct media_packet *, const str *s);
	void (*finish)(call_t *, bool discard);
	void (*response)(struct recording *, const ng_parser_t *, parser_arg);

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



/**
 * Initialize RTP Engine filesystem settings and structure.
 * Check for or create the RTP Engine spool directory.
 */
void recording_fs_init(const char *spooldir, const char *method, const char *format);
void recording_fs_free(void);


/**
 *
 * Controls the setting of recording variables on a `call_t *`.
 * Sets the `record_call` value on the `struct call`, initializing the
 * recording struct if necessary.
 * If we do not yet have a PCAP file associated with the call, create it
 * and write its file URL to the metadata file.
 *
 * Returns a boolean for whether or not the call is being recorded.
 */
void detect_setup_recording(call_t *call, const sdp_ng_flags *flags);
void update_metadata_call(call_t *call, const sdp_ng_flags *flags);
void update_metadata_monologue(struct call_monologue *ml, const sdp_ng_flags *flags);

void recording_start(call_t *call);
void recording_start_daemon(call_t *call);
void recording_pause(call_t *call);
void recording_stop(call_t *call);
void recording_stop_daemon(call_t *call);
void recording_discard(call_t *call);


#define meta_write_sdp_before(args...) _rm(sdp_before, args)
#define meta_write_sdp_after(args...) _rm(sdp_after, args)

void recording_finish(call_t *, bool discard);



#define recording_setup_stream(args...) _rm(setup_stream, args)
#define recording_setup_media(args...) _rm(setup_media, args)
#define recording_setup_monologue(args...) _rm(setup_monologue, args)
#define recording_init_stream(args...) _rm(init_stream_struct, args)
#define recording_stream_kernel_info(args...) _rm(stream_kernel_info, args)
#define recording_meta_chunk(args...) _rm(meta_chunk, args)
#define recording_response(args...) _rm(response, args)
#define dump_packet(args...) _rm(dump_packet, args)

#endif
