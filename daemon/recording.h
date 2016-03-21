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
#include "call.h"


struct recording {
	str           *meta_filepath;
	FILE          *meta_fp;
	str           *metadata;
	pcap_t        *recording_pd;
	pcap_dumper_t *recording_pdumper;
	uint64_t      *packet_num;
	str           *recording_path;
};


/**
 * Initialize RTP Engine filesystem settings and structure.
 * Check for or create the RTP Engine spool directory.
 */
void recording_fs_init(char *spooldir);

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
int detect_setup_recording(struct call *call, str recordcall);

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
str *meta_setup_file(struct recording *recording, str callid);

/**
 * Write out a block of SDP to the metadata file.
 */
ssize_t meta_write_sdp(FILE *meta_fp, struct iovec *sdp_iov, int iovcnt,
		       uint64_t packet_num, enum call_opmode opmode);

/**
 * Writes metadata to metafile, closes file, and moves it to finished location.
 * Returns non-zero for failure.
 *
 * Metadata files are moved to ${RECORDING_DIR}/metadata/
 */
int meta_finish_file(struct call *call);

/**
 * Generate a random PCAP filepath to write recorded RTP stream.
 * Returns path to created file.
 *
 * Files go in ${RECORDING_DIR}/pcaps, and are named like:
 * ${CALL_ID}-${RAND-HEX}.pcap
 */
str *recording_setup_file(struct recording *recording, str callid);

/**
 * Flushes PCAP file, closes the dumper and descriptors, and frees object memory.
 */
void recording_finish_file(struct recording *recording);

/**
 * Write out a PCAP packet with payload string.
 * A fair amount extraneous of packet data is spoofed.
 */
void stream_pcap_dump(pcap_dumper_t *pdumper, struct packet_stream *sink, str *s);

#endif
