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
	str           *recording_path;
};


/**
 * Initialize RTP Engine filesystem settings and structure.
 * Check for or create the RTP Engine spool directory.
 */
void recording_fs_init(char *spooldir);

/**
 * Create a call metadata file in a temporary location.
 * Attaches the filepath and the file pointer to the call struct.
 * Returns path to created file.
 *
 * Metadata file format is (with trailing newline):
 *
 *     /path/to/recording-pcap.pcap
 *
 *     start timestamp (YYYY-MM-DDThh:mm:ss)
 *     end timestamp   (YYYY-MM-DDThh:mm:ss)
 *
 *     generic metadata
 *
 */
str *meta_setup_file(struct recording *recording);

/**
 * Writes metadata to metafile, closes file, and renames it to finished location.
 * Returns non-zero for failure.
 */
int meta_finish_file(struct call *call);

/**
 * Generate a random PCAP filepath to write recorded RTP stream.
 * Returns path to created file.
 */
str *recording_setup_file(struct recording *recording);

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
