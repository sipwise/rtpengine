#ifndef __FS_H__
#define __FS_H__

#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include "call.h"

/**
 * Initialize RTP Engine filesystem settings and structure.
 * Check for or create the RTP Engine spool directory.
 */
void fs_init(char *spooldir);

/**
 * Create a call metadata file in a temporary location.
 * Attaches the filepath and the file pointer to the call struct.
 * Returns path to created file.
 *
 * Metadata file format is (with trailing newline):
 *
 *     /path/to/rec-pcap01.pcap
 *     /path/to/rec-pcap02.pcap
 *     ...
 *     /path/to/rec-pcap0n.pcap
 *
 *     start timestamp (YYYY-MM-DDThh:mm:ss)
 *     end timestamp   (YYYY-MM-DDThh:mm:ss)
 *
 *     metadata
 *
 */
str *meta_setup_file(struct call *call);

/**
 * Writes metadata to metafile, closes file, and renames it to finished location.
 * Returns non-zero for failure.
 */
int meta_finish_file(struct call *call);

/**
 * Generate a random PCAP filepath to write recorded RTP stream.
 * Returns path to created file.
 */
str *recording_setup_file(struct call *call, struct call_monologue *monologue);

/**
 * Write out a PCAP packet with payload string.
 * A fair amount extraneous of packet data is spoofed.
 */
void stream_pcap_dump(pcap_dumper_t *pdumper, str *s);

#endif
