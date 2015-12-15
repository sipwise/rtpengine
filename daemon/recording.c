#include "recording.h"
#include <stdio.h>
#include <stdlib.h>
#include <glib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <time.h>
#include "call.h"
#include <pcap.h>



int maybe_create_spool_dir(char *dirpath);

// Global file reference to the spool directory.
static char *spooldir = NULL;


/**
 * Initialize RTP Engine filesystem settings and structure.
 * Check for or create the RTP Engine spool directory.
 */
void recording_fs_init(char *spoolpath) {
	// Whether or not to fail if the spool directory does not exist.
	int dne_fail;
	if (spoolpath == NULL || spoolpath[0] == '\0') {
		spoolpath = "/var/spool/rtpengine";
		dne_fail = FALSE;
	} else {
		dne_fail = TRUE;
		int path_len = strlen(spoolpath);
		// Get rid of trailing "/" if it exists. Other code adds that in when needed.
		if (spoolpath[path_len-1] == '/') {
			spoolpath[path_len-1] = '\0';
		}
	}
	if (!maybe_create_spool_dir(spoolpath)) {
		fprintf(stderr, "Error while setting up spool directory \"%s\".\n", spoolpath);
		if (dne_fail) {
			fprintf(stderr, "Please run `mkdir %s` and start rtpengine again.\n", spoolpath);
			exit(-1);
		}
	} else {
		spooldir = strdup(spoolpath);
	}
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
int maybe_create_spool_dir(char *spoolpath) {
	struct stat info;
	int spool_good = TRUE;

	if (stat(spoolpath, &info) != 0) {
		fprintf(stderr, "Spool directory \"%s\" does not exist.\n", spoolpath);
		spool_good = FALSE;
	} else if (!S_ISDIR(info.st_mode)) {
		fprintf(stderr, "Spool file exists, but \"%s\" is not a directory.\n", spoolpath);
		spool_good = FALSE;
	} else {
		// Spool directory exists. Make sure it has inner directories.
		int path_len = strlen(spoolpath);
		char meta_path[path_len + 10];
		char rec_path[path_len + 7];
		snprintf(meta_path, path_len + 10, "%s/metadata", spoolpath);
		snprintf(rec_path, path_len + 7, "%s/pcaps", spoolpath);

		if (stat(meta_path, &info) != 0) {
			fprintf(stdout, "Creating metadata directory \"%s\".\n", meta_path);
			mkdir(meta_path, 0660);
		} else if(!S_ISDIR(info.st_mode)) {
			fprintf(stderr, "metadata file exists, but \"%s\" is not a directory.\n", meta_path);
			spool_good = FALSE;
		}

		if (stat(rec_path, &info) != 0) {
			fprintf(stdout, "Creating pcaps directory \"%s\".\n", rec_path);
			mkdir(rec_path, 0660);
		} else if(!S_ISDIR(info.st_mode)) {
			fprintf(stderr, "pcaps file exists, but \"%s\" is not a directory.\n", rec_path);
			spool_good = FALSE;
		}
	}

	return spool_good;
}

/**
 * Create a call metadata file in a temporary location.
 * Attaches the filepath and the file pointer to the call struct.
 */
str *meta_setup_file(struct recording *recording) {
	if (spooldir == NULL) {
		// No spool directory was created, so we cannot have metadata files.
		return NULL;
	}
	else {
		int rand_bytes = 16;
		str *meta_filepath = malloc(sizeof(str));
		// Initially file extension is ".tmp". When call is over, it changes to ".txt".
		char *path_chars = rand_affixed_str(rand_bytes, "/tmp/rtpengine-meta-", ".tmp");
		meta_filepath = str_init(meta_filepath, path_chars);
		recording->meta_filepath = meta_filepath;
		FILE *mfp = fopen(meta_filepath->s, "w");
		if (mfp == NULL) {
			ilog(LOG_ERROR, "Could not open metadata file: %s", meta_filepath->s);
			free(recording->meta_filepath->s);
			free(recording->meta_filepath);
			recording->meta_filepath = NULL;
		}
		recording->meta_fp = mfp;
		ilog(LOG_INFO, "Wrote metadata file to temporary path: %s", meta_filepath->s);
		return meta_filepath;
	}
}

/**
 * Writes metadata to metafile, closes file, and renames it to finished location.
 * Returns non-zero for failure.
 */
int meta_finish_file(struct call *call) {
	struct recording *recording = call->recording;
	int return_code = 0;

	if (recording != NULL && recording->meta_fp != NULL) {
		// Print start timestamp and end timestamp
		// YYYY-MM-DDThh:mm:ss
		time_t start = 0, end = 0;
		char timebuffer[20];
		struct tm *timeinfo;
		if (call->monologues.head) {
			struct call_monologue *ml;
			ml = call->monologues.head->data;
			start = ml->started.tv_sec;
			end = g_now.tv_sec;
		}
		timeinfo = localtime(&start);
		strftime(timebuffer, 20, "%FT%T", timeinfo);
		fprintf(recording->meta_fp, "\n%s\n", timebuffer);
		timeinfo = localtime(&end);
		strftime(timebuffer, 20, "%FT%T", timeinfo);
		fprintf(recording->meta_fp, "%s\n", timebuffer);

		// Print metadata
		fprintf(recording->meta_fp, "\n%s\n", recording->metadata->s);
		fclose(recording->meta_fp);

		// Get the filename (in between its directory and the file extension)
		// and move it to the finished file location.
		// Rename extension to ".txt".
		int fn_len;
		char *meta_filename = strrchr(recording->meta_filepath->s, '/');
		char *meta_ext = NULL;
		if (meta_filename == NULL) {
			meta_filename = recording->meta_filepath->s;
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
		return_code = return_code || rename(recording->meta_filepath->s, new_metapath);
		if (return_code != 0) {
			ilog(LOG_ERROR, "Could not move metadata file \"%s\" to \"%s/metadata/\"",
					 recording->meta_filepath->s, spooldir);
		} else {
			ilog(LOG_INFO, "Moved metadata file \"%s\" to \"%s/metadata\"",
					 recording->meta_filepath->s, spooldir);
		}
	}
	if (recording != NULL && recording->meta_filepath != NULL) {
		free(recording->meta_filepath->s);
		free(recording->meta_filepath);
	}

	return return_code;
}

/**
 * Generate a random PCAP filepath to write recorded RTP stream.
 */
str *recording_setup_file(struct recording *recording) {
	str *recording_path = NULL;
	if (spooldir != NULL
      && recording != NULL
	    && recording->recording_pd == NULL && recording->recording_pdumper == NULL) {
		int rand_bytes = 16;
		int rec_path_len = strlen(spooldir) + 8; // spool directory path + "/pcaps/"
		char rec_path[rec_path_len];
		snprintf(rec_path, rec_path_len, "%s/pcaps/", spooldir);
		char *path_chars = rand_affixed_str(rand_bytes, rec_path, ".pcap");

		recording_path = malloc(sizeof(str));
		recording_path = str_init(recording_path, path_chars);
		recording->recording_path = recording_path;

		recording->recording_pd = pcap_open_dead(DLT_RAW, 65535);
		recording->recording_pdumper = pcap_dump_open(recording->recording_pd, path_chars);
		if (recording->recording_pdumper == NULL) {
			pcap_close(recording->recording_pd);
			recording->recording_pd = NULL;
			ilog(LOG_INFO, "Failed to write recording file: %s", recording_path->s);
		} else {
			ilog(LOG_INFO, "Writing recording file: %s", recording_path->s);
		}
	} else if (recording != NULL) {
		recording->recording_path = NULL;
		recording->recording_pd = NULL;
		recording->recording_pdumper = NULL;
	}

	return recording_path;
}

/**
 * Flushes PCAP file, closes the dumper and descriptors, and frees object memory.
 */
void recording_finish_file(struct recording *recording) {
	if (recording->recording_pdumper != NULL) {
		pcap_dump_flush(recording->recording_pdumper);
		pcap_dump_close(recording->recording_pdumper);
		free(recording->recording_path->s);
		free(recording->recording_path);
	}
	if (recording->recording_pd != NULL) {
		pcap_close(recording->recording_pd);
	}
}

/**
 * Write out a PCAP packet with payload string.
 * A fair amount extraneous of packet data is spoofed.
 */
void stream_pcap_dump(pcap_dumper_t *pdumper, str *s) {
	// Wrap RTP in fake UDP packet header
	// Right now, we spoof it all
	u_int16_t udp_len = ((u_int16_t)s->len) + 8;
	u_int16_t udp_header[4];
	udp_header[0] = htons(5028); // source port
	udp_header[1] = htons(50116); // destination port
	udp_header[2] = htons(udp_len); // packet length
	udp_header[3] = 0; // checksum

	// Wrap RTP in fake IP packet header
	u_int8_t ip_header[20];
	u_int16_t *ip_total_length = (u_int16_t*)(ip_header + 2);
	u_int32_t *ip_src_addr = (u_int32_t*)(ip_header + 12);
	u_int32_t *ip_dst_addr = (u_int32_t*)(ip_header + 16);
	memset(ip_header, 0, 20);
	ip_header[0] = 4 << 4; // IP version - 4 bits
	ip_header[0] = ip_header[0] | 5; // Internet Header Length (IHL) - 4 bits
	ip_header[1] = 0; // DSCP - 6 bits
	ip_header[1] = 0; // ECN - 2 bits
	*ip_total_length = htons(udp_len + 20); // Total Length (entire packet size) - 2 bytes
	ip_header[4] = 0; ip_header[5] = 0 ; // Identification - 2 bytes
	ip_header[6] = 0; // Flags - 3 bits
	ip_header[7] = 0; // Fragment Offset - 13 bits
	ip_header[8] = 64; // TTL - 1 byte
	ip_header[9] = 17; // Protocol (defines protocol in data portion) - 1 byte
	ip_header[10] = 0; ip_header[11] = 0; // Header Checksum - 2 bytes
	*ip_src_addr = htonl(2130706433); // Source IP (set to localhost) - 4 bytes
	*ip_dst_addr = htonl(2130706433); // Destination IP (set to localhost) - 4 bytes

	// Set up PCAP packet header
	struct pcap_pkthdr header;
	ZERO(header);
	header.ts = g_now;
	header.caplen = s->len + 28;
	// This must be the same value we use in `pcap_open_dead`
	header.len = s->len + 28;

  // Copy all the headers and payload into a new string
	unsigned char pkt_s[*ip_total_length];
	memcpy(pkt_s, ip_header, 20);
	memcpy(pkt_s + 20, udp_header, 8);
	memcpy(pkt_s + 28, s->s, s->len);

	// Write the packet to the PCAP file
	// Casting quiets compiler warning.
	pcap_dump((unsigned char *)pdumper, &header, (unsigned char *)pkt_s);
}
