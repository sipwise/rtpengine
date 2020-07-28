
#include <str.h>
#include <zlib.h>
#include <string.h>
#include <errno.h>

#include "log.h"
#include "udp_listener.h"
#include "str.h"
#include "compress.h"

#define RTPENGINE_ZLIB_WINDOWBITS 15
#define RTPENGINE_ZLIB_ENABLE_ZLIB_GZIP 32

static void init_stream(z_stream *stream)
{
	stream->zalloc = Z_NULL;
	stream->zfree = Z_NULL;
	stream->opaque = Z_NULL;
}

// compress_data compress the data of the given length.
// returns compressed buffer length and replace the original buffer.
int compress_data(char *buf, int len, char *out_buf, int out_len) {
	uLong comp_len = compressBound(len);
	int ret;

	if (out_len < comp_len) {
		ilog(LOG_ERROR,"The given outbuf is not enough for compressed message\n");
		return -1;
	}

	ret = compress2((Bytef *)out_buf, &comp_len, (Bytef *)buf, len, Z_BEST_COMPRESSION);
	if (ret != Z_OK) {
		ilog(LOG_ERROR,"Could not compress the message. err: %d\n", ret);
		return -1;
	}

	return comp_len;
}

// uncompress_data uncompress the compressed data with given length.
// it compare the first byte to check the compressed data or not.
int uncompress_data(char *buf, int len, char *buf_tmp, int buf_size) {
	z_stream stream;
	int ret;

	init_stream(&stream);
	ret = inflateInit2(&stream, RTPENGINE_ZLIB_WINDOWBITS | RTPENGINE_ZLIB_ENABLE_ZLIB_GZIP);
	if (ret != Z_OK) {
		ilog(LOG_ERROR,"Could not initiate zstream. err: %d\n", ret);
		return -1;
	}

	stream.next_in = (Bytef *)buf;
	stream.avail_in = len;

	memset(buf_tmp, 0x00, buf_size);
	stream.next_out = (Bytef *)buf_tmp;
	stream.avail_out = buf_size - 1;

	ret = inflate(&stream, Z_NO_FLUSH);
	if (ret != Z_OK && ret != Z_STREAM_END) {
		inflateEnd(&stream);
		ilog(LOG_ERROR,"Could not uncompress the data correctly. err: %d\n", ret);
		return -1;
	}

	memcpy(buf, buf_tmp, buf_size);
	ret = stream.total_out;
	inflateEnd(&stream);

	return ret;
}
