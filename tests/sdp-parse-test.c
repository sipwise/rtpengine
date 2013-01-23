/* gcc -Wall -g `pkg-config glib-2.0 --cflags --libs` sdp-parse-test.c ../daemon/sdp.c -o sdp-parse-test */
#include <glib.h>
#include <stdio.h>
#include <string.h>

#include "../daemon/sdp.h"

int main() {
	char sdp[] = "v=0\r\no=root 25669 25669 IN IP4 192.168.51.133\r\ns=session\r\nc=IN IP4 192.168.51.133\r\nt=0 0\r\nm=audio 30018 RTP/AVP 8 0 101\r\na=rtpmap:8 PCMA/8000\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-16\r\na=silenceSupp:off - - - -\r\na=ptime:20\r\na=sendrecv\r\na=nortpproxy:yes\r\n";
	int len = strlen(sdp);
	int i;
	GQueue ret = G_QUEUE_INIT;

	i = sdp_parse(sdp, len, &ret);
	if (i)
		return 0;

	printf("%i stream(s)\n", g_queue_get_length(&ret));

	return 0;
}
