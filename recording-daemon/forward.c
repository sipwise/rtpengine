#include "forward.h"
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include "main.h"
#include "log.h"

void start_forwarding_capture(metafile_t *mf, char *meta_info) {
	int sock;
	struct sockaddr_un addr;

	if (mf->forward_fd >= 0) {
		ilog(LOG_INFO, "Connection already established");
		return;
	}

#ifdef SOCK_SEQPACKET
	if ((sock = socket(AF_UNIX, SOCK_SEQPACKET, 0)) == -1) {
#else
	if ((sock = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1) {
#endif
		ilog(LOG_ERR, "Error creating socket: %s", strerror(errno));
		return;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, forward_to, sizeof(addr.sun_path) - 1);

	if (fcntl(sock, F_SETFL, O_NONBLOCK) < 0) {
		ilog(LOG_ERR, "Error setting socket non-blocking: %s", strerror(errno));
		goto err;
	}

	if (connect(sock, (struct sockaddr*) &addr, sizeof(addr)) == -1) {
		ilog(LOG_ERR, "Error connecting to socket %s : %s", addr.sun_path,
				strerror(errno));
		goto err;
	}

	if (send(sock, meta_info, strlen(meta_info), 0) == -1) {
		ilog(LOG_ERR, "Error sending meta info: %s. Call will not be forwarded", strerror(errno));
		goto err;
	}

	mf->forward_fd = sock;
	return;
err:
	close(sock);
}

int forward_packet(metafile_t *mf, unsigned char *buf, unsigned len) {

	if (mf->forward_fd == -1) {
		ilog(LOG_ERR,
				"Trying to send packets, but connection not initialized!");
		goto err;
	}

	if (send(mf->forward_fd, buf, len, 0) == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			ilog(LOG_DEBUG, "Dropping packet since call would block");
		else
			ilog(LOG_ERR, "Error sending: %s", strerror(errno));
		goto err;
	}

	return 0;

err:
	return -1;
}

