/*
 * accept.c
 *
 *  Created on: Nov 18, 2015
 *      Author: root
 */
#define _GNU_SOURCE
#include "accept.h"
#include "util.h"
#include <sys/socket.h>
#include <errno.h>
#include <stdio.h>
#include "xstring.h"
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <stdlib.h>
#include <poll.h>
#include "work.h"
#include <unistd.h>
#include "tls.h"
#include "version.h"
#include <sys/types.h>

//TODO: SNI?

void run_accept(struct accept_param* param) {
	static int one = 1;
	static unsigned char onec = 1;
	struct timeval timeout;
	timeout.tv_sec = 60;
	timeout.tv_usec = 0;
	struct pollfd spfd;
	spfd.events = POLLIN;
	spfd.revents = 0;
	spfd.fd = param->server_fd;
	static char* header = "220 Avuna " DAEMON_NAME " " VERSION "\r\n";
	size_t headerlen = strlen(header);
	while (1) {
		struct conn* c = xmalloc(sizeof(struct conn));
		memset(&c->addr, 0, sizeof(struct sockaddr_in6));
		c->addrlen = sizeof(struct sockaddr_in6);
		c->readBuffer = NULL;
		c->readBuffer_size = 0;
		c->readBuffer_checked = 0;
		c->writeBuffer = NULL;
		c->writeBuffer_size = 0;
		c->handshaked = 0;
		c->state = 0;
		c->user = NULL;
		c->auth = NULL;
		c->cwd = NULL;
		c->skip = 0;
		c->kwr = 0;
		c->sendfd = -1;
		c->pasv = 0;
		c->twr = 0;
		c->prot = 'c';
		c->ren = NULL;
		if (param->cert != NULL) {
			c->session = SSL_new(param->cert->ctx);
			SSL_set_mode(c->session, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE);
			SSL_set_accept_state(c->session);
			c->tls = 1;
		} else {
			c->tls = 0;
		}
		if (poll(&spfd, 1, -1) < 0) {
			printf("Error while polling server: %s\n", strerror(errno));
			if (param->cert != NULL) SSL_free(c->session);			
			xfree(c);
			continue;
		}
		if ((spfd.revents ^ POLLIN) != 0) {
			errlog(param->logsess, "Error after polling server: %i (poll revents), closing server!", spfd.revents);			
			if (param->cert != NULL) SSL_free(c->session);			
			xfree(c);
			close(param->server_fd);
			break;
		}
		spfd.revents = 0;
		int cfd = accept4(param->server_fd, &c->addr, &c->addrlen, SOCK_CLOEXEC);
		if (cfd < 0) {
			if (param->cert != NULL) SSL_free(c->session);			
			if (errno == EAGAIN) continue;
			printf("Error while accepting client: %s\n", strerror(errno));
			xfree(c);
			continue;
		}
		c->fd = cfd;
		if (setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, sizeof(timeout))) printf("Setting recv timeout failed! %s\n", strerror(errno));
		if (setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, (char *) &timeout, sizeof(timeout))) printf("Setting send timeout failed! %s\n", strerror(errno));
		if (setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, (void *) &one, sizeof(one))) printf("Setting TCP_NODELAY failed! %s\n", strerror(errno));
		if (fcntl(cfd, F_SETFL, fcntl(cfd, F_GETFL) | O_NONBLOCK) < 0) {
			printf("Setting O_NONBLOCK failed! %s, this error cannot be recovered, closing client.\n", strerror(errno));
			close(cfd);
			continue;
		}
		if (param->cert != NULL) {
			SSL_set_fd(c->session, c->fd);
			int r = SSL_accept(c->session);
			if (r == 1) {
				c->handshaked = 1;
			} else if (r == 2) {
				SSL_free(c->session);
				close(c->fd);
				xfree(c);
				continue;
			} else {
				int err = SSL_get_error(c->session, r);
				if (err == SSL_ERROR_WANT_READ) c->ssl_nextdir = 1;
				else if (err == SSL_ERROR_WANT_WRITE) c->ssl_nextdir = 2;
				else {
					SSL_free(c->session);
					close(c->fd);
					xfree(c);
					continue;
				}
			}
		}
		if (param->cert != NULL && param->cert->isDummy && SSL_get_SSL_CTX(c->session) == param->cert->ctx) {
			SSL_free(c->session);
			close(c->fd);
			xfree(c);
			continue;
		}
		struct work_param* work = param->works[rand() % param->works_count];
		c->writeBuffer = xmalloc(headerlen);
		memcpy(c->writeBuffer, header, headerlen);
		c->writeBuffer_size = headerlen;
		if (add_collection(work->conns, c)) { // TODO: send to lowest load, not random
			xfree(c->writeBuffer);
			if (errno == EINVAL) {
				printf("Too many open connections! Closing client.\n");
			} else {
				printf("Collection failure! Closing client. %s\n", strerror(errno));
			}
			close(cfd);
			continue;
		}
		if (write(work->pipes[1], &onec, 1) < 1) {
			printf("Failed to write to wakeup pipe! Things may slow down. %s\n", strerror(errno));
		}
	}
}
