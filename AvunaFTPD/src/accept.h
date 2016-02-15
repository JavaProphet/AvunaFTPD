/*
 * accept.h
 *
 *  Created on: Nov 18, 2015
 *      Author: root
 */

#ifndef ACCEPT_H_
#define ACCEPT_H_

#include "config.h"
#include "collection.h"
#include <sys/socket.h>
#include "work.h"
#include <gnutls/gnutls.h>
#include <netinet/ip6.h>

struct accept_param {
		int server_fd;
		int port;
		struct cnode* config;
		int works_count;
		struct work_param** works;
		struct logsess* logsess;
		struct cert* cert;
};

struct conn {
		int fd;
		struct sockaddr_in6 addr;
		socklen_t addrlen;
		unsigned char* readBuffer;
		size_t readBuffer_size;
		size_t readBuffer_checked;
		unsigned char* writeBuffer;
		size_t writeBuffer_size;
		int tls;
		int handshaked;
		gnutls_session_t session;
		int state;
		char* user;
		struct user* auth;
		char* cwd;
		size_t skip;
		int kwr;
		int sendfd;
		int pasv;
};

void run_accept(struct accept_param* param);

#endif /* ACCEPT_H_ */
