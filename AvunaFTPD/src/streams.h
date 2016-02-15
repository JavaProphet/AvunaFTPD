/*
 * streams.h
 *
 *  Created on: Nov 17, 2015
 *      Author: root
 */

#ifndef STREAMS_H_
#define STREAMS_H_

#include <gnutls/gnutls.h>

size_t readLine(int fd, char* line, size_t len);

size_t writeLine(int fd, char* line, size_t len);

ssize_t writeLineSSL(gnutls_session_t session, char* line, size_t len);

#endif /* STREAMS_H_ */
