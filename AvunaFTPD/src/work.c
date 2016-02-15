/*
 * work.c
 *
 *  Created on: Nov 18, 2015
 *      Author: root
 */

#include "work.h"
#include "accept.h"
#include "xstring.h"
#include <errno.h>
#include <sys/socket.h>
#include <poll.h>
#include <unistd.h>
#include <stdio.h>
#include <pthread.h>
#include "collection.h"
#include "util.h"
#include "streams.h"
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include "globals.h"
#include <time.h>
#include <sys/wait.h>
#include "version.h"
#include <sys/stat.h>

char* realpathext(char* path) {
	const char* orp = path;
	path = xstrdup(path, 0);
	ssize_t pki = -1;
	char* rp = NULL;
	while (rp == NULL) {
		rp = realpath(path, NULL);
		if (rp == NULL) {
			if (errno != ENOENT) {
				xfree(path);
				return NULL;
			}
			char* rch = strrchr(path, '/');
			if (rch == NULL) return NULL;
			rch[0] = 0;
			if (strlen(path) == 0) return NULL;
			pki = rch - path;
		}
	}
	xfree(path);
	if (pki < 0) return rp;
	size_t rpl = strlen(rp);
	rp = xrealloc(rp, rpl + pki + 1);
	memcpy(rp + pki, orp + pki, strlen(orp + pki) + 1);
	return rp;
}

char* calcChroot(char* root, char* cwd, char* file) {
	//size_t cl = strlen(cwd);
	//if (cl < 0) return NULL;
	size_t fl = strlen(file);
	char* base = (fl == 0 || file[0] != '/') ? cwd : root;
	size_t bl = strlen(base);
	if (bl < 0) return NULL;
	char* fp = xmalloc(bl + fl + 8);
	size_t ci = 0;
	memcpy(fp + ci, base, bl);
	ci += bl;
	if (fl == 0) {
		fp[ci] = 0;
		char* rp = realpathext(fp);
		xfree(fp);
		fp = rp;
		goto check;
	}
	if (fp[ci - 1] != '/') {
		fp[ci] = '/';
		ci++;
	}
	int efs = (file[0] == '/' ? 1 : 0);
	memcpy(fp + ci, file + efs, fl - efs);
	ci += fl - efs;
	fp[ci++] = 0;
	char* rp = realpathext(fp);
	xfree(fp);
	fp = rp;
	check: ;
	if (!startsWith(fp, root)) {
		xfree(fp);
		return NULL;
	} else {
		return fp;
	}
}

void closeConn(struct work_param* param, struct conn* conn) {
	if (conn->tls) {
		if (conn->handshaked) {
			gnutls_bye(conn->session, GNUTLS_SHUT_RDWR);
		}
		gnutls_deinit(conn->session);
	}
	if (conn->user) xfree(conn->user);
	if (conn->cwd) xfree(conn->cwd);
	close(conn->fd);
	if (rem_collection(param->conns, conn)) {
		errlog(param->logsess, "Failed to delete connection properly! This is bad!");
	}
	if (conn->readBuffer) xfree(conn->readBuffer);
	if (conn->writeBuffer) xfree(conn->writeBuffer);
	xfree(conn);
}

ssize_t writeFTPLine(struct conn* conn, int code, char* line) {
	size_t l = strlen(line);
	char resp[32];
	snprintf(resp, 32, "%i ", code);
	size_t rl = strlen(resp);
	if (conn->writeBuffer == NULL) {
		conn->writeBuffer = xmalloc(l + rl + 2);
		conn->writeBuffer_size = 0;
	} else {
		conn->writeBuffer = xrealloc(conn->writeBuffer, conn->writeBuffer_size + l + rl + 2);
	}
	char* fl = conn->writeBuffer + conn->writeBuffer_size;
	memcpy(fl, resp, rl);
	memcpy(fl + rl, line, l);
	fl[l + rl] = '\r';
	fl[l + rl + 1] = '\n';
	conn->writeBuffer_size += l + rl + 2;
	return l + rl + 2;
}

ssize_t writeFTPBMLine(struct conn* conn, int code, char* line) {
	size_t l = strlen(line);
	char resp[32];
	snprintf(resp, 32, "%i-", code);
	size_t rl = strlen(resp);
	if (conn->writeBuffer == NULL) {
		conn->writeBuffer = xmalloc(l + rl + 2);
		conn->writeBuffer_size = 0;
	} else {
		conn->writeBuffer = xrealloc(conn->writeBuffer, conn->writeBuffer_size + l + rl + 2);
	}
	char* fl = conn->writeBuffer + conn->writeBuffer_size;
	memcpy(fl, resp, rl);
	memcpy(fl + rl, line, l);
	fl[l + rl] = '\r';
	fl[l + rl + 1] = '\n';
	conn->writeBuffer_size += l + rl + 2;
	return l + rl + 2;
}

ssize_t writeFTPMMLine(struct conn* conn, char* line) {
	size_t l = strlen(line);
	if (conn->writeBuffer == NULL) {
		conn->writeBuffer = xmalloc(l + 3);
		conn->writeBuffer_size = 0;
	} else {
		conn->writeBuffer = xrealloc(conn->writeBuffer, conn->writeBuffer_size + l + 3);
	}
	char* fl = conn->writeBuffer + conn->writeBuffer_size;
	fl[0] = ' ';
	memcpy(fl + 1, line, l);
	fl[l + 1] = '\r';
	fl[l + 2] = '\n';
	conn->writeBuffer_size += l + 3;
	return l + 3;
}

int canStat(uid_t uid, gid_t gid, uid_t fuid, uid_t fgid, mode_t mode) {
	if (uid == fuid && (mode & S_IRUSR) == S_IRUSR) return 1;
	else if (gid == fgid && (mode & S_IRGRP) == S_IRGRP) return 1;
	else if ((mode & S_IROTH) == S_IROTH) return 1;
	return 0;
}

int canWrite(uid_t uid, gid_t gid, uid_t fuid, uid_t fgid, mode_t mode) {
	if (uid == fuid && (mode & S_IWUSR) == S_IWUSR) return 1;
	else if (gid == fgid && (mode & S_IWGRP) == S_IWGRP) return 1;
	else if ((mode & S_IWOTH) == S_IWOTH) return 1;
	return 0;
}

int canStatFile(char* file, uid_t uid, gid_t gid) {
	struct stat st;
	if (lstat(file, &st) != 0) return 0;
	return canStat(uid, gid, st.st_uid, st.st_gid, st.st_mode);
}

int canWriteFile(char* file, uid_t uid, gid_t gid) {
	struct stat st;
	if (lstat(file, &st) != 0) return 0;
	return canWrite(uid, gid, st.st_uid, st.st_gid, st.st_mode);
}

int checkpid(pid_t pid) {
	int st = 0;
	pid_t p = waitpid(pid, &st, WNOHANG);
	return p == 0 ? -1 : st;
}

void handleLine(int wfd, struct timespec* stt, struct conn* conn, struct work_param* param, char* line) {
	char* cmd = NULL;
	line = trim(line);
	if (conn->state != 101) {
		cmd = line;
		line = strchr(line, ' ');
		if (line != NULL) {
			line[0] = 0;
			line++;
		} else {
			line = cmd + strlen(cmd);
		}
	}
	int recog = 0;
	if (streq_nocase(cmd, "quit")) {
		writeFTPLine(conn, 221, "Goodbye.");
		conn->kwr = 1;
	} else if (conn->state == 0) {
		if (streq_nocase(cmd, "user")) {
			conn->user = xstrdup(line, 0);
			conn->state = 1;
			recog = 1;
			writeFTPLine(conn, 331, "Please specify the password.");
		} else if (streq_nocase(cmd, "acct")) {
			writeFTPLine(conn, 502, "ACCT not implemented.");
			recog = 1;
		}
	} else if (conn->state == 1) {
		if (streq_nocase(cmd, "pass")) {
			pthread_rwlock_rdlock(&param->users->lock);
			for (size_t x = 0; x < param->users->user_count; x++) {
				if (streq_nocase(param->users->users[x]->username, conn->user)) {
					conn->auth = streq(param->users->users[x]->password, line) ? param->users->users[x] : NULL;
					break;
				}
			}
			pthread_rwlock_unlock(&param->users->lock);
			if (conn->auth) { // do proper auth
				conn->state = 2;
				conn->cwd = xstrdup(conn->auth->root, 0);
				writeFTPLine(conn, 230, "Login successful.");
			} else {
				writeFTPLine(conn, 531, "Login incorrect.");
				conn->state = 0;
			}
			recog = 1;
		}
	} else if (conn->state == 2) {
		if (streq_nocase(cmd, "syst")) {
			writeFTPLine(conn, 215, "UNIX Type: L8.");
			recog = 1;
		} else if (streq_nocase(cmd, "feat")) {
			writeFTPBMLine(conn, 211, "Extensions supported:");
			writeFTPMMLine(conn, "MDTM");
			writeFTPMMLine(conn, "PASV");
			writeFTPMMLine(conn, "SIZE");
			writeFTPMMLine(conn, "UTF8");
			writeFTPLine(conn, 211, "End");
			recog = 1;
		} else if (streq_nocase(cmd, "pwd")) {
			char* path = calcChroot(conn->auth->root, conn->cwd, "");
			if (path) {
				size_t pl = strlen(path);
				if (startsWith(path, conn->auth->root)) {
					size_t rs = strlen(conn->auth->root);
					int ss = endsWith(conn->auth->root, "/");
					memmove(path, path + rs - ss, (pl + 1) - rs + ss);
					pl -= rs - ss;
				}
				path = xrealloc(path, pl + 3);
				memmove(path + 1, path, pl);
				path[0] = '"';
				path[pl + 1] = '"';
				path[pl + 2] = 0;
				writeFTPLine(conn, 257, path);
				xfree(path);
			} else {
				writeFTPLine(conn, 550, "Failed to open directory.");
			}
			recog = 1;
		} else if (streq_nocase(cmd, "rein")) {
			writeFTPLine(conn, 502, "REIN not implemented.");
			recog = 1;
		} else if (streq_nocase(cmd, "smnt")) {
			writeFTPLine(conn, 502, "SMNT not implemented.");
			recog = 1;
		} else if (streq_nocase(cmd, "opts")) {
			if (streq_nocase(line, "utf8 on")) {
				writeFTPLine(conn, 200, "Always in UTF8 mode.");
			} else {
				writeFTPLine(conn, 201, "Option not understood.");
			}
			recog = 1;
		} else if (streq_nocase(cmd, "type")) {
			if (streq_nocase(line, "a")) {
				writeFTPLine(conn, 200, "Switching to ASCII mode.");
			} else if (streq_nocase(line, "i") || streq_nocase(line, "l")) {
				writeFTPLine(conn, 200, "Switching to Binary mode.");
			} else {
				writeFTPLine(conn, 500, "Unrecognised TYPE command.");
			}
			recog = 1;
		} else if (streq_nocase(cmd, "pasv")) { //TODO EPSV/EPRT
			if (conn->sendfd >= 0) close(conn->sendfd);
			conn->sendfd = socket(PF_INET, SOCK_STREAM, 0);
			struct sockaddr_in sin;
			sin.sin_family = AF_INET;
			sin.sin_addr.s_addr = INADDR_ANY;
			sin.sin_port = 0;
			if (conn->sendfd < 0 || bind(conn->sendfd, (struct sockaddr*) &sin, sizeof(sin)) < 0 || listen(conn->sendfd, 1) < 0) {
				errlog(param->logsess, "Error creating socket for passive connection: %s.", strerror(errno));
				writeFTPLine(conn, 500, "Failed to create PASV connection.");
				if (conn->sendfd >= 0) {
					conn->sendfd = -1;
					close(conn->sendfd);
				}
				return;
			}
			char pasv[49];
			pasv[48] = 0;
			memcpy(pasv, "Entering Passive Mode (", 23);
			struct in_addr loop;
			inet_aton("127.0.0.1", &loop);
			inet_ntop(AF_INET, &loop, pasv + 23, 16);
			size_t cs = strlen(pasv);
			for (int i = 23; i < cs; i++) {
				if (pasv[i] == '.') pasv[i] = ',';
			}
			pasv[cs++] = ',';
			socklen_t len = sizeof(sin);
			getsockname(conn->sendfd, (struct sockaddr *) &sin, &len);
			snprintf(pasv + cs, 48 - cs, "%i,%i).", sin.sin_port & 0xFF, sin.sin_port >> 8);
			writeFTPLine(conn, 227, pasv);
			conn->pasv = 1;
			recog = 1;
		} else if (streq_nocase(cmd, "port")) {
			recog = 1;
		} else if (streq_nocase(cmd, "mdtm")) {
			char date[32];
			date[31] = 0;
			char* path = calcChroot(conn->auth->root, conn->cwd, line);
			if (!path || !canStatFile(path, conn->auth->uid, conn->auth->gid)) {
				writeFTPLine(conn, 550, "Failed to open file.");
				return;
			}
			struct stat st;
			if (!stat(path, &st)) {
				time_t tt;
				tt = st.st_mtime;
				strftime(date, 32, "%Y%m%d%H%M%S", localtime(&tt));
				writeFTPLine(conn, 213, date);
			} else {
				writeFTPLine(conn, 550, "Failed to open file.");
			}
			recog = 1;
		} else if (streq_nocase(cmd, "cdup")) {
			char* path = calcChroot(conn->auth->root, conn->cwd, "..");
			if (!path || access(path, R_OK)) {
				writeFTPLine(conn, 550, "Failed to open directory.");
				return;
			}
			struct stat st;
			if (lstat(path, &st) < 0 || !S_ISDIR(st.st_mode)) {
				writeFTPLine(conn, 550, "Failed to open directory.");
				return;
			}
			conn->cwd = path;
			writeFTPLine(conn, 250, "Directory successfully changed.");
			recog = 1;
		} else if (streq_nocase(cmd, "cwd")) {
			char* path = calcChroot(conn->auth->root, conn->cwd, line);
			if (!path || access(path, R_OK)) {
				writeFTPLine(conn, 550, "Failed to open directory.");
				return;
			}
			struct stat st;
			if (lstat(path, &st) < 0 || !S_ISDIR(st.st_mode)) {
				writeFTPLine(conn, 550, "Failed to open directory.");
				return;
			}
			conn->cwd = path;
			writeFTPLine(conn, 250, "Directory successfully changed.");
			recog = 1;
		} else if (streq_nocase(cmd, "stor")) {
			if (conn->sendfd < 0) {
				writeFTPLine(conn, 425, "Use PORT or PASV first.");
				return;
			}
			char* chr = calcChroot(conn->auth->root, conn->cwd, line);
			if (chr == NULL) {
				writeFTPLine(conn, 550, "Failed to open file.");
				return;
			}
			int cl = conn->pasv;
			char fds[32];
			snprintf(fds, 32, "%i", conn->sendfd);
			char uids[32];
			snprintf(uids, 32, "%i", conn->auth->uid);
			char gids[32];
			snprintf(gids, 32, "%i", conn->auth->gid);
			char pips[32];
			snprintf(pips, 32, "%i", param->pipes[1]);
			const char* mip = NULL;
			char tip[48];
			if (conn->addr.sin6_family == AF_INET) {
				struct sockaddr_in *sip4 = (struct sockaddr_in*) &conn->addr;
				mip = inet_ntop(AF_INET, &sip4->sin_addr, tip, 48);
			} else if (conn->addr.sin6_family == AF_INET6) {
				struct sockaddr_in6 *sip6 = (struct sockaddr_in6*) &conn->addr;
				if (memseq((unsigned char*) &sip6->sin6_addr, 10, 0) && memseq((unsigned char*) &sip6->sin6_addr + 10, 2, 0xff)) {
					mip = inet_ntop(AF_INET, ((unsigned char*) &sip6->sin6_addr) + 12, tip, 48);
				} else mip = inet_ntop(AF_INET6, &sip6->sin6_addr, tip, 48);
			} else if (conn->addr.sin6_family == AF_LOCAL) {
				mip = "UNIX";
			} else {
				mip = "UNKNOWN";
			}
			writeFTPLine(conn, 150, "Ok Send file contents.");
			pid_t frk = fork();
			if (frk == 0) {
				setenv(cl ? "AVFTPD_ACC_SERVER" : "AVFTPD_ACC_CLIENT", fds, 1);
				setenv("AVFTPD_COMMAND", "STOR", 1);
				setenv("AVFTPD_FILE", chr, 1);
				setenv("AVFTPD_UID", uids, 1);
				setenv("AVFTPD_GID", gids, 1);
				setenv("AVFTPD_WPIPE", pips, 1);
				setenv("AVFTPD_EXPECTED", mip, 1);
				execl(ourbinary, ourbinary, NULL);
			} else {
				int st = 0; // TODO: non blocking
				waitpid(frk, &st, 0);
				if (st == 0) {
					writeFTPLine(conn, 226, "Transfer complete.");
				} else {
					writeFTPLine(conn, 550, "Failed to open file.");
				}
			}
			recog = 1;
		} else if (streq_nocase(cmd, "stou")) {
			if (conn->sendfd < 0) {
				writeFTPLine(conn, 425, "Use PORT or PASV first.");
				return;
			}
			char* chr = calcChroot(conn->auth->root, conn->cwd, line);
			if (chr == NULL) {
				writeFTPLine(conn, 550, "Failed to open file.");
				return;
			}
			int cl = conn->pasv;
			char fds[32];
			snprintf(fds, 32, "%i", conn->sendfd);
			char uids[32];
			snprintf(uids, 32, "%i", conn->auth->uid);
			char gids[32];
			snprintf(gids, 32, "%i", conn->auth->gid);
			char pips[32];
			snprintf(pips, 32, "%i", param->pipes[1]);
			const char* mip = NULL;
			char tip[48];
			if (conn->addr.sin6_family == AF_INET) {
				struct sockaddr_in *sip4 = (struct sockaddr_in*) &conn->addr;
				mip = inet_ntop(AF_INET, &sip4->sin_addr, tip, 48);
			} else if (conn->addr.sin6_family == AF_INET6) {
				struct sockaddr_in6 *sip6 = (struct sockaddr_in6*) &conn->addr;
				if (memseq((unsigned char*) &sip6->sin6_addr, 10, 0) && memseq((unsigned char*) &sip6->sin6_addr + 10, 2, 0xff)) {
					mip = inet_ntop(AF_INET, ((unsigned char*) &sip6->sin6_addr) + 12, tip, 48);
				} else mip = inet_ntop(AF_INET6, &sip6->sin6_addr, tip, 48);
			} else if (conn->addr.sin6_family == AF_LOCAL) {
				mip = "UNIX";
			} else {
				mip = "UNKNOWN";
			}
			writeFTPLine(conn, 150, "Ok Send file contents.");
			pid_t frk = fork();
			if (frk == 0) {
				setenv(cl ? "AVFTPD_ACC_SERVER" : "AVFTPD_ACC_CLIENT", fds, 1);
				setenv("AVFTPD_COMMAND", "STOU", 1);
				setenv("AVFTPD_FILE", chr, 1);
				setenv("AVFTPD_UID", uids, 1);
				setenv("AVFTPD_GID", gids, 1);
				setenv("AVFTPD_WPIPE", pips, 1);
				setenv("AVFTPD_EXPECTED", mip, 1);
				execl(ourbinary, ourbinary, NULL);
			} else {
				int st = 0; // TODO: non blocking
				waitpid(frk, &st, 0);
				if (st == 0) {
					writeFTPLine(conn, 226, "Transfer complete.");
				} else {
					writeFTPLine(conn, 550, "Failed to open file.");
				}
			}
			recog = 1;
		} else if (streq_nocase(cmd, "appe")) {
			if (conn->sendfd < 0) {
				writeFTPLine(conn, 425, "Use PORT or PASV first.");
				return;
			}
			char* chr = calcChroot(conn->auth->root, conn->cwd, line);
			if (chr == NULL) {
				writeFTPLine(conn, 550, "Failed to open file.");
				return;
			}
			int cl = conn->pasv;
			char fds[32];
			snprintf(fds, 32, "%i", conn->sendfd);
			char uids[32];
			snprintf(uids, 32, "%i", conn->auth->uid);
			char gids[32];
			snprintf(gids, 32, "%i", conn->auth->gid);
			char pips[32];
			snprintf(pips, 32, "%i", param->pipes[1]);
			const char* mip = NULL;
			char tip[48];
			if (conn->addr.sin6_family == AF_INET) {
				struct sockaddr_in *sip4 = (struct sockaddr_in*) &conn->addr;
				mip = inet_ntop(AF_INET, &sip4->sin_addr, tip, 48);
			} else if (conn->addr.sin6_family == AF_INET6) {
				struct sockaddr_in6 *sip6 = (struct sockaddr_in6*) &conn->addr;
				if (memseq((unsigned char*) &sip6->sin6_addr, 10, 0) && memseq((unsigned char*) &sip6->sin6_addr + 10, 2, 0xff)) {
					mip = inet_ntop(AF_INET, ((unsigned char*) &sip6->sin6_addr) + 12, tip, 48);
				} else mip = inet_ntop(AF_INET6, &sip6->sin6_addr, tip, 48);
			} else if (conn->addr.sin6_family == AF_LOCAL) {
				mip = "UNIX";
			} else {
				mip = "UNKNOWN";
			}
			writeFTPLine(conn, 150, "Ok Send file contents.");
			pid_t frk = fork();
			if (frk == 0) {
				setenv(cl ? "AVFTPD_ACC_SERVER" : "AVFTPD_ACC_CLIENT", fds, 1);
				setenv("AVFTPD_COMMAND", "APPE", 1);
				setenv("AVFTPD_FILE", chr, 1);
				setenv("AVFTPD_UID", uids, 1);
				setenv("AVFTPD_GID", gids, 1);
				setenv("AVFTPD_WPIPE", pips, 1);
				setenv("AVFTPD_EXPECTED", mip, 1);
				execl(ourbinary, ourbinary, NULL);
			} else {
				int st = 0; // TODO: non blocking
				waitpid(frk, &st, 0);
				if (st == 0) {
					writeFTPLine(conn, 226, "Transfer complete.");
				} else {
					writeFTPLine(conn, 550, "Failed to open file.");
				}
			}
			recog = 1;
		} else if (streq_nocase(cmd, "list")) {
			if (conn->sendfd < 0) {
				writeFTPLine(conn, 425, "Use PORT or PASV first.");
				return;
			}
			char* chr = calcChroot(conn->auth->root, conn->cwd, line);
			if (chr == NULL || access(chr, R_OK)) {
				writeFTPLine(conn, 550, "Failed to open file.");
				return;
			}
			int cl = conn->pasv;
			char fds[32];
			snprintf(fds, 32, "%i", conn->sendfd);
			char uids[32];
			snprintf(uids, 32, "%i", conn->auth->uid);
			char gids[32];
			snprintf(gids, 32, "%i", conn->auth->gid);
			char pips[32];
			snprintf(pips, 32, "%i", param->pipes[1]);
			const char* mip = NULL;
			char tip[48];
			if (conn->addr.sin6_family == AF_INET) {
				struct sockaddr_in *sip4 = (struct sockaddr_in*) &conn->addr;
				mip = inet_ntop(AF_INET, &sip4->sin_addr, tip, 48);
			} else if (conn->addr.sin6_family == AF_INET6) {
				struct sockaddr_in6 *sip6 = (struct sockaddr_in6*) &conn->addr;
				if (memseq((unsigned char*) &sip6->sin6_addr, 10, 0) && memseq((unsigned char*) &sip6->sin6_addr + 10, 2, 0xff)) {
					mip = inet_ntop(AF_INET, ((unsigned char*) &sip6->sin6_addr) + 12, tip, 48);
				} else mip = inet_ntop(AF_INET6, &sip6->sin6_addr, tip, 48);
			} else if (conn->addr.sin6_family == AF_LOCAL) {
				mip = "UNIX";
			} else {
				mip = "UNKNOWN";
			}
			writeFTPLine(conn, 150, "Ok Here comes the directory listing.");
			pid_t frk = fork();
			if (frk == 0) {
				setenv(cl ? "AVFTPD_ACC_SERVER" : "AVFTPD_ACC_CLIENT", fds, 1);
				setenv("AVFTPD_COMMAND", "LIST", 1);
				setenv("AVFTPD_FILE", chr, 1);
				setenv("AVFTPD_UID", uids, 1);
				setenv("AVFTPD_GID", gids, 1);
				setenv("AVFTPD_WPIPE", pips, 1);
				setenv("AVFTPD_EXPECTED", mip, 1);
				execl(ourbinary, ourbinary, NULL);
			} else {
				int st = 0; // TODO: non blocking
				waitpid(frk, &st, 0);
				if (st == 0) {
					writeFTPLine(conn, 226, "Transfer complete.");
				} else {
					writeFTPLine(conn, 550, "Failed to open file.");
				}
			}
			recog = 1;
		} else if (streq_nocase(cmd, "nlst")) {
			if (conn->sendfd < 0) {
				writeFTPLine(conn, 425, "Use PORT or PASV first.");
				return;
			}
			char* chr = calcChroot(conn->auth->root, conn->cwd, line);
			if (chr == NULL || access(chr, R_OK)) {
				writeFTPLine(conn, 550, "Failed to open file.");
				return;
			}
			int cl = conn->pasv;
			char fds[32];
			snprintf(fds, 32, "%i", conn->sendfd);
			char uids[32];
			snprintf(uids, 32, "%i", conn->auth->uid);
			char gids[32];
			snprintf(gids, 32, "%i", conn->auth->gid);
			char pips[32];
			snprintf(pips, 32, "%i", param->pipes[1]);
			const char* mip = NULL;
			char tip[48];
			if (conn->addr.sin6_family == AF_INET) {
				struct sockaddr_in *sip4 = (struct sockaddr_in*) &conn->addr;
				mip = inet_ntop(AF_INET, &sip4->sin_addr, tip, 48);
			} else if (conn->addr.sin6_family == AF_INET6) {
				struct sockaddr_in6 *sip6 = (struct sockaddr_in6*) &conn->addr;
				if (memseq((unsigned char*) &sip6->sin6_addr, 10, 0) && memseq((unsigned char*) &sip6->sin6_addr + 10, 2, 0xff)) {
					mip = inet_ntop(AF_INET, ((unsigned char*) &sip6->sin6_addr) + 12, tip, 48);
				} else mip = inet_ntop(AF_INET6, &sip6->sin6_addr, tip, 48);
			} else if (conn->addr.sin6_family == AF_LOCAL) {
				mip = "UNIX";
			} else {
				mip = "UNKNOWN";
			}
			writeFTPLine(conn, 150, "Ok Here comes the directory listing.");
			pid_t frk = fork();
			if (frk == 0) {
				setenv(cl ? "AVFTPD_ACC_SERVER" : "AVFTPD_ACC_CLIENT", fds, 1);
				setenv("AVFTPD_COMMAND", "NLST", 1);
				setenv("AVFTPD_FILE", chr, 1);
				setenv("AVFTPD_UID", uids, 1);
				setenv("AVFTPD_GID", gids, 1);
				setenv("AVFTPD_WPIPE", pips, 1);
				setenv("AVFTPD_EXPECTED", mip, 1);
				execl(ourbinary, ourbinary, NULL);
			} else {
				int st = 0; // TODO: non blocking
				waitpid(frk, &st, 0);
				if (st == 0) {
					writeFTPLine(conn, 226, "Transfer complete.");
				} else {
					writeFTPLine(conn, 550, "Failed to open file.");
				}
			}
			recog = 1;
		} else if (streq_nocase(cmd, "retr")) {
			if (conn->sendfd < 0) {
				writeFTPLine(conn, 425, "Use PORT or PASV first.");
				return;
			}
			char* chr = calcChroot(conn->auth->root, conn->cwd, line);
			if (chr == NULL || access(chr, R_OK)) {
				writeFTPLine(conn, 550, "Failed to open file.");
				return;
			}
			int cl = conn->pasv;
			char fds[32];
			snprintf(fds, 32, "%i", conn->sendfd);
			char uids[32];
			snprintf(uids, 32, "%i", conn->auth->uid);
			char gids[32];
			snprintf(gids, 32, "%i", conn->auth->gid);
			char pips[32];
			snprintf(pips, 32, "%i", param->pipes[1]);
			const char* mip = NULL;
			char tip[48];
			if (conn->addr.sin6_family == AF_INET) {
				struct sockaddr_in *sip4 = (struct sockaddr_in*) &conn->addr;
				mip = inet_ntop(AF_INET, &sip4->sin_addr, tip, 48);
			} else if (conn->addr.sin6_family == AF_INET6) {
				struct sockaddr_in6 *sip6 = (struct sockaddr_in6*) &conn->addr;
				if (memseq((unsigned char*) &sip6->sin6_addr, 10, 0) && memseq((unsigned char*) &sip6->sin6_addr + 10, 2, 0xff)) {
					mip = inet_ntop(AF_INET, ((unsigned char*) &sip6->sin6_addr) + 12, tip, 48);
				} else mip = inet_ntop(AF_INET6, &sip6->sin6_addr, tip, 48);
			} else if (conn->addr.sin6_family == AF_LOCAL) {
				mip = "UNIX";
			} else {
				mip = "UNKNOWN";
			}
			writeFTPLine(conn, 150, "Ok Here comes the file contents.");
			pid_t frk = fork();
			if (frk == 0) {
				setenv(cl ? "AVFTPD_ACC_SERVER" : "AVFTPD_ACC_CLIENT", fds, 1);
				setenv("AVFTPD_COMMAND", "RETR", 1);
				setenv("AVFTPD_FILE", chr, 1);
				setenv("AVFTPD_UID", uids, 1);
				setenv("AVFTPD_GID", gids, 1);
				setenv("AVFTPD_WPIPE", pips, 1);
				setenv("AVFTPD_EXPECTED", mip, 1);
				execl(ourbinary, ourbinary, NULL);
			} else {
				int st = 0; // TODO: non blocking
				waitpid(frk, &st, 0);
				if (st == 0) {
					writeFTPLine(conn, 226, "Transfer complete.");
				} else {
					writeFTPLine(conn, 550, "Failed to open file.");
				}
			}
			recog = 1;
		} else if (streq_nocase(cmd, "size")) {
			char* path = calcChroot(conn->auth->root, conn->cwd, line);
			if (!path || !canStatFile(path, conn->auth->uid, conn->auth->gid)) {
				writeFTPLine(conn, 550, "Failed to open file.");
				return;
			}
			struct stat st;
			if (!stat(path, &st)) {
				char sz[32];
				snprintf(sz, 32, "%i", st.st_size);
				writeFTPLine(conn, 213, sz);
			} else {
				writeFTPLine(conn, 550, "Failed to open file.");
			}
			recog = 1;
		} else if (streq_nocase(cmd, "dele")) {
			char* path = calcChroot(conn->auth->root, conn->cwd, line);
			if (!path || !canWriteFile(path, conn->auth->uid, conn->auth->gid)) {
				writeFTPLine(conn, 550, "Failed to open file.");
				return;
			}
			if (unlink(path)) {
				writeFTPLine(conn, 550, "Failed to open file.");
			} else {
				writeFTPLine(conn, 250, "Delete operation successful.");
			}
			recog = 1;
		} else if (streq_nocase(cmd, "rnfr")) {
			recog = 1;
		} else if (streq_nocase(cmd, "rnto")) {
			recog = 1;
		} else if (streq_nocase(cmd, "noop")) {
			writeFTPLine(conn, 200, "noop");
			recog = 1;
		} else if (streq_nocase(cmd, "allo")) {
			writeFTPLine(conn, 202, "ALLO command ignored.");
			recog = 1;
		} else if (streq_nocase(cmd, "abor")) {
			writeFTPLine(conn, 225, "No transfer to ABOR.");
			recog = 1;
		} else if (streq_nocase(cmd, "rest")) {
			conn->skip = atol(line);
			writeFTPLine(conn, 350, "Restart position accepted.");
			recog = 1;
		} else if (streq_nocase(cmd, "mkd")) {
			char* path = calcChroot(conn->auth->root, conn->cwd, line);
			if (!path) {
				writeFTPLine(conn, 550, "Failed to open file.");
				return;
			}
			size_t pl = strlen(path);
			if (pl > 0 && path[pl - 1] == '/') {
				path[pl - 1] = 0;
			}
			char* ep = strrchr(path, '/');
			if (ep != NULL) ep[0] = 0;
			if (pl <= 0 || !canWriteFile(path, conn->auth->uid, conn->auth->gid)) {
				writeFTPLine(conn, 550, "Failed to open file.");
				return;
			}
			mkdir(path, 0664);
			recog = 1;
		} else if (streq_nocase(cmd, "rmd")) {
			char* path = calcChroot(conn->auth->root, conn->cwd, line);
			if (!path || !canWriteFile(path, conn->auth->uid, conn->auth->gid)) {
				writeFTPLine(conn, 550, "Failed to open file.");
				return;
			}
			if (rmdir(path)) {
				writeFTPLine(conn, 550, "Failed to open file.");
			} else {
				writeFTPLine(conn, 250, "Delete operation successful.");
			}
			recog = 1;
		} else if (streq_nocase(cmd, "help")) {
			writeFTPBMLine(conn, 214, "The following commands are recognized.");
			writeFTPMMLine(conn, "ABOR ACCT ALLO APPE CDUP CWD  DELE HELP LIST MDTM MKD  MODE NLST NOOP");
			writeFTPMMLine(conn, "PASS PASV PORT PWD  QUIT REIN REST RETR RMD  RNFR RNTO SITE SMNT STAT");
			writeFTPMMLine(conn, "STOR STOU STRU SYST TYPE USER FEAT SIZE OPTS");
			writeFTPLine(conn, 214, "Help OK.");
			recog = 1;
		} else if (streq_nocase(cmd, "site")) {
			if (startsWith_nocase(line, "chmod ")) {
				char* al = line + 6;
				char* csep = strchr(al, ' ');
				if (strlen(al) > 1 && csep != NULL && strlen(csep) >= 1) {
					csep[0] = 0;
					csep++;
					if (strisunum(al)) {
						int chm = strtol(al, NULL, 8);
						char* path = calcChroot(conn->auth->root, conn->cwd, csep);
						if (!path) {
							writeFTPLine(conn, 550, "Failed to chmod file.");
							return;
						}
						struct stat st;
						int p = 0;
						if ((p = lstat(path, &st)) != 0 || (conn->auth->uid != 0 && st.st_uid != conn->auth->uid)) {
							writeFTPLine(conn, 550, "Failed to chmod file.");
							return;
						}
						if (chmod(path, chm) == -1) {
							writeFTPLine(conn, 550, "Failed to chmod file.");
						} else {
							writeFTPLine(conn, 550, "Chmod successful.");
						}
					} else {
						writeFTPLine(conn, 500, "Invalid SITE CHMOD command.");
					}
				} else {
					writeFTPLine(conn, 500, "Invalid SITE CHMOD command.");
				}
			} else {
				writeFTPLine(conn, 500, "Unknown SITE command.");
			}
			recog = 1;
		} else if (streq_nocase(cmd, "stat")) {
			writeFTPBMLine(conn, 211, "FTP server status:");
			writeFTPMMLine(conn, "Avuna FTPD " VERSION);
			writeFTPLine(conn, 211, "End of status");
			recog = 1;
		} else if (streq_nocase(cmd, "mode")) {
			if (streq_nocase(line, "s")) {
				writeFTPLine(conn, 200, "Mode set to S.");
			} else {
				writeFTPLine(conn, 200, "Bad MODE command.");
			}
			recog = 1;
		} else if (streq_nocase(cmd, "stru")) {
			if (streq_nocase(line, "f")) {
				writeFTPLine(conn, 200, "Structure set to F.");
			} else {
				writeFTPLine(conn, 200, "Bad STRU command.");
			}
			recog = 1;
		}
	}
	if (!recog) {
		writeFTPLine(conn, 500, "Command not recognized");
	}
}

int handleRead(struct conn* conn, struct work_param* param, int fd) {
	static unsigned char tm[4] = { 0x0D, 0x0A };
	int ml = 0;
	for (size_t x = conn->readBuffer_checked; x < conn->readBuffer_size; x++) {
		if (conn->readBuffer[x] == tm[ml]) {
			ml++;
			if (ml == 2) {
				char* reqd = xmalloc(x + 2);
				memcpy(reqd, conn->readBuffer, x + 1);
				reqd[x + 1] = 0;
				conn->readBuffer_size -= x + 1;
				conn->readBuffer_checked = 0;
				memmove(conn->readBuffer, conn->readBuffer + x + 1, conn->readBuffer_size);
				struct timespec stt;
				clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stt);
				//errlog(param->logsess, "Malformed Request!");
				//xfree(reqd);
				//closeConn(param, conn);
				//return 1;
				handleLine(fd, &stt, conn, param, reqd);
			}
		} else ml = 0;
	}
	if (conn != NULL) {
		if (conn->readBuffer_size >= 10) conn->readBuffer_checked = conn->readBuffer_size - 10;
		else conn->readBuffer_checked = 0;
	}
	return 0;
}

void run_work(struct work_param* param) {
	if (pipe(param->pipes) != 0) {
		printf("Failed to create pipe! %s\n", strerror(errno));
		return;
	}
	unsigned char wb;
	unsigned char* mbuf = xmalloc(1024);
	while (1) {
		pthread_rwlock_rdlock(&param->conns->data_mutex);
		size_t cc = param->conns->count;
		struct pollfd fds[cc + 1];
		struct conn* conns[cc];
		int fdi = 0;
		for (int i = 0; i < param->conns->size; i++) {
			if (param->conns->data[i * param->conns->dsize] != NULL) {
				conns[fdi] = (param->conns->data[i * param->conns->dsize]);
				struct conn* conn = conns[fdi];
				fds[fdi].fd = conns[fdi]->fd;
				fds[fdi].events = POLLIN | ((conn->writeBuffer_size > 0 || (conn->tls && !conn->handshaked && gnutls_record_get_direction(conn->session))) ? POLLOUT : 0);
				fds[fdi++].revents = 0;
				if (fdi == cc) break;
			}
		}
		pthread_rwlock_unlock(&param->conns->data_mutex);
		fds[cc].fd = param->pipes[0];
		fds[cc].events = POLLIN;
		fds[cc].revents = 0;
		int cp = poll(fds, cc + 1, -1);
		if (cp < 0) {
			printf("Poll error in worker thread! %s\n", strerror(errno));
		} else if (cp == 0) continue;
		else if ((fds[cc].revents & POLLIN) == POLLIN) {
			if (read(param->pipes[0], &wb, 1) < 1) printf("Error reading from pipe, infinite loop COULD happen here.\n");
			if (cp-- == 1) continue;
		}
		for (int i = 0; i < cc; i++) {
			int re = fds[i].revents;
			struct conn* conn = conns[i];
			if ((re & POLLERR) == POLLERR) {
				//printf("POLLERR in worker poll! This is bad!\n");
				goto cont;
			}
			if ((re & POLLHUP) == POLLHUP) {
				closeConn(param, conn);
				goto cont;
			}
			if ((re & POLLNVAL) == POLLNVAL) {
				printf("Invalid FD in worker poll! This is bad!\n");
				closeConn(param, conn);
				goto cont;
			}
			if (conn->tls && !conn->handshaked) {
				int r = gnutls_handshake(conn->session);
				if (gnutls_error_is_fatal(r)) {
					closeConn(param, conn);
					goto cont;
				} else if (r == GNUTLS_E_SUCCESS) {
					conn->handshaked = 1;
				}
				goto cont;
			}
			if ((re & POLLIN) == POLLIN) {
				size_t tr = 0;
				if (conn->tls) {
					tr = gnutls_record_check_pending(conn->session);
					if (tr == 0) {
						tr += 1024;
					}
				} else {
					ioctl(fds[i].fd, FIONREAD, &tr);
				}
				unsigned char* loc;
				if (conn->readBuffer == NULL) {
					conn->readBuffer = xmalloc(tr); // TODO: max upload?
					conn->readBuffer_size = tr;
					loc = conn->readBuffer;
				} else {
					conn->readBuffer_size += tr;
					conn->readBuffer = xrealloc(conn->readBuffer, conn->readBuffer_size);
					loc = conn->readBuffer + conn->readBuffer_size - tr;
				}
				ssize_t r = 0;
				if (r == 0 && tr == 0) { // nothing to read, but wont block.
					ssize_t x = 0;
					if (conn->tls) {
						x = gnutls_record_recv(conn->session, loc + r, tr - r);
						if (x <= 0 && gnutls_error_is_fatal(x)) {
							closeConn(param, conn);
							conn = NULL;
							goto cont;
						} else if (x <= 0) {
							if (r < tr) {
								conn->readBuffer_size += r - tr;
								conn->readBuffer = xrealloc(conn->readBuffer, conn->readBuffer_size);
								tr = r;
							}
							break;
						}
					} else {
						x = read(fds[i].fd, loc + r, tr - r);
						if (x <= 0) {
							closeConn(param, conn);
							conn = NULL;
							goto cont;
						}
					}
					r += x;
				}
				while (r < tr) {
					ssize_t x = 0;
					if (conn->tls) {
						x = gnutls_record_recv(conn->session, loc + r, tr - r);
						if (x <= 0 && gnutls_error_is_fatal(x)) {
							closeConn(param, conn);
							conn = NULL;
							goto cont;
						} else if (x <= 0) {
							if (r < tr) {
								conn->readBuffer_size += r - tr;
								conn->readBuffer = xrealloc(conn->readBuffer, conn->readBuffer_size);
								tr = r;
							}
							break;
						}
					} else {
						x = read(fds[i].fd, loc + r, tr - r);
						if (x <= 0) {
							closeConn(param, conn);
							conn = NULL;
							goto cont;
						}
					}
					r += x;
				}
				int p = 0;
				p = handleRead(conn, param, fds[i].fd);
				if (p == 1) {
					goto cont;
				}
			}
			if ((re & POLLOUT) == POLLOUT && conn != NULL) {
				ssize_t mtr = conn->tls ? gnutls_record_send(conn->session, conn->writeBuffer, conn->writeBuffer_size) : write(fds[i].fd, conn->writeBuffer, conn->writeBuffer_size);
				if (mtr < 0 && (conn->tls ? gnutls_error_is_fatal(mtr) : errno != EAGAIN)) {
					closeConn(param, conn);
					conn = NULL;
					goto cont;
				} else if (mtr < 0) {
					goto cont;
				} else if (mtr < conn->writeBuffer_size) {
					memmove(conn->writeBuffer, conn->writeBuffer + mtr, conn->writeBuffer_size - mtr);
					conn->writeBuffer_size -= mtr;
					conn->writeBuffer = xrealloc(conn->writeBuffer, conn->writeBuffer_size);
				} else {
					conn->writeBuffer_size = 0;
					xfree(conn->writeBuffer);
					conn->writeBuffer = NULL;
				}
			}
			cont: ;
			if (conn != NULL && conn->kwr && conn->writeBuffer_size <= 0) {
				closeConn(param, conn);
				conn = NULL;
			}
			if (--cp == 0) break;
		}
	}
	xfree(mbuf);
}
