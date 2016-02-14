/*
 * main.c
 *
 *  Created on: Nov 17, 2015
 *      Author: root
 */

#include <unistd.h>
#include <stdio.h>
#include "config.h"
#include <errno.h>
#include "xstring.h"
#include "version.h"
#include "util.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include "streams.h"
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "accept.h"
#include "globals.h"
#include "collection.h"
#include "work.h"
#include <sys/types.h>
#include <gnutls/gnutls.h>
#include "tls.h"
#include <sys/wait.h>
#include <dirent.h>

int main(int argc, char* argv[]) {
	char* com = getenv("AVFTPD_COMMAND");
	if (com != NULL) {
		int pasv = 1;
		char* fds = getenv("AVFTPD_ACC_SERVER");
		if (fds == NULL) {
			fds = getenv("AVFTPD_ACC_CLIENT");
			if (fds == NULL) return 1;
			pasv = 0;
		}
		int fd = atoi(fds);
		if (fd < 0) return 1;
		struct sockaddr_in6 sin;
		if (pasv) {
			char* exp = getenv("AVFTPD_EXPECTED");
			if (exp == NULL) return 1;
			int pfd = fd;
			while (pasv) {
				socklen_t l = sizeof(struct sockaddr_in6);
				fd = accept(pfd, (struct sockaddr*) &sin, &l);
				const char* mip = NULL;
				char tip[48];
				if (sin.sin6_family == AF_INET) {
					struct sockaddr_in *sip4 = (struct sockaddr_in*) &sin;
					mip = inet_ntop(AF_INET, &sip4->sin_addr, tip, 48);
				} else if (sin.sin6_family == AF_INET6) {
					struct sockaddr_in6 *sip6 = (struct sockaddr_in6*) &sin;
					if (memseq((unsigned char*) &sip6->sin6_addr, 10, 0) && memseq((unsigned char*) &sip6->sin6_addr + 10, 2, 0xff)) {
						mip = inet_ntop(AF_INET, ((unsigned char*) &sip6->sin6_addr) + 12, tip, 48);
					} else mip = inet_ntop(AF_INET6, &sip6->sin6_addr, tip, 48);
				} else if (sin.sin6_family == AF_LOCAL) {
					mip = "UNIX";
				} else {
					mip = "UNKNOWN";
				}
				if (streq(mip, exp)) {
					pasv = 0;
				} else close(fd);
			}
		}
		char* certf = getenv("AVFTPD_CERT");
		char* keyf = getenv("AVFTPD_KEY");
		char* caf = getenv("AVFTPD_CA");
		int tls = 0;
		gnutls_session_t session;
		if (certf != NULL && keyf != NULL && caf != NULL) {
			gnutls_global_init();
			initdh();
			struct cert* crt = loadCert(caf, certf, keyf);
			tls = 1;
			gnutls_init(&session, GNUTLS_SERVER);
			gnutls_priority_set(session, crt->priority);
			gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, crt->cert);
			gnutls_certificate_server_set_request(session, GNUTLS_CERT_IGNORE);
			gnutls_transport_set_int2(session, fd, fd);
			int r = gnutls_handshake(session);
			while (r != GNUTLS_E_SUCCESS) {
				if (gnutls_error_is_fatal(r)) {
					return 1;
				}
				gnutls_handshake(session);
			}
		}
		char* file = getenv("AVFTPD_FILE");
		char* uids = getenv("AVFTPD_UID");
		char* gids = getenv("AVFTPD_GID");
		char* sks = getenv("AVFTPD_GID");
		if (uids == NULL || file == NULL || gids == NULL) return 1;
		uid_t uid = atol(uids);
		uid_t gid = atol(gids);
		size_t sk = sks == NULL ? 0 : atol(sks);
		setgid(gid);
		setuid(uid);
		if (streq_nocase(com, "list")) {
			if (tls) {
				int pipes[2];
				if (pipe(pipes)) {
					return 1;
				}
				dup2(pipes[1], STDOUT_FILENO);
				pid_t p = vfork();
				if (p == 0) {
					execl("/bin/ls", "/bin/ls", "-lALh", file, NULL);
				} else {
					int stp = 0;
					waitpid(p, &stp, 0);
					ssize_t x = 0;
					char buf[1024];
					fcntl(pipes[0], F_SETFL, fcntl(pipes[0], F_GETFL, 0) | O_NONBLOCK);
					while ((x = read(pipes[0], buf, 1024)) > 0) {
						ssize_t wx = 0;
						while (wx < x) {
							ssize_t px = gnutls_record_send(session, buf + wx, x - wx);
							if (px < 1) return 1;
							wx += px;
						}
					}
					gnutls_bye(session, GNUTLS_SHUT_RDWR);
					return stp;
				}
			} else {
				dup2(fd, STDOUT_FILENO);
				pid_t p = vfork();
				if (p == 0) {
					execl("/bin/ls", "/bin/ls", "-lALh", file, NULL);
				} else {
					int stp = 0;
					waitpid(p, &stp, 0);
					return stp;
				}
			}
		} else if (streq_nocase(com, "NLST")) {
			DIR* dir = opendir(file);
			struct dirent* de = NULL;
			while ((de = readdir(dir)) != NULL) {
				if (tls) writeLineSSL(session, de->d_name, strlen(de->d_name));
				else writeLine(fd, de->d_name, strlen(de->d_name));
			}
			closedir(dir);
		} else if (streq_nocase(com, "RETR")) {
			int fid = open(file, O_RDONLY);
			if (fid < 0) {
				return 1;
			}
			ssize_t i;
			lseek(fid, sk, SEEK_SET);
			unsigned char buf[1024];
			while ((i = read(fid, buf, 1024)) > 0) {
				ssize_t wr = 0;
				while (wr < i) {
					ssize_t wrt = tls ? gnutls_record_send(session, buf + wr, i - wr) : write(fd, buf + wr, i - wr);
					if (wrt < 0) {
						return 1;
					}
					wr += wrt;
				}
			}
		} else {
			int stor = streq_nocase(com, "STOR");
			int stou = streq_nocase(com, "STOU");
			int appe = streq_nocase(com, "APPE");
			if (!stor && !stou && !appe) {
				return 1;
			}
			if (stou) {
				int i = 1;
				size_t ofl = strlen(file);
				char* of = file;
				while (!access(file, F_OK)) {
					char si[32];
					snprintf(si, 32, "%i", i);
					if (i == 1) {
						file = xstrdup(file, strlen(si) + 1);
					} else {
						file = xrealloc(file, ofl + strlen(si) + 2);
					}
					memcpy(file, of, ofl);
					memcpy(file + ofl, si, strlen(si) + 1);
				}
			}
			int fid = open(file, O_RDWR | (appe ? O_APPEND : O_TRUNC) | O_CREAT);
			if (fid < 0) {
				return 1;
			}
			lseek(fid, sk, SEEK_SET);
			ssize_t i;
			unsigned char buf[1024];
			while ((i = (tls ? gnutls_record_recv(session, buf, 1024) : read(fd, buf, 1024))) > 0) {
				ssize_t wr = 0;
				while (wr < i) {
					ssize_t wrt = write(fid, buf + wr, i - wr);
					if (wrt < 0) {
						return 1;
					}
					wr += wrt;
				}
			}
		}
		if (tls) gnutls_bye(session, GNUTLS_SHUT_RDWR);
		return 0;
	}
	if (getuid() != 0 || getgid() != 0) {
		printf("Must run as root!\n");
		return 1;
	}
	if (readlink("/proc/self/exe", ourbinary, 256) < 0) memcpy(ourbinary, argv[0], strlen(argv[0]));
	printf("Loading Avuna %s %s\n", DAEMON_NAME, VERSION);
#ifdef DEBUG
	printf("Running in Debug mode!\n");
#endif
	char cwd[256];
	if (argc == 1) {
		memcpy(cwd, "/etc/avuna/", 11);
		cwd[11] = 0;
		char* dn = (char*) xcopy(DAEMON_NAME, strlen(DAEMON_NAME) + 1, 0);
		strcat(cwd, toLowerCase(dn));
		xfree(dn);
	} else {
		size_t l = strlen(argv[1]);
		if (argv[1][l - 1] == '/') argv[1][--l] = 0;
		memcpy(cwd, argv[1], l + 1);
	}
	recur_mkdir(cwd, 0750);
	chdir(cwd);
	if (strlen(cwd) > 240) {
		printf("Load Directory is more than 240 characters path length!\n");
		return 1;
	}
	strncat(cwd, "/main.cfg", 9);
	cfg = loadConfig(cwd);
	if (cfg == NULL) {
		printf("Error loading Config<%s>: %s\n", cwd, errno == EINVAL ? "File doesn't exist!" : strerror(errno));
		return 1;
	}
	struct cnode* dm = getUniqueByCat(cfg, CAT_DAEMON);
	if (dm == NULL) {
		printf("[daemon] block does not exist in %s!\n", cwd);
		return 1;
	}
	int runn = 0;
	pid_t pid = 0;
	const char* pid_file = getConfigValue(dm, "pid-file");
	if (!access(pid_file, F_OK)) {
		int pidfd = open(pid_file, O_RDONLY | O_CLOEXEC);
		if (pidfd < 0) {
			printf("Failed to open PID file! %s\n", strerror(errno));
			return 1;
		}
		char pidr[16];
		if (readLine(pidfd, pidr, 16) >= 1) {
			pid = atol(pidr);
			int k = kill(pid, 0);
			if (k == 0) {
				runn = 1;
			}
		} else {
			printf("Failed to read PID file! %s\n", strerror(errno));
			return 1;
		}
		close(pidfd);
	}
#ifndef DEBUG
	if (runn) {
		printf("Already running! PID = %i\n", pid);
		exit(0);
	} else {

		pid_t f = fork();
		if (f == 0) {
			printf("Now running as daemon!\n");
			exit(0);
		} else {
			printf("Daemonized! PID = %i\n", f);
			if (setsid() < 0) {
				printf("Failed to exit process tree: %s\n", strerror(errno));
				return 1;
			}
			if (freopen("/dev/null", "re", stdin) < 0) {
				printf("reopening of STDIN to /dev/null failed: %s\n", strerror(errno));
				return 1;
			}
			if (freopen("/dev/null", "we", stderr) < 0) {
				printf("reopening of STDERR to /dev/null failed: %s\n", strerror(errno));
				return 1;
			}
			if (freopen("/dev/null", "we", stdout) < 0) {
				printf("reopening of STDOUT to /dev/null failed: %s\n", strerror(errno));
				return 1;
			}
		}
	}
#else
	printf("Daemonized! PID = %i\n", getpid());
#endif
	delog = xmalloc(sizeof(struct logsess));
	delog->pi = 0;
	delog->access_fd = NULL;
	const char* el = getConfigValue(dm, "error-log");
	delog->error_fd = el == NULL ? NULL : fopen(el, "ae"); // fopen will return NULL on error, which works.
	int pfpl = strlen(pid_file);
	char* pfp = xcopy(pid_file, pfpl + 1, 0);
	for (int i = pfpl - 1; i--; i >= 0) {
		if (pfp[i] == '/') {
			pfp[i] = 0;
			break;
		}
	}
	if (recur_mkdir(pfp, 0750) == -1) {
		errlog(delog, "Error making directories for PID file: %s.", strerror(errno));
		return 1;
	}
//TODO: chown group to de-escalated
	FILE *pfd = fopen(pid_file, "we");
	if (pfd == NULL) {
		errlog(delog, "Error writing PID file: %s.", strerror(errno));
		return 1;
	}
	if (fprintf(pfd, "%i", getpid()) < 0) {
		errlog(delog, "Error writing PID file: %s.", strerror(errno));
		return 1;
	}
	if (fclose(pfd) < 0) {
		errlog(delog, "Error writing PID file: %s.", strerror(errno));
		return 1;
	}
	gnutls_global_init();
	initdh();
	int servsl;
	struct cnode** servs = getCatsByCat(cfg, CAT_SERVER, &servsl);
	int sr = 0;
	struct accept_param* aps[servsl];
	for (int i = 0; i < servsl; i++) {
		struct cnode* serv = servs[i];
		const char* bind_mode = getConfigValue(serv, "bind-mode");
		const char* bind_ip = NULL;
		int port = -1;
		const char* bind_file = NULL;
		int namespace = -1;
		int ba = 0;
		int ip6 = 0;
		if (streq(bind_mode, "tcp")) {
			bind_ip = getConfigValue(serv, "bind-ip");
			if (streq(bind_ip, "0.0.0.0")) {
				ba = 1;
			}
			ip6 = ba || contains(bind_ip, ":");
			const char* bind_port = getConfigValue(serv, "bind-port");
			if (!strisunum(bind_port)) {
				if (serv->id != NULL) errlog(delog, "Invalid bind-port for server: %s", serv->id);
				else errlog(delog, "Invalid bind-port for server.");
				continue;
			}
			port = atoi(bind_port);
			namespace = ip6 ? PF_INET6 : PF_INET;;
		} else if (streq(bind_mode, "unix")) {
			bind_file = getConfigValue(serv, "bind-file");
			namespace = PF_LOCAL;
		} else {
			if (serv->id != NULL) errlog(delog, "Invalid bind-mode for server: %s", serv->id);
			else errlog(delog, "Invalid bind-mode for server.");
			continue;
		}
		const char* tcc = getConfigValue(serv, "threads");
		if (!strisunum(tcc)) {
			if (serv->id != NULL) errlog(delog, "Invalid threads for server: %s", serv->id);
			else errlog(delog, "Invalid threads for server.");
			continue;
		}
		const char* usp = getConfigValue(serv, "user-provider");
		if (usp == NULL || !streq_nocase(usp, "file")) { //TODO: implement SQL
			if (serv->id != NULL) errlog(delog, "Invalid user-provider for server: %s", serv->id);
			else errlog(delog, "Invalid user-provider for server.");
			continue;
		}
		encip = getConfigValue(serv, "server-ip");
		if (encip == NULL) {
			if (serv->id != NULL) errlog(delog, "Invalid server-ip for server: %s", serv->id);
			else errlog(delog, "Invalid server-ip for server.");
			continue;
		}
		const char* uspff = NULL;
		if (streq_nocase(usp, "file")) {
			uspff = getConfigValue(serv, "user-provider-file");
			if (uspff == NULL || access(uspff, R_OK)) {
				if (serv->id != NULL) errlog(delog, "Invalid user-provider-file for server: %s", serv->id);
				else errlog(delog, "Invalid user-provider-file for server.");
				continue;
			}
		}
		int tc = atoi(tcc);
		if (tc < 1) {
			if (serv->id != NULL) errlog(delog, "Invalid threads for server: %s, must be greater than 1.", serv->id);
			else errlog(delog, "Invalid threads for server, must be greater than 1.");
			continue;
		}
		const char* mcc = getConfigValue(serv, "max-conn");
		if (!strisunum(mcc)) {
			if (serv->id != NULL) errlog(delog, "Invalid max-conn for server: %s", serv->id);
			else errlog(delog, "Invalid max-conn for server.");
			continue;
		}
		int mc = atoi(mcc);
		sock: ;
		int sfd = socket(namespace, SOCK_STREAM | SOCK_CLOEXEC, 0);
		if (sfd < 0) {
			if (serv->id != NULL) errlog(delog, "Error creating socket for server: %s, %s", serv->id, strerror(errno));
			else errlog(delog, "Error creating socket for server, %s", strerror(errno));
			continue;
		}
		int one = 1;
		int zero = 0;
		if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (void*) &one, sizeof(one)) == -1) {
			if (serv->id != NULL) errlog(delog, "Error setting SO_REUSEADDR for server: %s, %s", serv->id, strerror(errno));
			else errlog(delog, "Error setting SO_REUSEADDR for server, %s", strerror(errno));
			close (sfd);
			continue;
		}
		if (namespace == PF_INET || namespace == PF_INET6) {
			if (ip6) {
				if (setsockopt(sfd, IPPROTO_IPV6, IPV6_V6ONLY, (void*) &zero, sizeof(zero)) == -1) {
					if (serv->id != NULL) errlog(delog, "Error unsetting IPV6_V6ONLY for server: %s, %s", serv->id, strerror(errno));
					else errlog(delog, "Error unsetting IPV6_V6ONLY for server, %s", strerror(errno));
					close (sfd);
					continue;
				}
				struct sockaddr_in6 bip;
				bip.sin6_flowinfo = 0;
				bip.sin6_scope_id = 0;
				bip.sin6_family = AF_INET6;
				if (ba) bip.sin6_addr = in6addr_any;
				else if (!inet_pton(AF_INET6, bind_ip, &(bip.sin6_addr))) {
					close (sfd);
					if (serv->id != NULL) errlog(delog, "Error binding socket for server: %s, invalid bind-ip", serv->id);
					else errlog(delog, "Error binding socket for server, invalid bind-ip");
					continue;
				}
				bip.sin6_port = htons(port);
				if (bind(sfd, (struct sockaddr*) &bip, sizeof(bip))) {
					close (sfd);
					if (ba) {
						namespace = PF_INET;
						ip6 = 0;
						goto sock;
					}
					if (serv->id != NULL) errlog(delog, "Error binding socket for server: %s, %s", serv->id, strerror(errno));
					else errlog(delog, "Error binding socket for server, %s\n", strerror(errno));
					continue;
				}
			} else {
				struct sockaddr_in bip;
				bip.sin_family = AF_INET;
				if (!inet_aton(bind_ip, &(bip.sin_addr))) {
					close (sfd);
					if (serv->id != NULL) errlog(delog, "Error binding socket for server: %s, invalid bind-ip", serv->id);
					else errlog(delog, "Error binding socket for server, invalid bind-ip");
					continue;
				}
				bip.sin_port = htons(port);
				if (bind(sfd, (struct sockaddr*) &bip, sizeof(bip))) {
					if (serv->id != NULL) errlog(delog, "Error binding socket for server: %s, %s", serv->id, strerror(errno));
					else errlog(delog, "Error binding socket for server, %s\n", strerror(errno));
					close (sfd);
					continue;
				}
			}
		} else if (namespace == PF_LOCAL) {
			struct sockaddr_un uip;
			strncpy(uip.sun_path, bind_file, 108);
			if (bind(sfd, (struct sockaddr*) &uip, sizeof(uip))) {
				if (serv->id != NULL) errlog(delog, "Error binding socket for server: %s, %s", serv->id, strerror(errno));
				else errlog(delog, "Error binding socket for server, %s\n", strerror(errno));
				close (sfd);
				continue;
			}
		} else {
			if (serv->id != NULL) errlog(delog, "Invalid family for server: %s", serv->id);
			else errlog(delog, "Invalid family for server\n");
			close (sfd);
			continue;
		}
		if (listen(sfd, 50)) {
			if (serv->id != NULL) errlog(delog, "Error listening on socket for server: %s, %s", serv->id, strerror(errno));
			else errlog(delog, "Error listening on socket for server, %s", strerror(errno));
			close (sfd);
			continue;
		}
		if (fcntl(sfd, F_SETFL, fcntl(sfd, F_GETFL) | O_NONBLOCK) < 0) {
			if (serv->id != NULL) errlog(delog, "Error setting non-blocking for server: %s, %s", serv->id, strerror(errno));
			else errlog(delog, "Error setting non-blocking for server, %s", strerror(errno));
			close (sfd);
			continue;
		}
		struct logsess* slog = xmalloc(sizeof(struct logsess));
		slog->pi = 0;
		const char* lal = getConfigValue(serv, "access-log");
		slog->access_fd = lal == NULL ? NULL : fopen(lal, "ae");
		const char* lel = getConfigValue(serv, "error-log");
		slog->error_fd = lel == NULL ? NULL : fopen(lel, "ae");
		const char* sssl = getConfigValue(serv, "ssl");
		if (serv->id != NULL) acclog(slog, "Server %s listening for connections!", serv->id);
		else acclog(slog, "Server listening for connections!");
		struct accept_param* ap = xmalloc(sizeof(struct accept_param));
		if (sssl != NULL) {
			struct cnode* ssln = getCatByID(cfg, sssl);
			if (ssln == NULL) {
				errlog(slog, "Invalid SSL node! Node not found!");
				goto pssl;
			}
			const char* cert = getConfigValue(ssln, "publicKey");
			const char* key = getConfigValue(ssln, "privateKey");
			const char* ca = getConfigValue(ssln, "ca");
			if (ca != NULL && access(ca, R_OK)) {
				errlog(slog, "CA for SSL node was not valid, loading without CA!");
				ca = NULL;
			}
			if (cert == NULL || key == NULL || access(cert, R_OK) || access(key, R_OK)) {
				errlog(slog, "Invalid SSL node! No publicKey/privateKey value or cannot be read!");
				goto pssl;
			}
			ap->cert = loadCert(ca, cert, key);
		} else {
			ap->cert = NULL;
		}
		pssl: ap->port = port;
		ap->server_fd = sfd;
		ap->config = serv;
		ap->works_count = tc;
		ap->works = xmalloc(sizeof(struct work_param*) * tc);
		ap->logsess = slog;
		struct users* users = xmalloc(sizeof(struct users));
		pthread_rwlock_init(&users->lock, NULL);
		users->user_count = 0;
		users->users = NULL;
		struct config* uc = loadConfig(uspff);
		if (uc == NULL) {
			if (serv->id != NULL) errlog(delog, "Error loading users for server: %s, %s", serv->id, strerror(errno));
			else errlog(delog, "Error loading users for server, %s", strerror(errno));
			close (sfd);
			xfree(users);
			continue;
		}
		for (size_t x = 0; x < uc->node_count; x++) {
			struct cnode* cnu = uc->nodes[x];
			if (cnu->cat == CAT_USER) {
				if (users->users) {
					users->users = xrealloc(users->users, sizeof(struct user*) * (users->user_count + 1));
				} else {
					users->users = xmalloc(sizeof(struct user*) * (users->user_count + 1));
				}
				struct user* user = xmalloc(sizeof(struct user));
				users->users[users->user_count++] = user;
				user->username = cnu->id;
				user->password = getConfigValue(cnu, "password");
				user->root = getConfigValue(cnu, "root");
				const char* uids = getConfigValue(cnu, "uid");
				const char* gids = getConfigValue(cnu, "gid");
				if (!user->username || !user->password || !user->root || !uids || !gids) {
					xfree(user);
					users->user_count--;
					errlog(delog, "Invalid user: '%s' in '%s'.", user->username == NULL ? "NULL" : user->username, uspff);
					continue;
				}
				user->uid = atol(uids);
				user->gid = atol(gids);
			}
		}
		for (int x = 0; x < tc; x++) {
			struct work_param* wp = xmalloc(sizeof(struct work_param));
			wp->cert = ap->cert;
			wp->conns = new_collection(mc < 1 ? 0 : mc / tc, sizeof(struct conn*));
			wp->logsess = slog;
			wp->i = x;
			wp->sport = port;
			wp->users = users;
			ap->works[x] = wp;
		}
		aps[i] = ap;
		sr++;
	}
	const char* uids = getConfigValue(dm, "uid");
	const char* gids = getConfigValue(dm, "gid");
	uid_t uid = uids == NULL ? 0 : atol(uids);
	uid_t gid = gids == NULL ? 0 : atol(gids);
	if (gid > 0) {
		if (setgid(gid) != 0) {
			errlog(delog, "Failed to setgid! %s", strerror(errno));
		}
	}
	if (uid > 0) {
		if (setuid(uid) != 0) {
			errlog(delog, "Failed to setuid! %s", strerror(errno));
		}
	}
	acclog(delog, "Running as UID = %u, GID = %u, starting workers.", getuid(), getgid());
	for (int i = 0; i < servsl; i++) {
		pthread_t pt;
		for (int x = 0; x < aps[i]->works_count; x++) {
			int c = pthread_create(&pt, NULL, (void *) run_work, aps[i]->works[x]);
			if (c != 0) {
				if (servs[i]->id != NULL) errlog(delog, "Error creating thread: pthread errno = %i, this will cause occasional connection hanging @ %s server.", c, servs[i]->id);
				else errlog(delog, "Error creating thread: pthread errno = %i, this will cause occasional connection hanging.", c);
			}
		}
		int c = pthread_create(&pt, NULL, (void *) run_accept, aps[i]);
		if (c != 0) {
			if (servs[i]->id != NULL) errlog(delog, "Error creating thread: pthread errno = %i, server %s is shutting down.", c, servs[i]->id);
			else errlog(delog, "Error creating thread: pthread errno = %i, server is shutting down.", c);
			close(aps[i]->server_fd);
		}
	}
	while (sr > 0)
		sleep(1);
	return 0;
}
