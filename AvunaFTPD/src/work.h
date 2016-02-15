/*
 * work.h
 *
 *  Created on: Nov 18, 2015
 *      Author: root
 */

#ifndef WORK_H_
#define WORK_H_

#include "collection.h"
#include "accept.h"
#include "log.h"
#include <pthread.h>

struct user {
		char* username;
		char* password;
		char* root;
		uid_t uid;
		gid_t gid;
};

struct users {
		struct user** users;
		size_t user_count;
		pthread_rwlock_t lock;
};

struct work_param {
		struct collection* conns;
		int pipes[2];
		struct logsess* logsess;
		int i;
		int sport;
		struct users* users;
		struct cert* cert;
};

void run_work(struct work_param* param);

#endif /* WORK_H_ */
