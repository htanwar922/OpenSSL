#pragma once

#include "cstdio"
#include "cstdlib"
#include "cerrno"
#include "semaphore.h"
#include "sys/ipc.h"
#include "sys/shm.h"
#include "sys/sem.h"

bool Wait(const int &semid)
{
	struct sembuf semopdec = {
		.sem_num = 0,
		.sem_op = -1,
		.sem_flg = 0
	};
	return semop(semid, &semopdec, 1) != -1;
}

int Signal(const int &semid)
{
	struct sembuf semopinc = {
		.sem_num = 0,
		.sem_op = 1,
		.sem_flg = 0
	};
	return semop(semid, &semopinc, 1) != -1;
}

int CreateSemaphore(int &semid, key_t key)
{
	printf("K : %d\n", (int)key);
	if((semid = semget(key, 0, 0)) == -1) {
		perror("IPC warning: semget - creating new.");
		if((semid = semget(key, 1, IPC_CREAT | 0666)) == -1) {
			perror("IPC error: semget");
			if (errno == EEXIST) {
				if ((semid = semget(key, 0, 0)) == -1) {
					perror("IPC error 1: semget"); exit(errno);
				}
			}
			else {
				perror("IPC error 2: semget"); exit(errno);
			}
		}
		else {
			Signal(semid);
		}
	}
	return semid;
}

/** References :
 * [1] https://www.ibm.com/docs/en/zos/2.3.0?topic=functions-semop-semaphore-operations
 * [2] https://pubs.opengroup.org/onlinepubs/9699919799/
*/