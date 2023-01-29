#pragma once

#include "cstdio"
#include "cstdlib"
#include "cerrno"
#include "sys/ipc.h"
#include "sys/sem.h"
#include "semaphore.h"

class Semaphore {
	int semid = 0;
	bool locked = false;

public:
	Semaphore(const char * pathname, int projectId, int nSems = 1, int iv = 1)
	{
		key_t key;	// = IPC_PRIVATE;
		if((key = ftok(pathname, projectId)) == (key_t)-1) {
			perror("IPC error: ftok"); exit(errno);
		}
		/** POSIX semaphore :
		 * sem_t * sem = sem_open("/tmp", O_CREAT, 0644, 1/*initial_value* /);
		 * sem_t * sem = sem_open("/tmp", 0);	// Open a preexisting semaphore.
		*/
		/** In shared memory :
		 * int fd = shm_open("shmname", O_CREAT, O_RDWR);
		 * ftruncate(fd, sizeof(sem_t));
		 * sem_t *sem = mmap(NULL, sizeof(sem_t), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		 * sem_init(sem, 1, 1);
		*/
		if((semid = semget(key, 0, 0)) == -1) {
			perror("IPC warning: semget - creating new");
			if((semid = semget(key, nSems, IPC_CREAT | 0666)) == -1) {
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
				for(int i=0; i<nSems; i++)
					semctl(semid, i, SETVAL, iv);
			}
		}
		printf("Value : %d\n", GetVal());
	}

	int GetVal(int semnum = 0)
	{
		return semctl(semid, semnum, GETVAL);
	}

	int GetCount()
	{
		struct semid_ds buf;
		semctl(semid, 0, IPC_STAT, &buf);
		int semcnt = 0;
		for(int i=0; i<buf.sem_nsems; i++)
		{
			semcnt += GetVal(i);
		}
		printf("NSems : %lu, Associated Instances : %d\n", buf.sem_nsems, semcnt);
		return semcnt;
	}

	bool Wait()
	{
		struct sembuf semopdec = {
			.sem_num = 0,
			.sem_op = -1,
			.sem_flg = 0
		};
		locked = semop(semid, &semopdec, 1) != -1;
		return locked;
	}

	int Signal()
	{
		struct sembuf semopinc = {
			.sem_num = 0,
			.sem_op = 1,
			.sem_flg = 0
		};
		locked = not(semop(semid, &semopinc, 1) != -1);
		return locked;
	}

	int DestroySemaphore()
	{
		if(locked)
			Signal();
		return semctl(semid, 0, IPC_RMID);
	}

	~Semaphore()
	{
		//
	}
};

/** References :
 * [1] https://www.ibm.com/docs/en/zos/2.3.0?topic=functions-semop-semaphore-operations
 * [2] https://pubs.opengroup.org/onlinepubs/9699919799/
*/