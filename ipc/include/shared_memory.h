#pragma once

#include "cstdio"
#include "cstdlib"
#include "cerrno"
#include "sys/ipc.h"
#include "sys/shm.h"

class SharedMemory {
	int shmid = 0;
	void * addr = NULL;
		
public:
	SharedMemory(const char * pathname, int projectId, size_t size)		// file name, proj id
	{
		key_t key;
		if((key = ftok(pathname, projectId)) == (key_t)-1) {
			perror("IPC error: ftok"); exit(errno);
		}
		if((shmid = shmget(key, 0, 0)) == -1) {
			perror("IPC warning: shmget - creating new.");
			if((shmid = shmget(key, size, IPC_CREAT | 0666)) == -1) {
				perror("IPC error: shmget\n");
				if (errno == EEXIST) {
					if ((shmid = shmget(key, 0, 0)) == -1) {
						perror("IPC error 1: shmget"); exit(errno);
					}
				}
				else {
					perror("IPC error 2: shmget"); exit(errno);
				}
			}
			else {
				printf("Created shared memory.\n");
			}
		}
	}

	void * GetSharedMemoryAddress()
	{
		if((addr = shmat(shmid, (void *)0, 0)) == (void *)-1) {
			perror("IPC error: shmat");
			return NULL;
		}
		return addr;
	}

	int DetachFromSharedMemory()
	{
		int ret = -1;
		if(addr)
			ret = shmdt(addr);
		addr = NULL;
		return ret;
	}

	int DestroySharedMemory()
	{
		DetachFromSharedMemory();
		return shmctl(shmid, IPC_RMID, NULL);
	}

	~SharedMemory()
	{
		struct shmid_ds buf;
		shmctl(shmid, IPC_STAT, &buf);
		printf("Processes attached to memory : %lu\n", buf.shm_nattch);
		if(buf.shm_nattch == 1)
		{
			DestroySharedMemory();
			printf("Shared memory destroyed.\n");
		}
		else
		{
			DetachFromSharedMemory();
			printf("Detached from shared memory.\n");
		}
	}
};