#include "iostream"
#include "string"
#include "cstdio"
#include "cstring"
#include "csignal"
#include "cstdlib"
#include "semaphore.h"
#include "sys/ipc.h"
#include "sys/shm.h"
#include "sys/sem.h"

#include "binary_semaphore.h"

#define SHMEM_SIZE (1024 + 1)

int main()
{
	key_t key;
	static int shmid;
	static char * str;
	static int semid;
	std::string buf;
	
	if((key = ftok("shared_file", 1)) == (key_t)-1) {		// file name, proj id
		perror("IPC error: ftok"); exit(errno);
	}
	CreateSemaphore(semid, key);
	if((shmid = shmget(key, 0, 0)) == -1) {
		perror("IPC warning: shmget - creating new.");
		if((shmid = shmget(key, SHMEM_SIZE, IPC_CREAT | 0666)) == -1) {
			perror("IPC error: shmget");
			if (errno == EEXIST) {
				if ((semid = shmget(key, 0, 0)) == -1) {
					perror("IPC error 1: shmget"); exit(errno);
				}
			}
			else {
				perror("IPC error 2: shmget"); exit(errno);
			}
		}
	}
	if((str = (char *)shmat(shmid, (void *)0, 0)) == NULL) {
		perror("IPC error: shmat"); exit(errno);
	}

	std::cout << key << " ";
	std::cout << shmid << " ";
	std::cout << semid << " ";
	std::cout << (size_t)str << std::endl;
	
	struct sigaction SigIntHandler;
	SigIntHandler.sa_handler = [](int s) {
		printf("Caught signal %d\n", s);
		shmdt(str);
		exit(0);
	};
	sigemptyset(&SigIntHandler.sa_mask);
	SigIntHandler.sa_flags = 0;
	sigaction(SIGINT, &SigIntHandler, NULL);

	// Signal(semid);
	
	memset(str, 0, SHMEM_SIZE);
	do {
		if(Wait(semid)) {
			buf.clear();
			std::cout << "SHMEM WR > ";
			std::getline(std::cin, buf);
			// if(Wait(semid));
			memcpy(str, buf.c_str(), SHMEM_SIZE - 1);
			printf("Written : %s\n", str);
			Signal(semid);
		}
		else {
			perror("IPC error: Semaphore Wait.");
			perror(NULL);
			shmdt(str);
			shmctl(shmid, IPC_RMID, NULL);
			semctl(semid, 0, IPC_RMID);
			exit(errno);
		}
	} while(true);
	
	shmdt(str);
}
