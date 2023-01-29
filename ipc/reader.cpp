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
#include "shared_memory.h"

#define SHMEM_SIZE (1024 + 1)

int main()
{
	static Semaphore semaphore("/tmp", 1, 1, 1);
	static Semaphore semaphoreInstances("/tmp", 2, 1, 0);
	static SharedMemory shmem("/tmp", 1, SHMEM_SIZE);
	static char * str = (char *)shmem.GetSharedMemoryAddress();

	struct sigaction SigIntHandler;
	SigIntHandler.sa_handler = [](int s) {
		printf("Caught signal %d\n", s);
		semaphoreInstances.Wait();
		if(semaphoreInstances.GetCount() == 0)
		{
			semaphoreInstances.DestroySemaphore();
			semaphore.DestroySemaphore();
			printf("Semaphores Destroyed.\n");
		}
		exit(0);
	};
	sigemptyset(&SigIntHandler.sa_mask);
	SigIntHandler.sa_flags = 0;
	sigaction(SIGINT, &SigIntHandler, NULL);
	
	std::string buf;
	semaphoreInstances.Signal();
	do {
		if(semaphore.Wait()) {
			if(strlen(str)) {
				buf = str;
				std::cout << "SHMEM RD > " << buf << std::endl;
				memset(str, 0, SHMEM_SIZE - 1);
			}
			semaphore.Signal();
		}
		else {
			perror("IPC error: Semaphore Wait");
			perror(NULL);
			exit(errno);
		}
	} while(true);
}
