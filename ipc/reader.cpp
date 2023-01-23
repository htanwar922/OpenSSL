#include <iostream>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <cstdio>
#include <cstring>
#include <csignal>

#include <unistd.h>

#define MEMSIZE 1024

int main()
{
	key_t key = ftok("shmfile", 65);								// generate unique key
	static int shmid = shmget(key, MEMSIZE + 1, 0666|IPC_CREAT);	// rwcrw-rw-
	static char * str = (char *)shmat(shmid, (void*)0, 0);			// attach to shared memory

	struct sigaction Action;
	Action.sa_handler = [](int s) {
		printf("Received signal : %d\n", s);
		shmdt(str);
		shmctl(shmid, IPC_RMID, NULL);
		exit(s);
	};
	sigemptyset(&Action.sa_mask);
	Action.sa_flags = 0;
	sigaction(SIGINT, &Action, NULL);

	std::cout << key << " " << shmid << " " << (void *)str << " " << (int)str[0] << std::endl;
	while (true)
	{
		if(str[0] == 0) {
			str[0] = 1;
			std::cout << "SHMEM RD > " << str + 1;
			memset(str + 1, 0, MEMSIZE);
			str[0] = 0;
			sleep(1000);
		}
	}

	shmdt(str);
	shmctl(shmid, IPC_RMID, NULL);

	return 0;
}
