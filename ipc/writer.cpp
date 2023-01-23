#include <iostream>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <cstdio>
#include <cstring>
#include <csignal>

#define MEMSIZE 1024

int main()
{
	key_t key = ftok("shmfile", 65);								// generate unique key
	int shmid = shmget(key, MEMSIZE + 1, 0666|IPC_CREAT);			// rwcrw-rw-
	static char * str = (char *)shmat(shmid, (void*)0, 0);			// attach to shared memory

	struct sigaction Action;
	Action.sa_handler = [](int s) {
		printf("Received signal : %d\n", s);
		shmdt(str);
		exit(s);
	};
	sigemptyset(&Action.sa_mask);
	Action.sa_flags = 0;
	sigaction(SIGINT, &Action, NULL);

	char buffer[MEMSIZE]{0};
	memset(str, 0, MEMSIZE);
	std::cout << key << " " << shmid << " " << (void *)str << " " << (int)str[0] << std::endl;
	while (true)
	{
		std::cout << "SHMEM WR > ";
		std::cin >> buffer;
		std::cout << buffer << (int)str[0] << std::endl;
		while(str[0]);
		std::cout << buffer << std::endl;
		if(str[0] == 0) {
			str[0] = 1;
			memcpy(str + 1, buffer, MEMSIZE);
			std::cout << str + 1 << std::endl;
			str[0] = 0;
			std::cout << (int)str[0] << str + 1 << std::endl;
		}
	}

	shmdt(str);

	return 0;
}
