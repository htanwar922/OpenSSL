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
#include "openssl_test.h"

#define SHMEM_SIZE (MAX_BUFFER_SIZE + sizeof(size_t))

using namespace LibOpenSSL;

int main()
{
	printf("Source dir : %s\n", SOURCE_DIR);
	const char * filename = SOURCE_DIR"/private.pem";
	const char * passphrase = "Himanshu";

	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_ciphers();
	OpenSSL_add_all_digests();
	
	static Semaphore semaphore("/tmp", 1, 1, 1);
	static Semaphore semaphoreInstances("/tmp", 2, 1, 0);
	static SharedMemory shmem("/tmp", 1, SHMEM_SIZE + 1);
	static uint8_t * str = (uint8_t *)shmem.GetSharedMemoryAddress();
	
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

	BIO * bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
	AES_CBC_256 encodeObject = AES_CBC_256();
	Message textMessage, byteMessage;

	semaphoreInstances.Signal();
	std::cout << "\nSHMEM WR > ";
	std::cout.flush();
	do {
		std::cin.getline((char *)textMessage.Body, MAX_BUFFER_SIZE);
		textMessage.Len = strlen((char *)textMessage.Body);
		if(semaphore.Wait()) {
			{
				byteMessage.Len = encodeObject.Encrypt(textMessage.Body, textMessage.Len, byteMessage.Body);
				memcpy(str, (uint8_t *)&byteMessage.Len, sizeof(byteMessage.Len));
				memcpy(str + sizeof(byteMessage.Len), byteMessage.Body, byteMessage.Len);

				printf("Written %lu bytes:\n", byteMessage.Len);
				encodeObject.PrintCiphertext(byteMessage.Body, byteMessage.Len);
				

				std::cout << "\nSHMEM WR > ";
				std::cout.flush();
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
