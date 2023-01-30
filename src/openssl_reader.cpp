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
		// if(semaphoreInstances.GetCount() == 0)
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
	AES_CBC_256 encodeObject;
	PKey pkey;
	pkey.GetKey("../public.pem", "public");
	Message textMessage, byteMessage, signMessage;
	
	semaphoreInstances.Signal();
	std::cout << "\nSHMEM RD > ";
	std::cout.flush();
	do {
		if(semaphore.Wait()) {
			memcpy((uint8_t *)&byteMessage.Len, str, sizeof(byteMessage.Len));
			if(byteMessage.Len) {
				memcpy(byteMessage.Body, str + sizeof(byteMessage.Len), byteMessage.Len);

				memcpy((uint8_t *)&signMessage.Len, str + sizeof(byteMessage.Len) + byteMessage.Len, sizeof(signMessage.Len));
				memcpy(signMessage.Body, str + sizeof(byteMessage.Len) + byteMessage.Len + sizeof(signMessage.Len), signMessage.Len);
				bool verify = pkey.Verify(byteMessage.Body, byteMessage.Len, signMessage.Body, signMessage.Len, "sha256");
				textMessage.Len = encodeObject.Decrypt(byteMessage.Body, byteMessage.Len, textMessage.Body);

				std::cout << textMessage.Body << std::endl;
				printf("Read %lu bytes:\n", byteMessage.Len);
				encodeObject.PrintCiphertext(byteMessage.Body, byteMessage.Len);
				printf("Read %lu bytes:\n", signMessage.Len);
				encodeObject.PrintCiphertext(signMessage.Body, signMessage.Len);
				printf("Verified : %s\n", verify ? "True" : "False");

				memset(str, 0, SHMEM_SIZE);
				memset(textMessage.Body, 0, MAX_BUFFER_SIZE);
				std::cout << "\nSHMEM RD > ";
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
