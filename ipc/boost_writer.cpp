#include "iostream"
#include "cstdlib"
#include "sstream"

#include "boost/interprocess/managed_shared_memory.hpp"

namespace ipc = boost::interprocess;

int main(int argc, char ** argv)
{
	struct {
		const char * Name = "MySharedMemory";
		size_t Size = 65536;
	} Memory;
	
	ipc::managed_shared_memory Segment(ipc::create_only, Memory.Name, Memory.Size);
	ipc::managed_shared_memory::size_type FreeMemoryBefore = Segment.get_free_memory();
	
	void * ShPtr = Segment.allocate(1024);
	ipc::managed_shared_memory::size_type FreeMemoryAfter = Segment.get_free_memory();
	std::cout << FreeMemoryBefore << " " << FreeMemoryAfter << " " << FreeMemoryBefore - FreeMemoryAfter << std::endl;

	ipc::managed_shared_memory::handle_t Handle = Segment.get_handle_from_address(ShPtr);
	std::cout << "Shared Memory Handle : " << Handle << std::endl;
	
	char buffer[1024];
	while(true)
	{
		std::cout << "SHMEM WR > ";
		std::cin >> buffer;
		memcpy((char *)ShPtr, buffer, 1024);
	}
}