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
	
	ipc::managed_shared_memory Segment(ipc::open_only, Memory.Name);
	
	ipc::managed_shared_memory::handle_t Handle;
	std::stringstream ss;
	ss << argv[1];
	ss >> Handle;

	void * ShPtr = Segment.get_address_from_handle(Handle);
	std::cout << "Shared Memory Handle : " << Handle << std::endl;
	
	while(true)
	{
		if(*(char *)ShPtr)
		{
			std::cout << "SHMEM RD > " << (char *)ShPtr << std::endl;
		}
	}
}