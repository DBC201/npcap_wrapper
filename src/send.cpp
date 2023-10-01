#include <iostream>
#include <pcap.h>
#include "npcap_wrapper.h"

#include <chrono>
#include <thread>

int main()
{

	npcap_wrapper::NpcapWrapper npcapWrapper;
	pcap_t *handle = npcapWrapper.open_live_interface("");
	std::string message = "Hello World";

	while (1)
	{
		npcap_wrapper::NpcapWrapper::send_packet(handle, (u_char *)message.c_str(), sizeof(message));
		std::this_thread::sleep_for(std::chrono::milliseconds(1000));
	}

	return 0;
}
