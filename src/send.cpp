#include <iostream>
#include <pcap.h>
#include "npcap_wrapper.h"

#include <chrono>
#include <thread>

int main()
{
	std::string interface;

	npcap_wrapper::NpcapWrapper npcap_wrapper;

	npcap_wrapper.update_interfaces();
	std::unordered_map<std::string, std::string> interface_map = npcap_wrapper.get_interface_names();
	std::vector<std::string> interface_names(interface_map.size());

	std::cout << "Detected Interfaces: " << std::endl
			  << std::endl;
	std::cout << "id | interface" << std::endl;
	int i = 1;
	for (auto const &[key, val] : interface_map)
	{
		std::cout << i << " | " << key << std::endl;
		interface_names[i - 1] = key;
		i++;
	}

	std::cout << std::endl;

	std::cout << "Enter the interface id:";
	std::cin >> i;
	interface = interface_map[interface_names[i - 1]];

	if (i > interface_names.size() || i < 1) {
		std::cout << "Invalid interface id" << std::endl;
		system("pause");
		return 0;
	}

	pcap_t *handle = npcapWrapper.open_live_interface(interface);
	std::string message = "Hello World";

	while (1)
	{
		npcap_wrapper::NpcapWrapper::send_packet(handle, (u_char *)message.c_str(), sizeof(message));
		std::this_thread::sleep_for(std::chrono::milliseconds(1000));
		std::cout << "Packet sent!" << std::endl;
	}

	return 0;
}
