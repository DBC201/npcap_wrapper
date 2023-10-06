#include <iostream>
#include <pcap.h>
#include "npcap_wrapper.h"

#include <chrono>
#include <thread>

int main()
{
	std::string interface_name;

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

	if (i > interface_names.size() || i < 1) {
		std::cout << "Invalid interface id" << std::endl;
		system("pause");
		return 0;
	}
	
	interface_name = interface_map[interface_names[i - 1]];

	char promiscious_flag;

	do {
		std::cout << "Enable promisciuos mode? (y/n):";
		std::cin >> promiscious_flag;
	} while (promiscious_flag != 'y' && promiscious_flag != 'n');

	pcap_t *handle = npcap_wrapper.open_live_interface(interface_name, promiscious_flag == 'y' ? 1 : 0);
	std::string message = "Hello World";

	while (1)
	{
		npcap_wrapper::NpcapWrapper::send_packet(handle, (u_char *)message.c_str(), sizeof(message));
		std::cout << "Packet sent!" << std::endl;
		std::this_thread::sleep_for(std::chrono::milliseconds(1000));
	}

	return 0;
}
