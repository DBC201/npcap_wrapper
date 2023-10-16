#include <iostream>
#include <pcap.h>
#include <npcap_wrapper.h>
#include <ethernet_packet.h>

#include <chrono>
#include <thread>

using npcap_wrapper::ethernet_packet::create_ethernet_packet;
using npcap_wrapper::ethernet_packet::EthernetPacket;
using npcap_wrapper::ethernet_packet::ByteArray;

int main()
{
	std::string interface_name;

	npcap_wrapper::NpcapWrapper npcap_wrapper;

	npcap_wrapper.update_interfaces();
	std::unordered_map<std::string, std::string> interface_map = npcap_wrapper.get_interface_names();
	std::vector<std::string> interface_names(interface_map.size());

	std::cout << "Detected Interfaces: " << std::endl
			  << std::endl;
	std::cout << "id | interface | description" << std::endl;
	int i = 1;
	for (auto const &[key, val] : interface_map)
	{
		std::cout << i << " | " << key << " | " << val << std::endl;
		interface_names[i - 1] = key;
		i++;
	}

	std::cout << std::endl;

	std::cout << "Enter the interface id:";
	std::cin >> i;

	if (i > interface_names.size() || i < 1)
	{
		std::cout << "Invalid interface id" << std::endl;
		system("pause");
		return 0;
	}

	interface_name = interface_names[i - 1];

	pcap_t *handle = npcap_wrapper.open_live_interface(interface_name, 0);
	std::string message = "Hello World";

	while (1)
	{
		// demo values
		ByteArray src_mac = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}; 
    	ByteArray dst_mac = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

		uint16_t etherType = 0x0800; // IPv4

		EthernetPacket *packet = create_ethernet_packet(src_mac, dst_mac, (unsigned char *)message.c_str(), message.size(), etherType);
		npcap_wrapper::NpcapWrapper::send_packet(handle, (u_char *)packet, sizeof(message));
		std::cout << "Packet sent!" << std::endl;
		std::this_thread::sleep_for(std::chrono::milliseconds(1000));
		delete packet;
	}

	return 0;
}
