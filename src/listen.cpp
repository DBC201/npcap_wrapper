#include "npcap_wrapper.h"

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

	npcapWrapper.listen_interface(
		interface, [](unsigned char *user, const struct pcap_pkthdr *pkthdr, const unsigned char *packet)
		{
			npcap_wrapper::NpcapWrapper::print_packet(pkthdr, packet);
		},
		nullptr);
	return 0;
}
