#include "npcap_wrapper.h"

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

	npcap_wrapper.listen_interface(
		interface_name, [](unsigned char *user, const struct pcap_pkthdr *pkthdr, const unsigned char *packet)
		{
			npcap_wrapper::NpcapWrapper::print_packet(pkthdr, packet);
		},
		nullptr, promiscious_flag == 'y' ? 1 : 0);
	return 0;
}
