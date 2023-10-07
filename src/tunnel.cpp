#include <npcap_wrapper.h>

int main() {
	std::string source_interface;
	std::string destination_interface;

	npcap_wrapper::NpcapWrapper npcap_wrapper;

	npcap_wrapper.update_interfaces();
	std::unordered_map<std::string, std::string> interface_map = npcap_wrapper.get_interface_names();
	std::vector<std::string> interface_names(interface_map.size());

	std::cout << "Detected Interfaces: " << std::endl
			  << std::endl;
	std::cout << "id | description | interface" << std::endl;
	int i = 1;
	for (auto const &[key, val] : interface_map)
	{
		std::cout << i << " | " << key << " | " << val << std::endl;
		interface_names[i - 1] = key;
		i++;
	}

	std::cout << std::endl;

	std::cout << "Enter the source interface id:";
	std::cin >> i;

	if (i > interface_names.size() || i < 1) {
		std::cout << "Invalid interface id" << std::endl;
		system("pause");
		return 0;
	}

	source_interface = interface_map[interface_names[i - 1]];

	std::cout << "Enter the destination interface id:";
	std::cin >> i;

	if (i > interface_names.size() || i < 1) {
		std::cout << "Invalid interface id" << std::endl;
		system("pause");
		return 0;
	}

	destination_interface = interface_map[interface_names[i - 1]];

	char promiscious_flag;

	do {
		std::cout << "Enable promisciuos mode? (y/n):";
		std::cin >> promiscious_flag;
	} while (promiscious_flag != 'y' && promiscious_flag != 'n');

	std::cout << "Tunneling " << source_interface << " to " << destination_interface << std::endl;
	npcap_wrapper.tunnel(source_interface, destination_interface, promiscious_flag == 'y' ? 1 : 0);

	return 0;
}
