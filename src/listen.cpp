#include "npcap_wrapper.h"
using npcap_wrapper::NpcapWrapper;

int main()
{

	NpcapWrapper npcapWrapper;

	npcapWrapper.update_interfaces();

	std::unordered_map<std::string, std::string> interfaces = npcapWrapper.get_interface_names();

	int count = 0;

	npcapWrapper.listen_interface(
		interfaces.at(""), [](unsigned char *user, const struct pcap_pkthdr *pkthdr, const unsigned char *packet)
		{
			int *count = (int *)user;
			std::cout << *count << ": ";
			(*count)++;
			std::cout << "Received a packet with length: " << pkthdr->len << " bytes" << std::endl;
			// Print the packet content as ASCII characters
			for (int i = 0; i < pkthdr->len; i++) {
				if (isprint(packet[i])) {
					std::cout << packet[i];
				} else {
					std::cout << '.';
				}

				if ((i + 1) % 80 == 0) {
					std::cout << std::endl;
				}
			}
        	std::cout << std::endl; 
		},
		(u_char*)(&count));
	return 0;
}
