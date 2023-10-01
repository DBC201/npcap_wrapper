#include "npcap_wrapper.h"

int main()
{
	npcap_wrapper::NpcapWrapper npcapWrapper;
	npcapWrapper.update_interfaces();
	npcapWrapper.print_interfaces();

	return 0;
}