#include "npcap_wrapper.h"
using npcap_wrapper::NpcapWrapper;

int main()
{

	NpcapWrapper npcapWrapper;

	npcapWrapper.tunnel("", "");
	return 0;
}
