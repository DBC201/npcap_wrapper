#ifndef ETHERNET_PACKET_H
#define ETHERNET_PACKET_H

#include <iostream>
#include <vector>

namespace npcap_wrapper::ethernet_packet
{
	using ByteArray = std::vector<uint8_t>;
	struct EthernetPacketHeader
	{
		uint8_t destMAC[6]; // 6 bytes (48 bits)
		uint8_t srcMAC[6];	// 6 bytes (48 bits)
		uint16_t etherType; // 2 bytes (16 bits)
	};

	struct EthernetPacket
	{
		EthernetPacketHeader header;
		unsigned char data[1500]; // 1500 bytes (1500 * 8 = 12000 bits)
	};

	EthernetPacket *create_ethernet_packet(ByteArray source_mac_address, ByteArray destination_mac_address, unsigned char* data, size_t data_size, uint16_t etherType)
	{
		EthernetPacket *packet = new EthernetPacket;
		memcpy(packet->header.srcMAC, source_mac_address.data(), 6);
		memcpy(packet->header.destMAC, destination_mac_address.data(), 6);
		memcpy(packet->data, data, data_size);
		packet->header.etherType = etherType;
		return packet;
	}
}

#endif // ETHERNET_PACKET_H
