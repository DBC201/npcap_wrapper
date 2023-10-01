/**
 * @file npcap_wrapper.h
 * @author Deniz Cakiroglu (dcakiroglu@torontomu.ca)
 * @brief 
 * @date 2023-09-27
 * 
 */
#ifndef NPCAP_WRAPPER_H
#define NPCAP_WRAPPER_H

#include <iostream>
#include <pcap.h>
#include <unordered_map>

namespace npcap_wrapper
{
	class NpcapWrapper
	{
	public:
		/**
		 * @brief
		 *
		 * @param interface_name
		 * @param packet_handler void callback(unsigned char *user, const struct pcap_pkthdr *pkthdr, const unsigned char *packet);
		 * @param param
		 */
		void listen_interface(std::string interface_name, pcap_handler packet_handler, u_char *param)
		{
			const char *m_interface_name = interface_name.c_str();
			pcap_t *handle = open_live_interface(m_interface_name);
			if (handle == nullptr)
			{
				throw std::runtime_error("Error opening interface " + interface_name + ": " + std::string(errbuf));
			}

			if (pcap_loop(handle, 0, packet_handler, param) < 0)
			{
				throw std::runtime_error("Error in pcap_loop: " + std::string(pcap_geterr(handle)));
			}

			pcap_close(handle);
		}

		pcap_t *open_live_interface(std::string interface_name)
		{
			const char *m_interface_name = interface_name.c_str();
			pcap_t *handle = pcap_create(m_interface_name, errbuf);
			if (handle == nullptr)
			{
				throw std::runtime_error("Error creating interface " + interface_name + ": " + std::string(errbuf));
			}

			if (pcap_set_immediate_mode(handle, 1) != 0)
			{
				throw std::runtime_error("Error setting immediate mode for " + interface_name + ": " + std::string(pcap_geterr(handle)));
			}

			if (pcap_set_snaplen(handle, 65535) != 0)
			{
				throw std::runtime_error("Error setting snaplen for " + interface_name + ": " + std::string(pcap_geterr(handle)));
			}

			if (pcap_set_promisc(handle, 1) != 0)
			{
				throw std::runtime_error("Error setting promiscuous mode for " + interface_name + ": " + std::string(pcap_geterr(handle)));
			}

			if (pcap_activate(handle) != 0)
			{
				throw std::runtime_error("Error activating interface " + interface_name + ": " + std::string(pcap_geterr(handle)));
			}

			return handle;
		}

		void tunnel(std::string source_inteface_name, std::string destination_interface_name)
		{
			pcap_t *source_handle = open_live_interface(source_inteface_name);

			pcap_t *dest_handle = open_live_interface(destination_interface_name);

			if (pcap_loop(source_handle, 0, NpcapWrapper::tunnel_packet_handler, (u_char *)dest_handle) < 0)
			{
				throw std::runtime_error("Error in pcap_loop: " + std::string(pcap_geterr(source_handle)));
			}

			pcap_close(source_handle);
			pcap_close(dest_handle);
		}

		/**
		 * @brief 
		 * Returns interface_description and interface_name pairs.
		 * 
		 * @note
		 * Will return an empty map if update_interfaces() is not called.
		 * 
		 * @return std::unordered_map<std::string, std::string> {interface_description, interface_name}
		 */
		std::unordered_map<std::string, std::string> get_interface_names()
		{
			return m_interface_names;
		}

		/**
		 * @brief 
		 * Prints interface_description and interface_name pairs.
		 * 
		 * @note
		 * Won't print anything if update_interfaces() is not called.
		 * 
		 */
		void print_interfaces() {
			for (auto const& x : m_interface_names)
			{
				std::cout << x.first  
						<< ": "
						<< x.second 
						<< std::endl ;
			}
		}

		void update_interfaces()
		{
			pcap_if_t *interfaces;

			if (pcap_findalldevs(&interfaces, errbuf) == -1)
			{
				throw std::runtime_error("Error finding network interfaces: " + std::string(errbuf));
			}

			for (pcap_if_t *dev = interfaces; dev != nullptr; dev = dev->next)
			{
				m_interface_names.insert({dev->description, dev->name});
			}

			pcap_freealldevs(interfaces);
		}

		static void send_packet(pcap_t *handle, const u_char *packet, int packet_size)
		{
			if (pcap_sendpacket(handle, packet, packet_size) != 0)
			{
				throw std::runtime_error("Error sending packet: " + std::string(pcap_geterr(handle)));
			}
		}

	private:
		char errbuf[PCAP_ERRBUF_SIZE];
		std::unordered_map<std::string, std::string> m_interface_names;

		static void tunnel_packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet)
		{
			pcap_t *dest_handle = (pcap_t *)user;
			if (pcap_sendpacket(dest_handle, packet, pkthdr->len) != 0)
			{
				// don't throw error here to not halt the loop
				// throw std::runtime_error("Error sending packet: " + std::string(pcap_geterr(dest_handle)));

				std::cerr << "Error sending packet: " << pcap_geterr(dest_handle) << std::endl;
			}
		}
	};
} // namespace npcap_wrapper

#endif // NPCAP_WRAPPER_H
