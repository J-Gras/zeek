#include "Ethernet.h"
#include "NetVar.h"

using namespace zeek::llanalyzer::Ethernet;

EthernetAnalyzer::EthernetAnalyzer()
	: zeek::llanalyzer::Analyzer("Ethernet")
	{
	}

std::tuple<zeek::llanalyzer::AnalyzerResult, zeek::llanalyzer::identifier_t> EthernetAnalyzer::Analyze(Packet* packet)
	{
	auto& pdata = packet->cur_pos;
	auto end_of_data = packet->GetEndOfData();

	// Skip past Cisco FabricPath to encapsulated ethernet frame.
	if ( pdata[12] == 0x89 && pdata[13] == 0x03 )
		{
		auto constexpr cfplen = 16;

		if ( pdata + cfplen + 14 >= end_of_data )
			{
			packet->Weird("truncated_link_header_cfp");
			return { AnalyzerResult::Failed, 0 };
			}

		pdata += cfplen;
		}

	// Get protocol being carried from the ethernet frame.
	identifier_t protocol = (pdata[12] << 8) + pdata[13];

	packet->eth_type = protocol;
	packet->l2_dst = pdata;
	packet->l2_src = pdata + 6;

	// Ethernet II frames
	if ( protocol >= 1536 )
		{
		pdata += 14;
		return { AnalyzerResult::Continue, protocol };
		}

	// Other ethernet frame types
	if ( protocol <= 1500 )
		{
		if ( pdata + 16 >= end_of_data )
			{
			packet->Weird("truncated_ethernet_frame");
			return { AnalyzerResult::Failed, 0 };
			}

		// In the following we use undefined EtherTypes to signal uncommon
		// frame types. This allows specialized analyzers to take over.
		// Note that pdata remains at the start of the ethernet frame.

		// IEEE 802.2 SNAP
		if ( pdata[14] == 0xAA && pdata[15] == 0xAA)
			return { AnalyzerResult::Continue, 1502 };

		// Novell raw IEEE 802.3
		if ( pdata[14] == 0xFF && pdata[15] == 0xFF)
			return { AnalyzerResult::Continue, 1503 };


		// IEEE 802.2 LLC
		return { AnalyzerResult::Continue, 1501 };
		}

	// Undefined (1500 < EtherType < 1536)
	packet->Weird("undefined_ether_type");
	return { AnalyzerResult::Failed, protocol };
	}
