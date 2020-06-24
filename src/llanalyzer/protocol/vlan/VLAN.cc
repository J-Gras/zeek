#include "VLAN.h"
#include "NetVar.h"

using namespace zeek::llanalyzer::VLAN;

VLANAnalyzer::VLANAnalyzer()
	: zeek::llanalyzer::Analyzer("VLANAnalyzer")
	{
	}

std::tuple<zeek::llanalyzer::AnalyzerResult, zeek::llanalyzer::identifier_t> VLANAnalyzer::Analyze(Packet* packet)
	{
	auto& pdata = packet->cur_pos;

	if ( pdata + 4 >= packet->GetEndOfData() )
		{
		packet->Weird("truncated_VLAN_header");
		return std::make_tuple(AnalyzerResult::Failed, 0);
		}

	auto& vlan_ref = packet->vlan != 0 ? packet->inner_vlan : packet->vlan;
	vlan_ref = ((pdata[0] << 8u) + pdata[1]) & 0xfff;

	identifier_t protocol = ((pdata[2] << 8u) + pdata[3]);
	packet->eth_type = protocol;
	pdata += 4; // Skip the VLAN header

	return std::make_tuple(AnalyzerResult::Continue, protocol);
	}
