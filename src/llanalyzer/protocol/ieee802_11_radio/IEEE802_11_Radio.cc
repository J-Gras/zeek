#include <pcap.h>

#include "IEEE802_11_Radio.h"
#include "NetVar.h"

using namespace zeek::llanalyzer::IEEE802_11_Radio;

IEEE802_11_RadioAnalyzer::IEEE802_11_RadioAnalyzer()
	: zeek::llanalyzer::Analyzer("IEEE802_11_RadioAnalyzer")
	{
	}

std::tuple<zeek::llanalyzer::AnalyzerResult, zeek::llanalyzer::identifier_t> IEEE802_11_RadioAnalyzer::Analyze(Packet* packet)
	{
	auto pdata = packet->cur_pos;
	auto end_of_data = packet->GetEndOfData();

	if ( pdata + 3 >= end_of_data )
		{
		packet->Weird("truncated_radiotap_header");
		return std::make_tuple(AnalyzerResult::Failed, 0);
		}

	// Skip over the RadioTap header
	int rtheader_len = (pdata[3] << 8) + pdata[2];

	if ( pdata + rtheader_len >= end_of_data )
		{
		packet->Weird("truncated_radiotap_header");
		return std::make_tuple(AnalyzerResult::Failed, 0);
		}

	packet->cur_pos += rtheader_len;

	return std::make_tuple(AnalyzerResult::Continue, DLT_IEEE802_11);
	}