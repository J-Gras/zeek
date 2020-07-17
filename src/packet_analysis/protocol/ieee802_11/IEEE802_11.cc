// See the file "COPYING" in the main distribution directory for copyright.

#include "IEEE802_11.h"
#include "NetVar.h"

using namespace zeek::packet_analysis::IEEE802_11;

IEEE802_11Analyzer::IEEE802_11Analyzer()
	: zeek::packet_analysis::Analyzer("IEEE802_11")
	{
	}

zeek::packet_analysis::AnalysisResultTuple IEEE802_11Analyzer::Analyze(Packet* packet, const uint8_t*& data)
	{
	auto end_of_data = packet->GetEndOfData();

	u_char len_80211 = 24; // minimal length of data frames

	if ( data + len_80211 >= end_of_data )
		{
		packet->Weird("truncated_802_11_header");
		return { AnalyzerResult::Failed, 0 };
		}

	u_char fc_80211 = data[0]; // Frame Control field

	// Skip non-data frame types (management & control).
	if ( ! ((fc_80211 >> 2) & 0x02) )
		return { AnalyzerResult::Failed, 0 };

	// Skip subtypes without data.
	if ( (fc_80211 >> 4) & 0x04 )
		return { AnalyzerResult::Failed, 0 };

	// 'To DS' and 'From DS' flags set indicate use of the 4th
	// address field.
	if ( (data[1] & 0x03) == 0x03 )
		len_80211 += packet->L2_ADDR_LEN;

	// Look for the QoS indicator bit.
	if ( (fc_80211 >> 4) & 0x08 )
		{
		// Skip in case of A-MSDU subframes indicated by QoS
		// control field.
		if ( data[len_80211] & 0x80 )
			return { AnalyzerResult::Failed, 0 };

		len_80211 += 2;
		}

	if ( data + len_80211 >= end_of_data )
		{
		packet->Weird("truncated_802_11_header");
		return { AnalyzerResult::Failed, 0 };
		}

	// Determine link-layer addresses based
	// on 'To DS' and 'From DS' flags
	switch ( data[1] & 0x03 )
		{
		case 0x00:
			packet->l2_src = data + 10;
			packet->l2_dst = data + 4;
			break;

		case 0x01:
			packet->l2_src = data + 10;
			packet->l2_dst = data + 16;
			break;

		case 0x02:
			packet->l2_src = data + 16;
			packet->l2_dst = data + 4;
			break;

		case 0x03:
			packet->l2_src = data + 24;
			packet->l2_dst = data + 16;
			break;
		}

	// skip 802.11 data header
	data += len_80211;

	if ( data + 8 >= end_of_data )
		{
		packet->Weird("truncated_802_11_header");
		return { AnalyzerResult::Failed, 0 };
		}

	// Check that the DSAP and SSAP are both SNAP and that the control
	// field indicates that this is an unnumbered frame.
	// The organization code (24bits) needs to also be zero to
	// indicate that this is encapsulated ethernet.
	if ( data[0] == 0xAA && data[1] == 0xAA && data[2] == 0x03 &&
	     data[3] == 0 && data[4] == 0 && data[5] == 0 )
		{
		data += 6;
		}
	else
		{
		// If this is a logical link control frame without the
		// possibility of having a protocol we care about, we'll
		// just skip it for now.
		return { AnalyzerResult::Failed, 0 };
		}

	uint32_t protocol = (data[0] << 8) + data[1];
	data += 2;

	return { AnalyzerResult::Continue, protocol };
	}
