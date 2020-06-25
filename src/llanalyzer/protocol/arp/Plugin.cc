#include "plugin/Plugin.h"
#include "ARP.h"
#include "llanalyzer/Component.h"

namespace zeek::plugin::LLAnalyzer_ARP {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::llanalyzer::Component("ARPAnalyzer",
		                 zeek::llanalyzer::ARP::ARPAnalyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "LLAnalyzer::ARPAnalyzer";
		config.description = "A wrapper for the original zeek code.";
		return config;
		}

} plugin;

}
