#include "plugin/Plugin.h"
#include "IPv6.h"
#include "llanalyzer/Component.h"

namespace zeek::plugin::LLPOC_IPv6 {

class Plugin : public ::plugin::Plugin {
public:
	::plugin::Configuration Configure()
		{
		AddComponent(new zeek::llanalyzer::Component("IPv6Analyzer",
		             zeek::llanalyzer::IPv6::IPv6Analyzer::Instantiate));

		::plugin::Configuration config;
		config.name = "LLPOC::IPv6Analyzer";
		config.description = "A wrapper for the original zeek code.";
		return config;
		}
} plugin;

}