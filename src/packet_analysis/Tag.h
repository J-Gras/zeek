// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek-config.h"
#include "../Tag.h"

namespace zeek::plugin {
	template <class T> class TaggedComponent;
	template <class T, class C>	class ComponentManager;
}
namespace plugin {
	template <class T>
	using TaggedComponent [[deprecated("Remove in v4.1. Use zeek::plugin::TaggedComponent instead.")]] =
		zeek::plugin::TaggedComponent<T>;
	template <class T, class C>
	using ComponentManager [[deprecated("Remove in v4.1. Use zeek::plugin::ComponentManager instead.")]] =
		zeek::plugin::ComponentManager<T, C>;
}

namespace zeek::packet_analysis {

class Manager;
class Component;

/**
 * Class to identify a protocol analyzer type.
 */
class Tag : public zeek::Tag {
public:
	/*
	 * Copy constructor.
	 */
	Tag(const Tag& other) : zeek::Tag(other) { }

	/**
	 * Default constructor. This initializes the tag with an error value
	 * that will make \c operator \c bool return false.
	 */
	Tag() : zeek::Tag() { }

	/**
	 * Destructor.
	 */
	~Tag() = default;

	/**
	 * Returns false if the tag represents an error value rather than a
	 * legal analyzer type.
	 */
	explicit operator bool() const { return *this != Tag(); }

	/**
	 * Assignment operator.
	 */
	Tag& operator=(const Tag& other);

	/**
	 * Compares two tags for equality.
	 */
	bool operator==(const Tag& other) const
		{
		return zeek::Tag::operator==(other);
		}

	/**
	 * Compares two tags for inequality.
	 */
	bool operator!=(const Tag& other) const
		{
		return zeek::Tag::operator!=(other);
		}

	/**
	 * Compares two tags for less-than relationship.
	 */
	bool operator<(const Tag& other) const
		{
		return zeek::Tag::operator<(other);
		}

	/**
	 * Returns the \c Analyzer::Tag enum that corresponds to this tag.
	 * The returned value does not have its ref-count increased.
	 *
	 * @param etype the script-layer enum type associated with the tag.
	 */
	const IntrusivePtr<EnumVal>& AsVal() const;

	/**
	 * Returns the \c Analyzer::Tag enum that corresponds to this tag.
	 * The returned value does not have its ref-count increased.
	 *
	 * @param etype the script-layer enum type associated with the tag.
	 */
	[[deprecated("Remove in v4.1.  Use AsVal() instead.")]]
	EnumVal* AsEnumVal() const;

	static Tag Error;

protected:

	friend class packet_analysis::Manager;
	friend class plugin::ComponentManager<Tag, Component>;
	friend class plugin::TaggedComponent<Tag>;

	/**
	 * Constructor.
	 *
	 * @param type The main type. Note that the \a llanalyzer::Manager
	 * manages the value space internally, so noone else should assign
	 * any main types.
	 *
	 * @param subtype The sub type, which is left to an analyzer for
	 * interpretation. By default it's set to zero.
	 */
	explicit Tag(type_t type, subtype_t subtype = 0);

	/**
	 * Constructor.
	 *
	 * @param val An enum value of script type \c Analyzer::Tag.
	 */
	explicit Tag(IntrusivePtr<EnumVal> val);

	[[deprecated("Remove in v4.1.  Construct from IntrusivePtr instead")]]
	explicit Tag(EnumVal* val);
};

}