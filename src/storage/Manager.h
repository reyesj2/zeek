// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/plugin/ComponentManager.h"
#include "zeek/storage/Component.h"

namespace zeek::storage
	{

class Manager final : public plugin::ComponentManager<Component>
	{
public:
	Manager();
	~Manager() = default;

	/**
	 * Initialization of the manager. This is called late during Zeek's
	 * initialization after any scripts are processed.
	 */
	void InitPostScript();

	// NEEDS
	// method to open new backend (takes tag and val configuration, returns opaque?)
	// method to close backend (takes opaque?)
	// method for storing data (takes val key/value, returns bool success)
	// - should this link to a specific backend? tag-based maybe? it feels weird to pushing to
	//   every backend at once.
	// method for retrieving data (takes val key, returns val on success or null on failure)
	// - should this link to a specific backend? tag-based maybe?

	// QUESTIONS
	// Hooks for storage-backed tables?
	// Handling aggregation from workers?

private:
	};

	} // namespace zeek::storage

namespace zeek
	{

extern storage::Manager* storage_mgr;

	} // namespace zeek
