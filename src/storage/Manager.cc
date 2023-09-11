#include "zeek/storage/Manager.h"

namespace zeek::storage
	{

Manager::Manager() : plugin::ComponentManager<storage::Component>("Storage", "Backend") { }

void Manager::InitPostScript() { }

	} // namespace zeek::storage
