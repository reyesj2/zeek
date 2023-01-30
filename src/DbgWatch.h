// Structures and methods for implementing watches in the Zeek debugger.

#pragma once

#include "zeek/util.h"

namespace zeek
	{
class Obj;
	}

namespace zeek::detail
	{

class Expr;

class DbgWatch
	{
public:
	explicit DbgWatch(Obj* var_to_watch);
	explicit DbgWatch(Expr* expr_to_watch);
	~DbgWatch() = default;

protected:
	Obj* var = nullptr;
	Expr* expr = nullptr;
	};

	} // namespace zeek::detail
