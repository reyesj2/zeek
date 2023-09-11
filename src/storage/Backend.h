#pragma once

#include "zeek/Val.h"

namespace zeek::storage
	{

class Backend
	{
public:
	Backend() = default;

	/**
	 * Finalizes the backend when it's being closed. Can be overwritten by
	 * derived classes.
	 */
	virtual void Done() { }

	/**
	 * Returns a descriptive tag representing the source for debugging.
	 *
	 * Must be overridden by derived classes.
	 *
	 * @return The debugging name.
	 */
	virtual const char* Tag() = 0;

	/**
	 * Store a new key/value pair in the backend.
	 *
	 * @param key the key for the pair
	 * @param value the value for the pair
	 * @param overwrite whether an existing value for a key should be overwritten.
	 * @return true if the pair could be written to the backend, or false otherwise.
	 */
	virtual bool Store(ValPtr key, ValPtr value, bool overwrite = true) = 0;

	/**
	 * Retrieve a value from the backend for a provided key.
	 *
	 * @param key the key to lookup in the backend.
	 * @return the stored value, or null if the key is not found.
	 */
	virtual ValPtr Retrieve(ValPtr key) = 0;

	// QUESTIONS
	// Init method should allow for local worker connections vs aggregation?

protected:
	friend class Manager;

	/**
	 * Called by the manager system to open the backend.
	 *
	 * Derived classes must implement this method. If successful, the
	 * implementation must call \a Opened(); if not, it must call Error()
	 * with a corresponding message.
	 */
	virtual void Open() = 0;

	// NEEDS
	// - methods for serializing/deserializing keys and values to json
	};

	} // namespace zeek::storage
