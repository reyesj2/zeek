// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstdint>
#include <initializer_list>
#include <type_traits>

#include "zeek/Span.h"
#include "zeek/telemetry/MetricFamily.h"

#include "opentelemetry/sdk/metrics/sync_instruments.h"

namespace zeek::telemetry
	{

class DblCounterFamily;
class IntCounterFamily;
class Manager;

/**
 * A handle to a metric that represents an integer value that can only go up.
 */
class IntCounter
	{
public:
	static inline const char* OpaqueName = "IntCounterMetricVal";

	explicit IntCounter(std::shared_ptr<IntCounterFamily> family,
	                    Span<const LabelView> labels) noexcept;

	IntCounter() = delete;
	IntCounter(const IntCounter&) noexcept = default;
	IntCounter& operator=(const IntCounter&) noexcept = default;

	/**
	 * Increments the value by 1.
	 */
	void Inc() noexcept;

	/**
	 * Increments the value by @p amount.
	 * @pre `amount >= 0`
	 */
	void Inc(uint64_t amount) noexcept;

	/**
	 * Increments the value by 1.
	 * @return The new value.
	 */
	uint64_t operator++() noexcept;

	/**
	 * @return The current value.
	 */
	uint64_t Value() const noexcept { return value; }

	/**
	 * @return Whether @c this and @p other refer to the same counter.
	 */
	bool IsSameAs(const IntCounter& other) const noexcept
		{
		return family == other.family && attributes == other.attributes;
		}

	bool operator==(const IntCounter& rhs) const noexcept { return IsSameAs(rhs); }
	bool operator!=(const IntCounter& rhs) const noexcept { return ! IsSameAs(rhs); }

private:
	std::shared_ptr<IntCounterFamily> family;
	MetricAttributeIterable attributes;
	uint64_t value = 0;
	};

/**
 * Manages a collection of IntCounter metrics.
 */
class IntCounterFamily : public MetricFamily, public std::enable_shared_from_this<IntCounterFamily>
	{
public:
	static inline const char* OpaqueName = "IntCounterMetricFamilyVal";

	using InstanceType = IntCounter;

	explicit IntCounterFamily(std::string_view prefix, std::string_view name,
	                          Span<const std::string_view> labels, std::string_view helptext,
	                          std::string_view unit = "1", bool is_sum = false);

	IntCounterFamily(const IntCounterFamily&) noexcept = default;
	IntCounterFamily& operator=(const IntCounterFamily&) noexcept = default;

	/**
	 * Returns the metrics handle for given labels, creating a new instance
	 * lazily if necessary.
	 */
	std::shared_ptr<IntCounter> GetOrAdd(Span<const LabelView> labels);

	/**
	 * @copydoc GetOrAdd
	 */
	std::shared_ptr<IntCounter> GetOrAdd(std::initializer_list<LabelView> labels)
		{
		return GetOrAdd(Span{labels.begin(), labels.size()});
		}

private:
	friend class IntCounter;

	using Handle = opentelemetry::metrics::Counter<uint64_t>;

	opentelemetry::nostd::shared_ptr<Handle> instrument;
	};

/**
 * A handle to a metric that represents a floating point value that can only go
 * up.
 */
class DblCounter
	{
public:
	explicit DblCounter(std::shared_ptr<DblCounterFamily> family,
	                    Span<const LabelView> labels) noexcept;

	static inline const char* OpaqueName = "DblCounterMetricVal";

	DblCounter() = delete;
	DblCounter(const DblCounter&) noexcept = default;
	DblCounter& operator=(const DblCounter&) noexcept = default;

	/**
	 * Increments the value by 1.
	 */
	void Inc() noexcept;

	/**
	 * Increments the value by @p amount.
	 * @pre `amount >= 0`
	 */
	void Inc(double amount) noexcept;

	/**
	 * @return The current value.
	 */
	double Value() const noexcept { return value; }

	/**
	 * @return Whether @c this and @p other refer to the same counter.
	 */
	bool IsSameAs(const DblCounter& other) const noexcept
		{
		return family == other.family && attributes == other.attributes;
		}

	bool operator==(const DblCounter& rhs) const noexcept { return IsSameAs(rhs); }
	bool operator!=(const DblCounter& rhs) const noexcept { return ! IsSameAs(rhs); }

private:
	std::shared_ptr<DblCounterFamily> family;
	MetricAttributeIterable attributes;
	double value = 0;
	};

/**
 * Manages a collection of DblCounter metrics.
 */
class DblCounterFamily : public MetricFamily, public std::enable_shared_from_this<DblCounterFamily>
	{
public:
	static inline const char* OpaqueName = "DblCounterMetricFamilyVal";

	using InstanceType = DblCounter;

	explicit DblCounterFamily(std::string_view prefix, std::string_view name,
	                          Span<const std::string_view> labels, std::string_view helptext,
	                          std::string_view unit = "1", bool is_sum = false);

	DblCounterFamily(const DblCounterFamily&) noexcept = default;
	DblCounterFamily& operator=(const DblCounterFamily&) noexcept = default;

	/**
	 * Returns the metrics handle for given labels, creating a new instance
	 * lazily if necessary.
	 */
	std::shared_ptr<DblCounter> GetOrAdd(Span<const LabelView> labels);

	/**
	 * @copydoc GetOrAdd
	 */
	std::shared_ptr<DblCounter> GetOrAdd(std::initializer_list<LabelView> labels)
		{
		return GetOrAdd(Span{labels.begin(), labels.size()});
		}

private:
	friend class DblCounter;

	using Handle = opentelemetry::metrics::Counter<double>;

	opentelemetry::nostd::shared_ptr<Handle> instrument;
	};

namespace detail
	{

template <class T> struct CounterOracle
	{
	static_assert(std::is_same<T, int64_t>::value, "Counter<T> only supports int64_t and double");

	using type = IntCounter;
	};

template <> struct CounterOracle<double>
	{
	using type = DblCounter;
	};

	} // namespace detail

template <class T> using Counter = typename detail::CounterOracle<T>::type;

	} // namespace zeek::telemetry
