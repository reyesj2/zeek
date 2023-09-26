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

template <typename Family, typename BaseType> class BaseCounter
	{
public:
	BaseCounter() = delete;
	BaseCounter(const BaseCounter&) = default;
	BaseCounter& operator=(const BaseCounter&) noexcept = default;

	/**
	 * Increments the value by 1.
	 */
	void Inc() noexcept { Inc(1); }

	/**
	 * Increments the value by @p amount.
	 * @pre `amount >= 0`
	 */
	void Inc(BaseType amount) noexcept
		{
		family->Instrument()->Add(amount, attributes);
		value += amount;
		}

	/**
	 * Increments the value by 1.
	 * @return The new value.
	 */
	BaseType operator++() noexcept
		{
		Inc(1);
		return value;
		}

	BaseType Value() const noexcept { return value; }

	/**
	 * @return Whether @c this and @p other refer to the same counter.
	 */
	bool IsSameAs(const BaseCounter<Family, BaseType>& other) const noexcept
		{
		return family == other.family && attributes == other.attributes;
		}

	bool operator==(const BaseCounter<Family, BaseType>& rhs) const noexcept
		{
		return IsSameAs(rhs);
		}
	bool operator!=(const BaseCounter<Family, BaseType>& rhs) const noexcept
		{
		return ! IsSameAs(rhs);
		}

	bool CompareLabels(const Span<const LabelView>& labels) const { return attributes == labels; }

protected:
	explicit BaseCounter(std::shared_ptr<Family> family, Span<const LabelView> labels) noexcept
		: family(std::move(family)), attributes(labels)
		{
		}

	std::shared_ptr<Family> family;
	MetricAttributeIterable attributes;
	BaseType value = 0;
	};

/**
 * A handle to a metric that represents an integer value that can only go up.
 */
class IntCounter : public BaseCounter<IntCounterFamily, uint64_t>
	{
public:
	static inline const char* OpaqueName = "IntCounterMetricVal";
	explicit IntCounter(std::shared_ptr<IntCounterFamily> family,
	                    Span<const LabelView> labels) noexcept
		: BaseCounter(std::move(family), labels)
		{
		}
	};

/**
 * Manages a collection of IntCounter metrics.
 */
class IntCounterFamily : public MetricFamily, public std::enable_shared_from_this<IntCounterFamily>
	{
public:
	static inline const char* OpaqueName = "IntCounterMetricFamilyVal";

	using InstanceType = IntCounter;
	using Handle = opentelemetry::metrics::Counter<uint64_t>;

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

	opentelemetry::nostd::shared_ptr<Handle>& Instrument() { return instrument; }

private:
	friend class IntCounter;

	opentelemetry::nostd::shared_ptr<Handle> instrument;
	std::vector<std::shared_ptr<InstanceType>> counters;
	};

/**
 * A handle to a metric that represents an floating point value that can only go up.
 */
class DblCounter : public BaseCounter<DblCounterFamily, double>
	{
public:
	static inline const char* OpaqueName = "DblCounterMetricVal";
	explicit DblCounter(std::shared_ptr<DblCounterFamily> family,
	                    Span<const LabelView> labels) noexcept
		: BaseCounter(std::move(family), labels)
		{
		}
	};

/**
 * Manages a collection of DblCounter metrics.
 */
class DblCounterFamily : public MetricFamily, public std::enable_shared_from_this<DblCounterFamily>
	{
public:
	static inline const char* OpaqueName = "DblCounterMetricFamilyVal";

	using InstanceType = DblCounter;
	using Handle = opentelemetry::metrics::Counter<double>;

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

	opentelemetry::nostd::shared_ptr<Handle>& Instrument() { return instrument; }

private:
	opentelemetry::nostd::shared_ptr<Handle> instrument;
	std::vector<std::shared_ptr<InstanceType>> counters;
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
