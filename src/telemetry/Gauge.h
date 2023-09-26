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

class DblGaugeFamily;
class IntGaugeFamily;
class Manager;

template <typename Family, typename BaseType> class BaseGauge
	{
public:
	/**
	 * Increments the value by 1.
	 */
	void Inc() noexcept { Inc(1); }

	/**
	 * Increments the value by @p amount.
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

	/**
	 * Decrements the value by 1.
	 */
	void Dec() noexcept { Dec(1); }

	/**
	 * Decrements the value by @p amount.
	 */
	void Dec(int64_t amount) noexcept
		{
		family->Instrument()->Add(amount * -1, attributes);
		value -= amount;
		}

	/**
	 * Decrements the value by 1.
	 * @return The new value.
	 */
	int64_t operator--() noexcept
		{
		Dec(1);
		return value;
		}

	BaseType Value() const noexcept { return value; }

	/**
	 * @return Whether @c this and @p other refer to the same counter.
	 */
	bool IsSameAs(const BaseGauge<Family, BaseType>& other) const noexcept
		{
		return family == other.family && attributes == other.attributes;
		}

	bool operator==(const BaseGauge<Family, BaseType>& rhs) const noexcept { return IsSameAs(rhs); }
	bool operator!=(const BaseGauge<Family, BaseType>& rhs) const noexcept
		{
		return ! IsSameAs(rhs);
		}

	bool CompareLabels(const Span<const LabelView>& labels) const { return attributes == labels; }

protected:
	explicit BaseGauge(std::shared_ptr<Family> family, Span<const LabelView> labels) noexcept
		: family(std::move(family)), attributes(labels)
		{
		}

	std::shared_ptr<Family> family;
	MetricAttributeIterable attributes;
	BaseType value = 0;
	};

/**
 * A handle to a metric that represents an integer value. Gauges are more
 * permissive than counters and also allow decrementing the value.
 */
class IntGauge : public BaseGauge<IntGaugeFamily, int64_t>
	{
public:
	static inline const char* OpaqueName = "IntGaugeMetricVal";
	explicit IntGauge(std::shared_ptr<IntGaugeFamily> family, Span<const LabelView> labels) noexcept
		: BaseGauge(std::move(family), labels)
		{
		}
	};

/**
 * Manages a collection of IntGauge metrics.
 */
class IntGaugeFamily : public MetricFamily, public std::enable_shared_from_this<IntGaugeFamily>
	{
public:
	static inline const char* OpaqueName = "IntGaugeMetricFamilyVal";

	using InstanceType = IntGauge;
	using Handle = opentelemetry::metrics::UpDownCounter<int64_t>;

	IntGaugeFamily(std::string_view prefix, std::string_view name,
	               Span<const std::string_view> labels, std::string_view helptext,
	               std::string_view unit = "1", bool is_sum = false);

	IntGaugeFamily(const IntGaugeFamily&) noexcept = default;
	IntGaugeFamily& operator=(const IntGaugeFamily&) noexcept = default;

	/**
	 * Returns the metrics handle for given labels, creating a new instance
	 * lazily if necessary.
	 */
	std::shared_ptr<IntGauge> GetOrAdd(Span<const LabelView> labels);

	/**
	 * @copydoc GetOrAdd
	 */
	std::shared_ptr<IntGauge> GetOrAdd(std::initializer_list<LabelView> labels)
		{
		return GetOrAdd(Span{labels.begin(), labels.size()});
		}

	opentelemetry::nostd::shared_ptr<Handle>& Instrument() { return instrument; }

private:
	opentelemetry::nostd::shared_ptr<Handle> instrument;
	std::vector<std::shared_ptr<InstanceType>> gauges;
	};

/**
 * A handle to a metric that represents an floating point  value. Gauges are more
 * permissive than counters and also allow decrementing the value.
 */
class DblGauge : public BaseGauge<DblGaugeFamily, double>
	{
public:
	static inline const char* OpaqueName = "DblGaugeMetricVal";
	explicit DblGauge(std::shared_ptr<DblGaugeFamily> family, Span<const LabelView> labels) noexcept
		: BaseGauge(std::move(family), labels)
		{
		}
	};

/**
 * Manages a collection of DblGauge metrics.
 */
class DblGaugeFamily : public MetricFamily, public std::enable_shared_from_this<DblGaugeFamily>
	{
public:
	static inline const char* OpaqueName = "DblGaugeMetricFamilyVal";

	using InstanceType = DblGauge;
	using Handle = opentelemetry::metrics::UpDownCounter<double>;

	DblGaugeFamily(std::string_view prefix, std::string_view name,
	               Span<const std::string_view> labels, std::string_view helptext,
	               std::string_view unit = "1", bool is_sum = false);

	DblGaugeFamily(const DblGaugeFamily&) noexcept = default;
	DblGaugeFamily& operator=(const DblGaugeFamily&) noexcept = default;

	/**
	 * Returns the metrics handle for given labels, creating a new instance
	 * lazily if necessary.
	 */
	std::shared_ptr<DblGauge> GetOrAdd(Span<const LabelView> labels);

	/**
	 * @copydoc GetOrAdd
	 */
	std::shared_ptr<DblGauge> GetOrAdd(std::initializer_list<LabelView> labels)
		{
		return GetOrAdd(Span{labels.begin(), labels.size()});
		}

	opentelemetry::nostd::shared_ptr<Handle>& Instrument() { return instrument; }

private:
	opentelemetry::nostd::shared_ptr<Handle> instrument;
	std::vector<std::shared_ptr<InstanceType>> gauges;
	};

namespace detail
	{

template <class T> struct GaugeOracle
	{
	static_assert(std::is_same<T, int64_t>::value, "Gauge<T> only supports int64_t and double");

	using type = IntGauge;
	};

template <> struct GaugeOracle<double>
	{
	using type = DblGauge;
	};

	} // namespace detail

template <class T> using Gauge = typename detail::GaugeOracle<T>::type;

	} // namespace zeek::telemetry
