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

class DblHistogramFamily;
class IntHistogramFamily;
class Manager;

template <typename Family, typename BaseType> class BaseHistogram
	{
public:
	/**
	 * Increments all buckets with an upper bound less than or equal to @p value
	 * by one and adds @p value to the total sum of all observed values.
	 */
	void Observe(BaseType value) noexcept
		{
		family->Instrument()->Record(value, attributes, context);
		sum += value;
		}

	/// @return The sum of all observed values.
	BaseType Sum() const noexcept { return sum; }

	// TODO: the opentelemetry API doesn't have direct access to the bucket information
	// in the histogram instrument.

	// /// @return The number of buckets, including the implicit "infinite" bucket.
	// size_t NumBuckets() const noexcept { return broker::telemetry::num_buckets(hdl); }

	// /// @return The number of observations in the bucket at @p index.
	// /// @pre index < NumBuckets()
	// BaseType CountAt(size_t index) const noexcept { return broker::telemetry::count_at(hdl,
	// index); }

	// /// @return The upper bound of the bucket at @p index.
	// /// @pre index < NumBuckets()
	// BaseType UpperBoundAt(size_t index) const noexcept
	//		{
	//		return broker::telemetry::upper_bound_at(hdl, index);
	//		}

	/**
	 * @return Whether @c this and @p other refer to the same histogram.
	 */
	bool IsSameAs(const BaseHistogram& other) const noexcept
		{
		return family == other.family && attributes == other.attributes;
		}

	bool operator==(const BaseHistogram& other) const noexcept { return IsSameAs(other); }
	bool operator!=(const BaseHistogram& other) const noexcept { return ! IsSameAs(other); }

	bool CompareLabels(const Span<const LabelView>& labels) const { return attributes == labels; }

protected:
	explicit BaseHistogram(std::shared_ptr<Family> family, Span<const LabelView> labels) noexcept
		: family(std::move(family)), attributes(labels)
		{
		}

	std::shared_ptr<Family> family;
	MetricAttributeIterable attributes;
	opentelemetry::context::Context context;
	BaseType sum = 0;
	};

/**
 * A handle to a metric that represents an aggregable distribution of observed
 * measurements with integer precision. Sorts individual measurements into
 * configurable buckets.
 */
class IntHistogram : public BaseHistogram<IntHistogramFamily, uint64_t>
	{
public:
	static inline const char* OpaqueName = "IntHistogramMetricVal";

	explicit IntHistogram(std::shared_ptr<IntHistogramFamily> family,
	                      Span<const LabelView> labels) noexcept
		: BaseHistogram(std::move(family), labels)
		{
		}

	IntHistogram() = delete;
	IntHistogram(const IntHistogram&) noexcept = default;
	IntHistogram& operator=(const IntHistogram&) noexcept = default;
	};

/**
 * Manages a collection of IntHistogram metrics.
 */
class IntHistogramFamily : public MetricFamily,
						   public std::enable_shared_from_this<IntHistogramFamily>
	{
public:
	static inline const char* OpaqueName = "IntHistogramMetricFamilyVal";

	using InstanceType = IntHistogram;
	using Handle = opentelemetry::metrics::Histogram<uint64_t>;

	IntHistogramFamily(std::string_view prefix, std::string_view name,
	                   Span<const std::string_view> labels, std::string_view helptext,
	                   std::string_view unit = "1", bool is_sum = false);

	IntHistogramFamily(const IntHistogramFamily&) noexcept = default;
	IntHistogramFamily& operator=(const IntHistogramFamily&) noexcept = default;

	/**
	 * Returns the metrics handle for given labels, creating a new instance
	 * lazily if necessary.
	 */
	std::shared_ptr<IntHistogram> GetOrAdd(Span<const LabelView> labels);

	/**
	 * @copydoc GetOrAdd
	 */
	std::shared_ptr<IntHistogram> GetOrAdd(std::initializer_list<LabelView> labels)
		{
		return GetOrAdd(Span{labels.begin(), labels.size()});
		}

	opentelemetry::nostd::shared_ptr<Handle>& Instrument() { return instrument; }

private:
	opentelemetry::nostd::shared_ptr<Handle> instrument;
	std::vector<std::shared_ptr<InstanceType>> histograms;
	};

/**
 * A handle to a metric that represents an aggregable distribution of observed
 * measurements with integer precision. Sorts individual measurements into
 * configurable buckets.
 */
class DblHistogram : public BaseHistogram<DblHistogramFamily, double>
	{
public:
	static inline const char* OpaqueName = "DblHistogramMetricVal";

	explicit DblHistogram(std::shared_ptr<DblHistogramFamily> family,
	                      Span<const LabelView> labels) noexcept
		: BaseHistogram(std::move(family), labels)
		{
		}

	DblHistogram() = delete;
	DblHistogram(const DblHistogram&) noexcept = default;
	DblHistogram& operator=(const DblHistogram&) noexcept = default;
	};

/**
 * Manages a collection of DblHistogram metrics.
 */
class DblHistogramFamily : public MetricFamily,
						   public std::enable_shared_from_this<DblHistogramFamily>
	{
public:
	static inline const char* OpaqueName = "DblHistogramMetricFamilyVal";

	using InstanceType = DblHistogram;
	using Handle = opentelemetry::metrics::Histogram<double>;

	DblHistogramFamily(std::string_view prefix, std::string_view name,
	                   Span<const std::string_view> labels, std::string_view helptext,
	                   std::string_view unit = "1", bool is_sum = false);

	DblHistogramFamily(const DblHistogramFamily&) noexcept = default;
	DblHistogramFamily& operator=(const DblHistogramFamily&) noexcept = default;

	/**
	 * Returns the metrics handle for given labels, creating a new instance
	 * lazily if necessary.
	 */
	std::shared_ptr<DblHistogram> GetOrAdd(Span<const LabelView> labels);

	/**
	 * @copydoc GetOrAdd
	 */
	std::shared_ptr<DblHistogram> GetOrAdd(std::initializer_list<LabelView> labels)
		{
		return GetOrAdd(Span{labels.begin(), labels.size()});
		}

	opentelemetry::nostd::shared_ptr<Handle>& Instrument() { return instrument; }

private:
	opentelemetry::nostd::shared_ptr<Handle> instrument;
	std::vector<std::shared_ptr<InstanceType>> histograms;
	};

namespace detail
	{

template <class T> struct HistogramOracle
	{
	static_assert(std::is_same<T, int64_t>::value, "Histogram<T> only supports int64_t and double");

	using type = IntHistogram;
	};

template <> struct HistogramOracle<double>
	{
	using type = DblHistogram;
	};

	} // namespace detail

template <class T> using Histogram = typename detail::HistogramOracle<T>::type;

	} // namespace zeek::telemetry
