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

/**
 * A handle to a metric that represents an aggregable distribution of observed
 * measurements with integer precision. Sorts individual measurements into
 * configurable buckets.
 */
class IntHistogram
	{
public:
	static inline const char* OpaqueName = "IntHistogramMetricVal";

	explicit IntHistogram(std::shared_ptr<IntHistogramFamily> family,
	                      Span<const LabelView> labels) noexcept;

	IntHistogram() = delete;
	IntHistogram(const IntHistogram&) noexcept = default;
	IntHistogram& operator=(const IntHistogram&) noexcept = default;

	/**
	 * Increments all buckets with an upper bound less than or equal to @p value
	 * by one and adds @p value to the total sum of all observed values.
	 */
	void Observe(uint64_t value) noexcept;

	/// @return The sum of all observed values.
	uint64_t Sum() const noexcept { return sum; }

	// TODO: the opentelemetry API doesn't have direct access to the bucket information
	// in the histogram instrument.

	// /// @return The number of buckets, including the implicit "infinite" bucket.
	// size_t NumBuckets() const noexcept { return broker::telemetry::num_buckets(hdl); }

	// /// @return The number of observations in the bucket at @p index.
	// /// @pre index < NumBuckets()
	// uint64_t CountAt(size_t index) const noexcept { return broker::telemetry::count_at(hdl,
	// index); }

	// /// @return The upper bound of the bucket at @p index.
	// /// @pre index < NumBuckets()
	// uint64_t UpperBoundAt(size_t index) const noexcept
	//		{
	//		return broker::telemetry::upper_bound_at(hdl, index);
	//		}

	/**
	 * @return Whether @c this and @p other refer to the same histogram.
	 */
	bool IsSameAs(const IntHistogram& other) const noexcept
		{
		return family == other.family && attributes == other.attributes;
		}

	bool operator==(const IntHistogram& other) const noexcept { return IsSameAs(other); }
	bool operator!=(const IntHistogram& other) const noexcept { return ! IsSameAs(other); }

private:
	std::shared_ptr<IntHistogramFamily> family;
	MetricAttributeIterable attributes;
	opentelemetry::context::Context context;
	uint64_t sum = 0;
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

private:
	friend class IntHistogram;

	using Handle = opentelemetry::metrics::Histogram<uint64_t>;

	opentelemetry::nostd::shared_ptr<Handle> instrument;
	};

/**
 * A handle to a metric that represents an aggregable distribution of observed
 * measurements with floating point precision. Sorts individual measurements
 * into configurable buckets.
 */
class DblHistogram
	{
public:
	static inline const char* OpaqueName = "DblHistogramMetricVal";

	explicit DblHistogram(std::shared_ptr<DblHistogramFamily> family,
	                      Span<const LabelView> labels) noexcept;

	DblHistogram() = delete;
	DblHistogram(const DblHistogram&) noexcept = default;
	DblHistogram& operator=(const DblHistogram&) noexcept = default;

	/**
	 * Increments all buckets with an upper bound less than or equal to @p value
	 * by one and adds @p value to the total sum of all observed values.
	 */
	void Observe(double value) noexcept;

	/// @return The sum of all observed values.
	double Sum() const noexcept { return sum; }

	// TODO: the opentelemetry API doesn't have direct access to the bucket information
	// in the histogram instrument.

	// /// @return The number of buckets, including the implicit "infinite" bucket.
	// size_t NumBuckets() const noexcept { return broker::telemetry::num_buckets(hdl); }

	// /// @return The number of observations in the bucket at @p index.
	// /// @pre index < NumBuckets()
	// int64_t CountAt(size_t index) const noexcept { return broker::telemetry::count_at(hdl,
	// index); }

	// /// @return The upper bound of the bucket at @p index.
	// /// @pre index < NumBuckets()
	// double UpperBoundAt(size_t index) const noexcept
	//	{
	//	return broker::telemetry::upper_bound_at(hdl, index);
	//	}

	/**
	 * @return Whether @c this and @p other refer to the same histogram.
	 */
	bool IsSameAs(const DblHistogram& other) const noexcept
		{
		return family == other.family && attributes == other.attributes;
		}

	bool operator==(const DblHistogram& other) const noexcept { return IsSameAs(other); }
	bool operator!=(const DblHistogram& other) const noexcept { return ! IsSameAs(other); }

private:
	std::shared_ptr<DblHistogramFamily> family;
	MetricAttributeIterable attributes;
	opentelemetry::context::Context context;
	double sum = 0;
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

private:
	friend class DblHistogram;

	using Handle = opentelemetry::metrics::Histogram<double>;

	opentelemetry::nostd::shared_ptr<Handle> instrument;
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
