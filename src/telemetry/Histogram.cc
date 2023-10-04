#include "zeek/telemetry/Histogram.h"

#include "zeek/Val.h"

#include "opentelemetry/metrics/provider.h"

namespace
	{
// Convert an int64_t or double to a DoubleValPtr. int64_t is casted.
template <typename T> zeek::IntrusivePtr<zeek::DoubleVal> as_double_val(T val)
	{
	if constexpr ( std::is_same_v<T, uint64_t> )
		{
		return zeek::make_intrusive<zeek::DoubleVal>(static_cast<double>(val));
		}
	else
		{
		static_assert(std::is_same_v<T, double>);
		return zeek::make_intrusive<zeek::DoubleVal>(val);
		}
	};

	}

namespace zeek::telemetry
	{

IntHistogramFamily::IntHistogramFamily(std::string_view prefix, std::string_view name,
                                       Span<const std::string_view> labels,
                                       std::string_view helptext, std::string_view unit,
                                       bool is_sum)
	: MetricFamily(prefix, name, labels, helptext, unit, is_sum)
	{
	auto p = opentelemetry::metrics::Provider::GetMeterProvider();
	auto m = p->GetMeter(std::string{prefix});
	instrument = m->CreateUInt64Histogram(std::string{prefix} + "-" + std::string{name},
	                                      std::string{helptext}, std::string{unit});
	}

std::shared_ptr<IntHistogram> IntHistogramFamily::GetOrAdd(Span<const LabelView> labels)
	{
	auto check = [&](const std::shared_ptr<IntHistogram>& histogram)
	{
		return histogram->CompareLabels(labels);
	};

	if ( auto it = std::find_if(histograms.begin(), histograms.end(), check);
	     it != histograms.end() )
		return *it;

	auto histogram = std::make_shared<IntHistogram>(shared_from_this(), labels);
	histograms.push_back(histogram);
	return histogram;
	}

std::vector<CollectedHistogramMetric> IntHistogramFamily::CollectHistogramMetrics() const
	{
	std::vector<CollectedHistogramMetric> metrics;

	for ( const auto& hst : histograms )
		{
		// TODO: the opentelemetry API doesn't have direct access to the bucket information
		// in the histogram instrument. In the meantime we just return an empty set of
		// buckets.

		CollectedHistogramMetric::IntHistogramData histogram_data;
		histogram_data.sum = hst->Sum();

		metrics.emplace_back(BifEnum::Telemetry::MetricType::INT_HISTOGRAM, shared_from_this(),
		                     hst->Labels(), std::move(histogram_data));
		}

	return metrics;
	}

void IntHistogramFamily::AddAdditionalOpts() const
	{
	static auto double_vec_type = zeek::id::find_type<zeek::VectorType>("double_vec");
	static auto count_vec_type = zeek::id::find_type<zeek::VectorType>("index_vec");

	// Add bounds and optionally count_bounds into the MetricOpts record.
	static auto opts_rt = zeek::id::find_type<zeek::RecordType>("Telemetry::MetricOpts");
	static auto opts_rt_idx_bounds = opts_rt->FieldOffset("bounds");
	static auto opts_rt_idx_count_bounds = opts_rt->FieldOffset("count_bounds");

	auto add_double_bounds = [](auto& r, const auto* family)
	{
		size_t buckets = family->NumBuckets();
		auto bounds_vec = make_intrusive<zeek::VectorVal>(double_vec_type);
		for ( size_t i = 0; i < buckets; i++ )
			bounds_vec->Append(as_double_val(family->UpperBoundAt(i)));

		r->Assign(opts_rt_idx_bounds, bounds_vec);
	};

	add_double_bounds(record_val, this);

	// Add count_bounds to int64_t histograms
	size_t buckets = NumBuckets();
	auto count_bounds_vec = make_intrusive<zeek::VectorVal>(count_vec_type);
	for ( size_t i = 0; i < buckets; i++ )
		count_bounds_vec->Append(val_mgr->Count(UpperBoundAt(i)));

	record_val->Assign(opts_rt_idx_count_bounds, count_bounds_vec);
	}

DblHistogramFamily::DblHistogramFamily(std::string_view prefix, std::string_view name,
                                       Span<const std::string_view> labels,
                                       std::string_view helptext, std::string_view unit,
                                       bool is_sum)
	: MetricFamily(prefix, name, labels, helptext, unit, is_sum)
	{
	auto p = opentelemetry::metrics::Provider::GetMeterProvider();
	auto m = p->GetMeter(std::string{prefix});
	instrument = m->CreateDoubleHistogram(std::string{prefix} + "-" + std::string{name},
	                                      std::string{helptext}, std::string{unit});
	}

std::shared_ptr<DblHistogram> DblHistogramFamily::GetOrAdd(Span<const LabelView> labels)
	{
	auto check = [&](const std::shared_ptr<DblHistogram>& histogram)
	{
		return histogram->CompareLabels(labels);
	};

	if ( auto it = std::find_if(histograms.begin(), histograms.end(), check);
	     it != histograms.end() )
		return *it;

	auto histogram = std::make_shared<DblHistogram>(shared_from_this(), labels);
	histograms.push_back(histogram);
	return histogram;
	}

void DblHistogramFamily::AddAdditionalOpts() const
	{
	static auto double_vec_type = zeek::id::find_type<zeek::VectorType>("double_vec");
	static auto count_vec_type = zeek::id::find_type<zeek::VectorType>("index_vec");

	// Add bounds and optionally count_bounds into the MetricOpts record.
	static auto opts_rt = zeek::id::find_type<zeek::RecordType>("Telemetry::MetricOpts");
	static auto opts_rt_idx_bounds = opts_rt->FieldOffset("bounds");
	static auto opts_rt_idx_count_bounds = opts_rt->FieldOffset("count_bounds");

	auto add_double_bounds = [](auto& r, const auto* family)
	{
		size_t buckets = family->NumBuckets();
		auto bounds_vec = make_intrusive<zeek::VectorVal>(double_vec_type);
		for ( size_t i = 0; i < buckets; i++ )
			bounds_vec->Append(as_double_val(family->UpperBoundAt(i)));

		r->Assign(opts_rt_idx_bounds, bounds_vec);
	};

	add_double_bounds(record_val, this);
	}

std::vector<CollectedHistogramMetric> DblHistogramFamily::CollectHistogramMetrics() const
	{
	std::vector<CollectedHistogramMetric> metrics;

	for ( const auto& hst : histograms )
		{
		// TODO: the opentelemetry API doesn't have direct access to the bucket information
		// in the histogram instrument. In the meantime we just return an empty set of
		// buckets.

		CollectedHistogramMetric::DblHistogramData histogram_data;
		histogram_data.sum = hst->Sum();

		metrics.emplace_back(BifEnum::Telemetry::MetricType::DOUBLE_HISTOGRAM, shared_from_this(),
		                     hst->Labels(), std::move(histogram_data));
		}

	return metrics;
	}

	}
