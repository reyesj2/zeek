#include "zeek/telemetry/Counter.h"

#include "opentelemetry/metrics/provider.h"

using namespace zeek::telemetry;

IntCounterFamily::IntCounterFamily(std::string_view prefix, std::string_view name,
                                   Span<const std::string_view> labels, std::string_view helptext,
                                   std::string_view unit, bool is_sum)
	: MetricFamily(prefix, name, labels, helptext, unit, is_sum)
	{
	auto p = opentelemetry::metrics::Provider::GetMeterProvider();
	auto m = p->GetMeter(std::string{prefix});
	instrument = m->CreateUInt64Counter(std::string{prefix} + "-" + std::string{name},
	                                    std::string{helptext}, std::string{unit});
	}

// TODO: could GetOrAdd move to MetricFamily and avoid duplicating this code?
std::shared_ptr<IntCounter> IntCounterFamily::GetOrAdd(Span<const LabelView> labels)
	{
	auto check = [&](const std::shared_ptr<IntCounter>& counter)
	{
		return counter->CompareLabels(labels);
	};

	if ( auto it = std::find_if(counters.begin(), counters.end(), check); it != counters.end() )
		return *it;

	auto counter = std::make_shared<IntCounter>(shared_from_this(), labels);
	counters.push_back(counter);
	return counter;
	}

/**
 * @return All counter and gauge metrics and their values matching prefix and name.
 * @param prefix The prefix pattern to use for filtering. Supports globbing.
 * @param name The name pattern to use for filtering. Supports globbing.
 */
std::vector<CollectedValueMetric> IntCounterFamily::CollectMetrics() const
	{
	std::vector<CollectedValueMetric> result;
	result.reserve(counters.size());

	for ( const auto& cntr : counters )
		result.emplace_back(BifEnum::Telemetry::MetricType::INT_COUNTER, shared_from_this(),
		                    cntr->Labels(), cntr->Value());

	return result;
	}

DblCounterFamily::DblCounterFamily(std::string_view prefix, std::string_view name,
                                   Span<const std::string_view> labels, std::string_view helptext,
                                   std::string_view unit, bool is_sum)
	: MetricFamily(prefix, name, labels, helptext, unit, is_sum)
	{
	auto p = opentelemetry::metrics::Provider::GetMeterProvider();
	auto m = p->GetMeter(std::string{prefix});
	instrument = m->CreateDoubleCounter(std::string{prefix} + "-" + std::string{name},
	                                    std::string{helptext}, std::string{unit});
	}

std::shared_ptr<DblCounter> DblCounterFamily::GetOrAdd(Span<const LabelView> labels)
	{
	auto check = [&](const std::shared_ptr<DblCounter>& counter)
	{
		return counter->CompareLabels(labels);
	};

	if ( auto it = std::find_if(counters.begin(), counters.end(), check); it != counters.end() )
		return *it;

	auto counter = std::make_shared<DblCounter>(shared_from_this(), labels);
	counters.push_back(counter);
	return counter;
	}

/**
 * @return All counter and gauge metrics and their values matching prefix and name.
 * @param prefix The prefix pattern to use for filtering. Supports globbing.
 * @param name The name pattern to use for filtering. Supports globbing.
 */
std::vector<CollectedValueMetric> DblCounterFamily::CollectMetrics() const
	{
	std::vector<CollectedValueMetric> result;
	result.reserve(counters.size());

	for ( const auto& cntr : counters )
		result.emplace_back(BifEnum::Telemetry::MetricType::DOUBLE_COUNTER, shared_from_this(),
		                    cntr->Labels(), cntr->Value());

	return result;
	}
