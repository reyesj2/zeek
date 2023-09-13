#include "zeek/telemetry/Histogram.h"

#include "opentelemetry/metrics/provider.h"

using namespace zeek::telemetry;

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
	return std::make_shared<IntHistogram>(shared_from_this(), labels);
	}

IntHistogram::IntHistogram(std::shared_ptr<IntHistogramFamily> family,
                           Span<const LabelView> labels) noexcept
	: family(std::move(family)), attributes(labels)
	{
	}

void IntHistogram::Observe(uint64_t value) noexcept
	{
	family->instrument->Record(value, attributes, context);
	sum += value;
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
	return std::make_shared<DblHistogram>(shared_from_this(), labels);
	}

DblHistogram::DblHistogram(std::shared_ptr<DblHistogramFamily> family,
                           Span<const LabelView> labels) noexcept
	: family(std::move(family)), attributes(labels)
	{
	}

void DblHistogram::Observe(double value) noexcept
	{
	family->instrument->Record(value, attributes, context);
	sum += value;
	}
