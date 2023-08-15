#include "zeek/telemetry/Gauge.h"

#include "opentelemetry/metrics/provider.h"

using namespace zeek::telemetry;

IntGaugeFamily::IntGaugeFamily(std::string_view prefix, std::string_view name,
                               Span<const std::string_view> labels, std::string_view helptext,
                               std::string_view unit, bool is_sum)
	: MetricFamily(prefix, name, labels, helptext, unit, is_sum)
	{
	}

IntGauge IntGaugeFamily::GetOrAdd(Span<const LabelView> labels)
	{
	auto p = opentelemetry::metrics::Provider::GetMeterProvider();
	auto m = p->GetMeter(prefix);
	return IntGauge{m->CreateInt64UpDownCounter(name, helptext, unit), labels};
	}

IntGauge::IntGauge(opentelemetry::nostd::shared_ptr<Handle> hdl,
                   Span<const LabelView> labels) noexcept
	: hdl(std::move(hdl)), attributes(labels)
	{
	}

DblGaugeFamily::DblGaugeFamily(std::string_view prefix, std::string_view name,
                               Span<const std::string_view> labels, std::string_view helptext,
                               std::string_view unit, bool is_sum)
	: MetricFamily(prefix, name, labels, helptext, unit, is_sum)
	{
	}

DblGauge DblGaugeFamily::GetOrAdd(Span<const LabelView> labels)
	{
	auto p = opentelemetry::metrics::Provider::GetMeterProvider();
	auto m = p->GetMeter(prefix);
	return DblGauge{m->CreateDoubleUpDownCounter(name, helptext, unit), labels};
	}

DblGauge::DblGauge(opentelemetry::nostd::shared_ptr<Handle> hdl,
                   Span<const LabelView> labels) noexcept
	: hdl(std::move(hdl)), attributes(labels)
	{
	}
