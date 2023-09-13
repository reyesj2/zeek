#include "zeek/telemetry/Gauge.h"

#include "opentelemetry/metrics/provider.h"

using namespace zeek::telemetry;

IntGaugeFamily::IntGaugeFamily(std::string_view prefix, std::string_view name,
                               Span<const std::string_view> labels, std::string_view helptext,
                               std::string_view unit, bool is_sum)
	: MetricFamily(prefix, name, labels, helptext, unit, is_sum)
	{
	auto p = opentelemetry::metrics::Provider::GetMeterProvider();
	auto m = p->GetMeter(std::string{prefix});
	instrument = m->CreateInt64UpDownCounter(std::string{prefix} + "-" + std::string{name},
	                                         std::string{helptext}, std::string{unit});
	}

std::shared_ptr<IntGauge> IntGaugeFamily::GetOrAdd(Span<const LabelView> labels)
	{
	return std::make_shared<IntGauge>(shared_from_this(), labels);
	}

IntGauge::IntGauge(std::shared_ptr<IntGaugeFamily> family, Span<const LabelView> labels) noexcept
	: family(std::move(family)), attributes(labels)
	{
	}

/**
 * Increments the value by 1.
 */
void IntGauge::Inc() noexcept
	{
	family->instrument->Add(1, attributes);
	value++;
	}

/**
 * Increments the value by @p amount.
 */
void IntGauge::Inc(int64_t amount) noexcept
	{
	family->instrument->Add(amount, attributes);
	value += amount;
	}

/**
 * Increments the value by 1.
 * @return The new value.
 */
int64_t IntGauge::operator++() noexcept
	{
	Inc();
	return value;
	}

/**
 * Decrements the value by 1.
 */
void IntGauge::Dec() noexcept
	{
	family->instrument->Add(-1, attributes);
	value--;
	}

/**
 * Decrements the value by @p amount.
 */
void IntGauge::Dec(int64_t amount) noexcept
	{
	family->instrument->Add(amount * -1);
	value -= amount;
	}

/**
 * Decrements the value by 1.
 * @return The new value.
 */
int64_t IntGauge::operator--() noexcept
	{
	Dec();
	return value;
	}

DblGaugeFamily::DblGaugeFamily(std::string_view prefix, std::string_view name,
                               Span<const std::string_view> labels, std::string_view helptext,
                               std::string_view unit, bool is_sum)
	: MetricFamily(prefix, name, labels, helptext, unit, is_sum)
	{
	auto p = opentelemetry::metrics::Provider::GetMeterProvider();
	auto m = p->GetMeter(std::string{prefix});
	instrument = m->CreateDoubleUpDownCounter(std::string{prefix} + "-" + std::string{name},
	                                          std::string{helptext}, std::string{unit});
	}

std::shared_ptr<DblGauge> DblGaugeFamily::GetOrAdd(Span<const LabelView> labels)
	{
	return std::make_shared<DblGauge>(shared_from_this(), labels);
	}

DblGauge::DblGauge(std::shared_ptr<DblGaugeFamily> family, Span<const LabelView> labels) noexcept
	: family(std::move(family)), attributes(labels)
	{
	}

/**
 * Increments the value by 1.
 */
void DblGauge::Inc() noexcept
	{
	family->instrument->Add(1, attributes);
	value++;
	}

/**
 * Increments the value by @p amount.
 */
void DblGauge::Inc(double amount) noexcept
	{
	family->instrument->Add(amount, attributes);
	value += amount;
	}

/**
 * Decrements the value by 1.
 */
void DblGauge::Dec() noexcept
	{
	family->instrument->Add(-1, attributes);
	value--;
	}

/**
 * Decrements the value by @p amount.
 */
void DblGauge::Dec(double amount) noexcept
	{
	family->instrument->Add(amount * -1);
	value -= amount;
	}
