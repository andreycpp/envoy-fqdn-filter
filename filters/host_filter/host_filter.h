#pragma once

#include "filters/common/firewall_config.h"

#include "source/extensions/filters/http/common/pass_through_filter.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace UrlFilter {

using FirewallConfig = Filters::Common::Firewall::FirewallConfig;
using FirewallConfigSharedPtr = Filters::Common::Firewall::FirewallConfigSharedPtr;

class UrlFilter
    : public Http::PassThroughDecoderFilter,
      Logger::Loggable<Logger::Id::forward_proxy> {
public:
  UrlFilter(const FirewallConfigSharedPtr& config) : config_(config) {}

  // Http::PassThroughDecoderFilter
  Http::FilterHeadersStatus decodeHeaders(Http::RequestHeaderMap& headers,
                                          bool end_stream) override;

private:
  const FirewallConfigSharedPtr config_;
};

} // namespace UrlFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
