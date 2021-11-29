#pragma once

#include "filters/common/firewall.pb.h"
#include "filters/common/firewall.pb.validate.h"

#include "source/extensions/filters/http/common/factory_base.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace UrlFilter {

using FirewallProto =
    envoy::extensions::filters::common::firewall::v3alpha::FirewallProto;

/**
 * Config registration for the url filter.
 */
class UrlFilterFactory : public Common::FactoryBase<FirewallProto> {
public:
  UrlFilterFactory() : FactoryBase("envoy.filters.http.url_filter") {}

private:
  Http::FilterFactoryCb createFilterFactoryFromProtoTyped(
      const FirewallProto& proto_config,
      const std::string& stats_prefix, Server::Configuration::FactoryContext& context) override;
};

DECLARE_FACTORY(UrlFilterFactory);

} // namespace UrlFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
