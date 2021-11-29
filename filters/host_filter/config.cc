#include "filters/host_filter/config.h"
#include "filters/host_filter/host_filter.h"

#include "filters/common/firewall_config.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace UrlFilter {

Http::FilterFactoryCb UrlFilterFactory::createFilterFactoryFromProtoTyped(
    const FirewallProto& proto_config,
    const std::string&, Server::Configuration::FactoryContext&) {

  auto filter_config = std::make_shared<FirewallConfig>(proto_config);

  return [filter_config](Http::FilterChainFactoryCallbacks& callbacks) -> void {
    callbacks.addStreamDecoderFilter(std::make_shared<UrlFilter>(filter_config));
  };
}

/**
 * Static registration for the dynamic forward proxy filter. @see RegisterFactory.
 */
REGISTER_FACTORY(UrlFilterFactory,
                 Server::Configuration::NamedHttpFilterConfigFactory);

} // namespace UrlFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
