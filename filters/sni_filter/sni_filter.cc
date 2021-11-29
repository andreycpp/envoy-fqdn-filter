#include "filters/sni_filter/sni_filter.h"
#include "envoy/network/connection.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace SniFilter {

using Rule =
    envoy::extensions::filters::common::firewall::v3alpha::Rule;

Network::FilterStatus SniFilter::onNewConnection() {
  absl::string_view sni = read_callbacks_->connection().requestedServerName();

  auto [action, reason] = config_->match(sni);

  ENVOY_CONN_LOG(info, "sni_filter: host '{}' result {} reason {}", read_callbacks_->connection(), sni, Filters::Common::Firewall::ToString(action), reason);

  if (action == Rule::DENY) {
    read_callbacks_->connection().close(Network::ConnectionCloseType::NoFlush);
    return Network::FilterStatus::StopIteration;
  }

  return Network::FilterStatus::Continue;
}

} // namespace SniFilter
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
