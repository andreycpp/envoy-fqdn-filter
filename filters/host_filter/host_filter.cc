#include "filters/host_filter/host_filter.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace UrlFilter {

using Rule =
    envoy::extensions::filters::common::firewall::v3alpha::Rule;

const auto DenyTraffic = "Denied traffic";

Http::FilterHeadersStatus UrlFilter::decodeHeaders(Http::RequestHeaderMap& headers, bool) {
  auto host = headers.Host()->value().getStringView();
  std::vector<absl::string_view> hostParts = absl::StrSplit(host, ':');

  auto [action, reason] = config_->match(hostParts[0]);

  ENVOY_STREAM_LOG(info, "url_filter: host '{}' result {} reason {}", *decoder_callbacks_, host, Filters::Common::Firewall::ToString(action), reason);

  if (action == Rule::DENY) {
    decoder_callbacks_->sendLocalReply(Http::Code::Unauthorized,
                                       DenyTraffic, nullptr,
                                       absl::nullopt, DenyTraffic);
    return Http::FilterHeadersStatus::StopIteration;
  }

  return Http::FilterHeadersStatus::Continue;
}

} // namespace UrlFilter
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
