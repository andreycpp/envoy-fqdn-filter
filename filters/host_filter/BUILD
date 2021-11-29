load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

package(default_visibility = ["//visibility:public"])

envoy_cc_library(
    name = "host_filter_lib",
    srcs = ["host_filter.cc"],
    hdrs = ["host_filter.h"],
    repository = "@envoy",
    deps = [
        "@envoy//envoy/http:filter_interface",
        "@envoy//source/extensions/filters/http/common:pass_through_filter_lib",
        "//filters/common:firewall_config_lib",
    ],
)

envoy_cc_library(
    name = "config",
    srcs = ["config.cc"],
    hdrs = ["config.h"],
    repository = "@envoy",
    deps = [
        "@envoy//envoy/registry",
        "@envoy//envoy/server:filter_config_interface",
        "@envoy//source/extensions/filters/http/common:factory_base_lib",
        ":host_filter_lib",
    ],
)



