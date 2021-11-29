load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
)

load("@envoy_api//bazel:api_build_system.bzl", "api_proto_package")

licenses(["notice"])  # Apache 2

package(default_visibility = ["//visibility:public"])

api_proto_package(
    deps = [
        "@envoy_api//envoy/config/core/v3:pkg",
        "@com_github_cncf_udpa//udpa/annotations:pkg",
    ],
)

envoy_cc_library(
    name = "firewall_config_lib",
    srcs = ["firewall_config.cc"],
    hdrs = ["firewall_config.h"],
    repository = "@envoy",
    deps = [
        ":pkg_cc_proto",
    ],
)
