#!/bin/bash
set -e

# create envoy user and give access to envoy
sudo useradd envoy -G $(id -gn) || true
chmod a+rx $HOME/.cache
# sudo rm /dev/shm/envoy_shared_memory_0

sudo iptables -t nat -F
sudo iptables -t nat -A OUTPUT -m owner ! --uid-owner envoy -p tcp --dport 443 -j REDIRECT --to-port 8443
sudo iptables -t nat -A OUTPUT -m owner ! --uid-owner envoy -p tcp --dport 80 -j REDIRECT --to-port 8080

echo start envoy as user'envoy': sudo -u envoy ../bazel-bin/filters/envoy -c sni_http_filter_example.yaml
