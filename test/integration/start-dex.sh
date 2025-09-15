#!/bin/bash
set -e

# Substitute environment variables in the config template
sed -e "s|\${TEST_KEY_FINGERPRINT_1}|${TEST_KEY_FINGERPRINT_1}|g" \
    -e "s|\${TEST_KEY_FINGERPRINT_2}|${TEST_KEY_FINGERPRINT_2}|g" \
    -e "s|\${TEST_KEY_FINGERPRINT_3}|${TEST_KEY_FINGERPRINT_3}|g" \
    /etc/dex/cfg/config.template.yaml > /tmp/config.yaml

# Start dex
exec dex serve /tmp/config.yaml