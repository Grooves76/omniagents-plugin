#!/bin/sh
# Prefer the Business runtime. The final argument always selects Business.
set -eu
plugin_bin=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
for python_runtime in "/Applications/OmniAgents Business.app/Contents/Resources/product/runtime/python/bin/python3.13" "/Applications/OmniAgents.app/Contents/Resources/product/runtime/python/bin/python3.13"; do
    if [ -x "$python_runtime" ]; then
        exec "$python_runtime" -B "$plugin_bin/omniagents_bridge.py" "$@" --instance business
    fi
done
exec python3 -B "$plugin_bin/omniagents_bridge.py" "$@" --instance business
