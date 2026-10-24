#!/bin/sh
# Prefer the runtime shipped with the current installation. No downloads.
set -eu
plugin_bin=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
for python_runtime in "/Applications/OmniAgents.app/Contents/Resources/product/runtime/python/bin/python3.13" "/Applications/OmniAgents Business.app/Contents/Resources/product/runtime/python/bin/python3.13"; do
    if [ -x "$python_runtime" ]; then
        exec "$python_runtime" -B "$plugin_bin/omniagents_bridge.py" "$@"
    fi
done
exec python3 -B "$plugin_bin/omniagents_bridge.py" "$@"
