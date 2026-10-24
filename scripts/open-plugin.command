#!/bin/sh
# Register the public source and open the host's own installation confirmation.
set -eu

if [ "$(uname -s)" != Darwin ]; then
  echo 'Questo script richiede ChatGPT desktop su macOS.' >&2
  exit 1
fi

plugin_cli='/Applications/ChatGPT.app/Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex'
if [ ! -x "$plugin_cli" ]; then
  plugin_cli="$HOME/Applications/ChatGPT.app/Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex"
fi
if [ ! -x "$plugin_cli" ]; then
  echo 'Installa o aggiorna ChatGPT desktop prima di aggiungere OmniAgents.' >&2
  exit 1
fi

if [ "${1:-}" = '--check' ]; then
  "$plugin_cli" plugin marketplace add --help >/dev/null
  printf '%s\n' 'CLI ChatGPT disponibile. Nessuna configurazione modificata.'
  exit 0
fi
if [ "$#" -gt 0 ]; then
  echo 'Uso: open-plugin.command [--check]' >&2
  exit 2
fi

"$plugin_cli" plugin marketplace add \
  'https://github.com/Grooves76/omniagents-plugin.git' --ref main --json
open 'codex://plugins/install/omniagents?marketplace=omniagents'
