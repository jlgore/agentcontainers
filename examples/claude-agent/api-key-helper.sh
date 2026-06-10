#!/usr/bin/env sh
# apiKeyHelper for Claude Code: print the Anthropic API key to stdout.
#
# The key is read from the tmpfs secret that agentcontainers injects via the
# enforcer at /run/secrets/ANTHROPIC_API_KEY — never from an environment
# variable, so it does not appear in the agent's /proc/<pid>/environ or in any
# child process it spawns.
set -eu

key_file=/run/secrets/ANTHROPIC_API_KEY
if [ ! -r "$key_file" ]; then
	echo "ac-api-key: $key_file not readable (is the secret injected and the agent uid able to read it?)" >&2
	exit 1
fi
exec cat "$key_file"
