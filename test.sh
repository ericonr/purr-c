#!/bin/sh
readme="${1:-README.md}"
EXIT=
assert () {
	if [ "$1" != "$2" ]; then
		echo "expected: $1"
		echo "result: $2"
		EXIT=1
	fi
}
rate_limit() {
	if [ "$RATELIMIT" ]; then
		echo "Rate limiting"
		sleep 5
	fi
}

echo "Fetch wikipedia homepage"
xbps-fetch -o /tmp/wikipedia.html https://www.wikipedia.org
e="$(xbps-digest /tmp/wikipedia.html)"
r="$(./purr r https://www.wikipedia.org | xbps-digest)"
assert "$e" "$r"

echo "Pastebin and retrieve - unencrypted"
e="$(xbps-digest "$readme")"
r="$(./purr r $(./purr s "$readme") | xbps-digest)"
assert "$e" "$r"

rate_limit

echo "Pastebin and retrieve - encrypted"
e="$(xbps-digest "$readme")"
r="$(./purr -e r $(./purr -e s "$readme") | xbps-digest)"
assert "$e" "$r"

# TODO: find some reliable way of testing gemi

exit $EXIT
