#!/usr/bin/env bash
# Fails when secret:, bindPW: or clientSecret: under the scanned recipe paths
# holds a literal instead of an env reference ($VAR or ${VAR...}), in block
# style (one key per line) or flow style ({id: x, secret: abc}). Full-line
# comments are ignored.
# Prints path, line and key only, never the value. seed.ldif is allowlisted.
#
#   ROOT              tree to scan (default .)
#   SECRET_SCAN_PATHS space-separated paths under ROOT. A recipe for another
#                     IdP adds its directory here.
set -euo pipefail

ROOT="${ROOT:-.}"
SCAN="${SECRET_SCAN_PATHS:-deploy/compose/dex deploy/compose/docker-compose.identity.yml}"

bad=0

# check_literal KEY VALUE: flags VALUE unless it is an env reference. Prints
# file:line:key only (uses rel and lineno from the caller), never the value.
check_literal() {
	local key="$1" val="$2"
	val="${val#"${val%%[![:space:]]*}"}"
	val="${val%"${val##*[![:space:]]}"}"
	if [[ "$val" =~ ^\"(.*)\"$ || "$val" =~ ^\'(.*)\'$ ]]; then val="${BASH_REMATCH[1]}"; fi
	if [[ "$val" =~ ^\$[A-Za-z_][A-Za-z0-9_]*$ || "$val" =~ ^\$\{[A-Za-z_][A-Za-z0-9_]*([:?-][^}]*)?\}$ ]]; then
		return 0
	fi
	echo "secrets: $rel:$lineno: $key is a literal; use an env reference (\$VAR or \${VAR:?})" >&2
	bad=1
}
for p in $SCAN; do
	[ -e "$ROOT/$p" ] || continue # the compose file arrives with the recipe
	while IFS= read -r -d '' f; do
		case "$f" in */seed.ldif) continue ;; esac
		rel="${f#"$ROOT"/}"
		lineno=0
		while IFS= read -r line || [ -n "$line" ]; do
			lineno=$((lineno + 1))
			[[ "$line" =~ ^[[:space:]]*# ]] && continue # full-line comment
			# Block style: the key starts the line (optionally after "- ").
			if [[ "$line" =~ ^[[:space:]]*(-[[:space:]]+)?(secret|bindPW|clientSecret):(.*)$ ]]; then
				val="${BASH_REMATCH[3]}"
				val="${val%%[[:space:]]#*}" # trailing comment
				check_literal "${BASH_REMATCH[2]}" "$val"
			fi
			# Flow style: {id: x, secret: abc} on one line; the value ends at , or }.
			rest="$line"
			while [[ "$rest" =~ [\{,][[:space:]]*(secret|bindPW|clientSecret):[[:space:]]*(\$\{[^\}]*\}|[^,\}]*) ]]; do
				whole="${BASH_REMATCH[0]}"
				check_literal "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
				rest="${rest#*"$whole"}"
			done
		done <"$f"
	done < <(find "$ROOT/$p" -type f -print0 | sort -z)
done

[ "$bad" -eq 0 ] || exit 1
echo "ok"
