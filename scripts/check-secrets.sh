#!/usr/bin/env bash
# Fails when secret:, bindPW: or clientSecret: under the scanned recipe paths
# holds a literal instead of an env reference ($VAR or ${VAR...}).
# Prints path, line and key only, never the value. seed.ldif is allowlisted.
#
#   ROOT              tree to scan (default .)
#   SECRET_SCAN_PATHS space-separated paths under ROOT. A recipe for another
#                     IdP adds its directory here.
set -euo pipefail

ROOT="${ROOT:-.}"
SCAN="${SECRET_SCAN_PATHS:-deploy/compose/dex deploy/compose/docker-compose.identity.yml}"

bad=0
for p in $SCAN; do
	[ -e "$ROOT/$p" ] || continue # the compose file arrives with the recipe
	while IFS= read -r -d '' f; do
		case "$f" in */seed.ldif) continue ;; esac
		rel="${f#"$ROOT"/}"
		lineno=0
		while IFS= read -r line || [ -n "$line" ]; do
			lineno=$((lineno + 1))
			[[ "$line" =~ ^[[:space:]]*(-[[:space:]]+)?(secret|bindPW|clientSecret):(.*)$ ]] || continue
			key="${BASH_REMATCH[2]}"
			val="${BASH_REMATCH[3]}"
			val="${val%%[[:space:]]#*}" # trailing comment
			val="${val#"${val%%[![:space:]]*}"}"
			val="${val%"${val##*[![:space:]]}"}"
			if [[ "$val" =~ ^\"(.*)\"$ || "$val" =~ ^\'(.*)\'$ ]]; then val="${BASH_REMATCH[1]}"; fi
			if [[ "$val" =~ ^\$[A-Za-z_][A-Za-z0-9_]*$ || "$val" =~ ^\$\{[A-Za-z_][A-Za-z0-9_]*([:?-][^}]*)?\}$ ]]; then
				continue
			fi
			echo "secrets: $rel:$lineno: $key is a literal; use an env reference (\$VAR or \${VAR:?})" >&2
			bad=1
		done <"$f"
	done < <(find "$ROOT/$p" -type f -print0 | sort -z)
done

[ "$bad" -eq 0 ] || exit 1
echo "ok"
