#!/usr/bin/env bash
# Match raw AES-256-CBC plaintext bytes to a supplied MD5 fingerprint.
set -euo pipefail
shopt -s nullglob

if [[ $# != 5 || ! $3 =~ ^[[:xdigit:]]{32}$ || ! $4 =~ ^[[:xdigit:]]{32}$ ]]; then
  echo 'Usage: bash scripts/find_message.sh <message-directory> <raw-32-byte-key-file> <md5> <iv-hex> <new-output-file>' >&2
  exit 2
fi
for tool in openssl md5sum mktemp od tr wc; do
  command -v "$tool" >/dev/null || { echo "Missing command: $tool" >&2; exit 2; }
done
[[ -d $1 && -f $2 ]] || { echo 'Message directory and key file must exist.' >&2; exit 2; }
[[ ! -e $5 && ! -L $5 ]] || { echo 'Output already exists; choose a new file.' >&2; exit 2; }
[[ $(wc -c < "$2") -eq 32 ]] || { echo 'AES key must contain exactly 32 raw bytes.' >&2; exit 2; }
candidates=("$1"/*.emsg)
(( ${#candidates[@]} )) || { echo 'No .emsg candidates found.' >&2; exit 2; }
key_hex=$(od -An -v -tx1 "$2" | tr -d ' \n')
target=${3,,}
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
count=0
for candidate in "${candidates[@]}"; do
  count=$((count + 1))
  if openssl enc -d -aes-256-cbc -K "$key_hex" -iv "$4" -nopad \
      -in "$candidate" -out "$scratch/message" 2>/dev/null; then
    hash=$(md5sum < "$scratch/message")
    if [[ ${hash%% *} == "$target" ]]; then
      (set -o noclobber; cat "$scratch/message" > "$5")
      printf 'MATCH FOUND\nEncrypted message: %s\nAttempts: %s\nSaved plaintext: %s\n' "$candidate" "$count" "$5"
      exit 0
    fi
  fi
done
printf 'No matching message found after %s attempts.\n' "$count"
exit 1
