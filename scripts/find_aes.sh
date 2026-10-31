#!/usr/bin/env bash
# Match an RSA-decrypted session key to a supplied MD5 fingerprint.
set -euo pipefail
shopt -s nullglob

if [[ $# != 4 || ! $3 =~ ^[[:xdigit:]]{32}$ ]]; then
  echo 'Usage: bash scripts/find_aes.sh <rsa-directory> <encrypted-key-directory> <md5> <new-output-file>' >&2
  exit 2
fi
for tool in openssl md5sum mktemp; do
  command -v "$tool" >/dev/null || { echo "Missing command: $tool" >&2; exit 2; }
done
[[ -d $1 && -d $2 ]] || { echo 'Both input directories must exist.' >&2; exit 2; }
[[ ! -e $4 && ! -L $4 ]] || { echo 'Output already exists; choose a new file.' >&2; exit 2; }
keys=("$1"/*.pem)
candidates=("$2"/*.eaes)
(( ${#keys[@]} && ${#candidates[@]} )) || { echo 'No .pem keys or .eaes candidates found.' >&2; exit 2; }
target=${3,,}
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
count=0
for rsa in "${keys[@]}"; do
  for candidate in "${candidates[@]}"; do
    count=$((count + 1))
    if openssl pkeyutl -decrypt -inkey "$rsa" -in "$candidate" \
        -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha1 \
        -pkeyopt rsa_mgf1_md:sha1 -out "$scratch/key" 2>/dev/null; then
      hash=$(md5sum < "$scratch/key")
      if [[ ${hash%% *} == "$target" ]]; then
        (set -o noclobber; cat "$scratch/key" > "$4")
        printf 'MATCH FOUND\nRSA key: %s\nEncrypted key: %s\nAttempts: %s\nSaved key: %s\n' "$rsa" "$candidate" "$count" "$4"
        exit 0
      fi
    fi
  done
done
printf 'No matching AES key found after %s attempts.\n' "$count"
exit 1
