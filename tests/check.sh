#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")/.."
mkdir -p build
javac -d build src/*.java
bash -n scripts/find_aes.sh scripts/find_message.sh tests/check.sh
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
demo="$scratch/demo with spaces"
java -cp build DemoFixture "$demo"
plain_hash=$(cat "$demo/hashes/plain.md5")
key_hash=$(cat "$demo/hashes/aes.md5")
message_hash=$(cat "$demo/hashes/message.md5")
iv=00000000000000000000000000000000

expect_status() {
  local expected=$1 actual=0
  shift
  "$@" > "$scratch/status.log" 2>&1 || actual=$?
  if [[ $actual != "$expected" ]]; then
    cat "$scratch/status.log" >&2
    echo "Expected exit $expected; got $actual: $*" >&2
    exit 1
  fi
}

java -cp build MD5FileFinder "$demo/plain" "$plain_hash" | grep -q 'MATCH FOUND'
expect_status 1 java -cp build MD5FileFinder "$demo/plain" 00000000000000000000000000000000
expect_status 2 java -cp build MD5FileFinder "$demo/plain" invalid
expect_status 2 java -cp build MD5FileFinder "$demo/missing" "$plain_hash"

bash scripts/find_aes.sh "$demo/rsa" "$demo/aes" "$key_hash" "$scratch/recovered.key"
cmp "$scratch/recovered.key" "$demo/expected/session.key"
bash scripts/find_message.sh "$demo/messages" "$scratch/recovered.key" "$message_hash" "$iv" "$scratch/message.bin"
cmp "$scratch/message.bin" "$demo/expected/message.bin"

# Standalone RSA and AES stages using the same generated fixture.
openssl pkeyutl -decrypt -inkey "$demo/rsa/02-match.pem" -in "$demo/aes/02-match.eaes" \
  -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha1 -pkeyopt rsa_mgf1_md:sha1 \
  -out "$scratch/direct.key"
cmp "$scratch/direct.key" "$demo/expected/session.key"
key_hex=$(od -An -v -tx1 "$scratch/direct.key" | tr -d ' \n')
openssl enc -d -aes-256-cbc -K "$key_hex" -iv "$iv" -nopad \
  -in "$demo/messages/02-match.emsg" -out "$scratch/direct-message.bin"
cmp "$scratch/direct-message.bin" "$demo/expected/message.bin"

expect_status 1 bash scripts/find_aes.sh "$demo/rsa" "$demo/aes" 00000000000000000000000000000000 "$scratch/no-key"
expect_status 1 bash scripts/find_message.sh "$demo/messages" "$scratch/recovered.key" 00000000000000000000000000000000 "$iv" "$scratch/no-message"
expect_status 2 bash scripts/find_aes.sh "$demo/rsa" "$demo/aes" "$key_hash" "$scratch/recovered.key"
expect_status 2 bash scripts/find_message.sh "$demo/messages" "$scratch/recovered.key" "$message_hash" "$iv" "$scratch/message.bin"
expect_status 2 bash scripts/find_aes.sh "$demo/rsa" "$demo/aes" invalid "$scratch/invalid"
expect_status 2 bash scripts/find_message.sh "$demo/messages" "$demo/plain/decoy.txt" "$message_hash" "$iv" "$scratch/invalid"
mkdir "$scratch/empty"
expect_status 2 bash scripts/find_aes.sh "$scratch/empty" "$demo/aes" "$key_hash" "$scratch/empty-result"
expect_status 2 bash scripts/find_message.sh "$scratch/empty" "$scratch/recovered.key" "$message_hash" "$iv" "$scratch/empty-result"
[[ ! -e "$scratch/no-key" && ! -e "$scratch/no-message" ]]
echo 'All integration checks passed.'
