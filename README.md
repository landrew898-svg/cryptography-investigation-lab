# Cryptography Investigation Lab

A small lab combining MD5 file identification, RSA-OAEP key recovery, and AES-256-CBC message recovery. Java scans files for a matching fingerprint; Bash and OpenSSL automate searches through candidate keys and encrypted messages.

This repository is a cleaned-up version of a four-stage project. The original work used supplied datasets. The portable demo generator and integration checks were added when preparing this repository; they generate fresh disposable keys and sample data instead of including the original datasets, keys, reports, or screenshots.

## Requirements

- JDK 11 or newer
- Bash 4+, OpenSSL, and GNU command-line tools (`md5sum`, `od`, `tr`, `wc`, `mktemp`, `cmp`)
- Linux or a Linux environment such as Ubuntu on WSL for the complete workflow

The Java tools also run directly on Windows. Run the commands below from the repository root in Bash. No Maven, Gradle, or third-party Java libraries are needed.

## Generate a small demo

```bash
mkdir -p build
javac -d build src/*.java
java -cp build DemoFixture demo-data
```

Use a new directory for each demo; the generator refuses an existing directory. It creates two RSA private keys, two encrypted-key candidates, two encrypted-message candidates, and two plaintext files. One candidate in each search matches the target. RSA keys and AES keys are randomly generated, so encrypted bytes and key hashes vary between runs. The demo generator checks RSA and AES round trips before saving its output.

Private keys and recovered files belong to this disposable local demo. They are ignored by Git and are not committed.

## Stage 1 - Identify a file by MD5

```bash
java -cp build MD5FileFinder demo-data/plain "$(cat demo-data/hashes/plain.md5)"
```

The finder walks subdirectories and hashes files in chunks. It prints the first matching file and the number of files checked. Symbolic links are skipped. Exit status is `0` for a match, `1` for no match, and `2` for invalid input or a read/listing error.

## Stage 2 - Recover an RSA-encrypted session key

For a known matching private key and ciphertext:

```bash
openssl pkeyutl -decrypt -inkey demo-data/rsa/02-match.pem \
  -in demo-data/aes/02-match.eaes -pkeyopt rsa_padding_mode:oaep \
  -pkeyopt rsa_oaep_md:sha1 -pkeyopt rsa_mgf1_md:sha1 \
  -out build/direct-session.key
```

The lab uses RSA-OAEP with SHA-1 for both OAEP and MGF1 to preserve the original dataset settings. This is supplied-key decryption, not RSA key cracking.

## Stage 3 - Decrypt an AES message

```bash
key_hex=$(od -An -v -tx1 build/direct-session.key | tr -d ' \n')
openssl enc -d -aes-256-cbc -K "$key_hex" \
  -iv 00000000000000000000000000000000 -nopad \
  -in demo-data/messages/02-match.emsg -out build/direct-message.bin
```

The key file holds exactly 32 raw bytes. The IV is supplied as 32 hexadecimal characters. The demo follows the original lab's zero IV and manual `!` padding conventions; these are lab compatibility settings. The MD5 fingerprint covers the raw padded plaintext, so padding must remain in place during matching. Displaying or stripping it is a separate step and can be ambiguous if the actual message ends in `!`.

## Stage 4 - Search candidates automatically

```bash
bash scripts/find_aes.sh demo-data/rsa demo-data/aes \
  "$(cat demo-data/hashes/aes.md5)" build/recovered-session.key

bash scripts/find_message.sh demo-data/messages build/recovered-session.key \
  "$(cat demo-data/hashes/message.md5)" \
  00000000000000000000000000000000 build/recovered-message.bin

cmp build/recovered-session.key demo-data/expected/session.key
cmp build/recovered-message.bin demo-data/expected/message.bin
```

Choose new output paths if rerunning the searches; the scripts refuse existing output files. `find_aes.sh` tries each `.pem` / `.eaes` combination and checks successful decryptions against the requested MD5. `find_message.sh` tries each `.emsg` file with the recovered AES key. Both use isolated temporary directories, clean them up on exit, and write the result only after a hash match. Recovered keys are saved to a file rather than printed.

Both scripts return `0` for a match, `1` for no match, and `2` for explicit argument/dependency validation failures. Other runtime failures return a nonzero status. Candidate decryption errors are expected during a search and are suppressed; a no-match result can therefore also mean the supplied candidates or cryptographic settings were unsuitable. This is a simple serial search; the RSA stage may perform up to the number of private keys multiplied by the number of encrypted keys attempts.

## Verification

```bash
bash tests/check.sh
```

The checks generate a fresh dataset in a temporary directory, compile both Java tools, verify all four stages, compare recovered bytes, and exercise no-match, malformed input, missing directory, empty candidate, existing output, and invalid key-length cases. Paths with spaces are included. GitHub Actions runs the same checks on Ubuntu for pushes and pull requests.

## Scope

These utilities demonstrate working with known lab keys and verifying recovered files. MD5 is used only to reproduce the lab's fingerprints; it does not provide secure authentication. AES-CBC here has no authentication, and fixed IVs and manual padding are unsuitable for a new encryption system. The scripts are small investigation helpers rather than a general-purpose encryption product.

The original Java hashing approach and Bash/OpenSSL search workflow are retained. Cleanup replaces machine-specific paths and embedded keys/hashes with arguments, checks errors and output paths, and adds portable demonstration and verification files. The original reports are excluded; their standalone AES section also contained an unrelated RSA command that is not reproduced here.
