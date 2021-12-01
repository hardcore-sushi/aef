# doby

Secure symmetric encryption from the command line.

doby started as a fork of [aef](https://github.com/wyhaya/aef) by [wyhaya](https://github.com/wyhaya) with the goal of becoming a simple, fast and lightweight CLI utility for symmetric encryption. It aims to be an alternative to the old [ccrypt](http://ccrypt.sourceforge.net) tool by using modern cryptography and authenticated encryption.

# Features

* Fast: written in [rust](https://www.rust-lang.org), encrypts with [AES-256-CTR](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)) or [XChaCha20](https://en.wikipedia.org/wiki/Salsa20#XChaCha)
* [HMAC](https://en.wikipedia.org/wiki/HMAC) ciphertext authentication
* Password brute-force resistance with [Argon2](https://en.wikipedia.org/wiki/Argon2)
* Increase the plaintext size of only 113 bytes
* Encryption from STDIN/STDOUT or from files
* Adjustable performance & secuity parameters

# Disclamer
doby is provided "as is", without any warranty of any kind. I'm not a professional cryptographer. This program didn't receive any security audit and therefore __shouldn't be considered fully secure__.

# Usage

Encryption:
```bash
doby my-super-secret-source-code.rs encrypted.doby
```

Decryption:
```bash
doby encrypted.doby decrypted.rs
```

If you ommit file path or use `-`, doby operates from `stdin/stdout`:
```bash
# Read from stdin and write to stdout
cat my-super-secret-music.flac | doby > encrypted.doby

# Read from a file and output to stdout
doby encrypted.doby > decrypted.flac

# Read from stdin and save to a file
cat my-super-secret-logs-file.log | doby - logs.doby
```

Speicfy password from the command line:
```bash
doby --password "A super very ultra strong passphrase" my-super-secret-document.pdf document.doby
```

Double encryption:
```bash
doby --password "first password" my-super-secret-database.db | doby -f - double-encrypted.doby
```

Increase password brute-force resistance:
```bash
echo "you-will-never-break-this" | doby --memory-cost 524288 --parallelism 16 --time-cost 40 > my-super-secret-data.doby
```

## Full Options

```
USAGE:
    doby [FLAGS] [OPTIONS] [ARGS]

FLAGS:
    -f, --force-encrypt    Encrypt even if doby format is recognized
    -i, --interactive      Prompt before overwriting files
    -h, --help             Prints help information
    -V, --version          Prints version information

OPTIONS:
        --password <password>          Password used to derive encryption keys
    -t, --time-cost <iterations>       Argon2 time cost [default: 10]
    -m, --memory-cost <memory size>    Argon2 memory cost (in kilobytes) [default: 4096]
    -p, --parallelism <threads>        Argon2 parallelism cost [default: 4]
    -b, --block-size <blocksize>       Size of the I/O buffer (in bytes) [default: 65536]
    -c, --cipher <cipher>              Encryption cipher to use [possible values: aes, xchacha20]

ARGS:
    <INPUT>     <PATH> | "-" or empty for stdin
    <OUTPUT>    <PATH> | "-" or empty for stdout
```

# Installation
You can download doby from the "Releases" section in this repo.

All binaries MUST be signed with my PGP key available on keyservers. To import it:
```bash
gpg --keyserver hkp://pool.sks-keyservers.net --recv-keys 007F84120107191E
```
Fingerprint: `BD56 2147 9E7B 74D3 6A40  5BE8 007F 8412 0107 191E` \
Email: `Hardcore Sushi <hardcore.sushi@disroot.org>`

Then, save the PGP-signed message to a file and run:
```bash
gpg --verify <the file>
```
__Don't continue if the verification fails!__

If everything goes fine, you can compute the SHA-256 hash of the binary file you want to verify:
```bash
sha256sum <doby binary file>
```
Compare this output and the hash in the PGP-signed message. __Don't execute the file if the hashes don't match!__

You can make doby available in your `$PATH` by running:
```bash
sudo cp <doby binary file> /usr/local/bin/
```

# Build

You should verify commits before building the binary. Follow the steps in [Installation](#installation) to import my PGP key.

```bash
git clone --depth=1 https://forge.chapril.org/hardcoresushi/doby.git
cd doby
git verify-commit HEAD #you need to import my PGP key to verify the commit signature
cargo build --release --bin doby #outputs to ./target/release/doby
```

# Cryptographic details

The following explanations are illustrated with pseudo rust code to simplify understanding. If you want to see how it's exactly implemented in doby, you can always check the source code.

### Encryption

doby first derives your password with Argon2 (version 19) in Argon2id mode with a 64 bytes long random salt. A `master_key` of 32 bytes is thus generated.

```rust
let master_key: [u8; 32] = argon2id(
    password,
    random_salt,
    argon2_time_cost,
    argon2_memory_cost,
    argon2_parallelism,
);
```

Then, doby uses [HKDF](https://en.wikipedia.org/wiki/HKDF) with the previous random salt to compute the `nonce`, the `encryption_key` and the `authentication_key`.

```rust
let hkdf = Hkdf::new(
    random_salt,
    master_key, //ikm
    blake2b, //hash function
);
let nonce: [u8; 16] = hkdf.expand(b"doby_nonce"); //(16 bytes for AES-CTR, 24 for XChaCha20)
let encryption_key: [u8; 32] = hkdf.expand(b"doby_encryption_key");
let authentication_key: [u8; 32] = hkdf.expand(b"doby_authentication_key");
```

NOTE: To reduce the size of the header, the `nonce` is derived from the `master_key` instead of being generated purely at random then stored in the encrypted file.

Next, doby initializes a [BLAKE2b](https://en.wikipedia.org/wiki/BLAKE_(hash_function)#BLAKE2) HMAC with `authentication_key` and add all public encryption parameters to it.

```rust
let hmac = Blake2b::new_keyed(
    authentication_key,
    32, //digest size
);
hmac.update(random_salt);
//integers are encoded in big-endian
hmac.update(argon2_time_cost);
hmac.update(argon2_memory_cost);
hmac.update(argon2_parallelism);
hmac.update(cipher); //1-byte representation of the symmetric cipher used to encrypt (either AES-CTR or XChaCha20)
```

All this parameters are also written in plain text in the header of the doby output.

Now, doby initializes a symmetric cipher with `encryption_key` and `nonce` (either AES-CTR or XChaCha20, based on the `--cipher` option) and starts the actual encryption. It reads chunks from the plaintext (according to the `--block-size` parameter), encrypts them with the cipher and updates the HMAC with the ciphertext.

```rust
let cipher = Aes256Ctr::new(encryption_key, nonce); //example with AES-CTR
let mut n = 1;
let mut chunk: [u8; block_size] = [0; block_size];
while n != 0 {
    n = input.read(&mut chunk); //read plaintext
    cipher.apply_keystream(&mut chunk[..n]); //encrypt
    hmac.update(chunk[..n]);
    output.write(chunk[..n]); //write ciphertext
}
```

Once the whole plaintext is encrypted, doby computes and appends the HMAC to the ciphertext.

```rust
output.write(hmac.digest());
```

So here is what an encrypted file layout looks like:

<table>
  <tr>
    <th align="left">Magic bytes</th>
    <td>4 bytes</td>
  </tr>
  <tr>
    <th align="left">Salt</th>
    <td>64 bytes</td>
  </tr>
  <tr>
    <th align="left" rowspan="3">Argon2 parameters</th>
    <td>Time cost: 4 bytes</td>
  </tr>
  <tr>
    <td>Memory cost: 4 bytes</td>
  </tr>
  <tr>
    <td>Parallelism cost: 1 byte</td>
  </tr>
  <tr>
    <th align="left">Encryption cipher</th>
    <td>1 byte</td>
  </tr>
  <tr>
    <th align="left">Ciphertext</th>
    <td>Exact same size as the plaintext</td>
  </tr>
  <tr>
    <th align="left">HMAC</th>
    <td>32 bytes</td>
  </tr>
</table>

### Decryption

doby reads the public encryption values from the input header to get all parameters needed to re-derive the `master_key` from the password with Argon2.

```rust
let master_key: [u8; 32] = argon2id(
    password,
    salt_read_from_input,
    argon2_time_cost_read_from_input,
    argon2_memory_cost_read_from_input,
    argon2_parallelism_read_from_input,
);
```

`nonce`, `encryption_key` and `authentication_key` are computed from `master_key` in the same way as during encryption. The HMAC is also initialized and updated with the values read from the header.

Then, doby starts decryption.

```rust
let cipher = XChaCha20::new(encryption_key, nonce); //example with XChaCha20
let mut n = 1;
let mut chunk: [u8; block_size] = [0; block_size];
while n != 0 {
    n = input.read(&mut chunk); //read ciphertext
    hmac.update(chunk[..n]);
    cipher.apply_keystream(&mut chunk[..n]); //decrypt
    output.write(chunk[..n]); //write plaintext
}
```

Once the whole ciphertext is decrypted, doby computes and verifies the HMAC.

```rust
hmac.digest() == last_32_bytes_read
```

If the verification success, the file is successfully decrypted and authenticated.

_If you find any weakness or security issue is this protocol, please open an issue._

## Why not using authenticated encryption such as AES-GCM instead of AES-CTR + HMAC ?

In order to encrypt data larger than memory, we need to split the plaintext into severavl smaller chunks and encrypt each of these chunks one by one. With authenticated encryption such as AES-GCM, this involves adding an authentication tag to each chunk. As a result, the final ciphertext size would be:
```
ciphertext size = plaintext size + (number of chunks ྾ tag size)
```
For example, a 50MB file encrypted with AES-GCM by chunks of 64KiB would be 12.2KB larger than the original plaintext, just to authenticate the file.

doby solves this problem by performing authentication independently of encryption. By using AES-CTR, the ciphertext remains the same size as the plaintext. The HMAC can be computed incrementally, one chunk at a time. Only one hash needs to be included in the final file. Thus, doby encrypted files are only 142 bytes larger than the plaintext, no matter how big the original file is.