# doby

Secure symmetric encryption from the command line.

doby started as a fork of [aef](https://github.com/wyhaya/aef) by [wyhaya](https://github.com/wyhaya). It aims to replace the [ccrypt](http://ccrypt.sourceforge.net) tool which is a bit old and not very secure.

# Features

* Fast: written in [rust](https://www.rust-lang.org), encrypts with [AES-256-CTR](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)) or [XChaCha20](https://en.wikipedia.org/wiki/Salsa20#XChaCha)
* [HMAC](https://en.wikipedia.org/wiki/HMAC) ciphertext authentication
* Password brute-force resistance with [Argon2](https://en.wikipedia.org/wiki/Argon2)
* Encryption from STDIN/STDOUT or from files
* Adjustable performance & secuity parameters

# Disclamer
doby is provided "as is", without any warranty of any kind. I'm not a professional cryptographer. This program didn't receive any security audit and therefore __shouldn't be considered fully secure__.

# Usage

Encryption

```bash
doby my-super-secret-source-code.rs encrypted.doby
```

Decryption

```bash
doby encrypted.doby decrypted.rs
```

If you ommit file path or use `-`, doby operates from `stdin/stdout`

```bash
# Read from stdin and write to stdout
cat my-super-secret-music.flac | doby > encrypted.doby

# Read from a file and output to stdout
doby encrypted.doby > decrypted.flac

# Read from stdin and save to a file
cat my-super-secret-logs-file.log | doby - logs.doby
```

Speicfy password from the command line

```bash
doby -p "A super very ultra strong passphrase" my-super-secret-document.pdf document.doby
```

Double encryption

```bash
doby -p "first password" my-super-secret-database.db | doby -f - double-encrypted.doby
```

Increase password brute-force resistance

```bash
echo "you-will-never-break-this" | doby --memory-cost 524288 --threads 16 --iterations 40 > my-super-secret-password.doby
```

## Full Options

```
USAGE:
    doby [FLAGS] [OPTIONS] [ARGS]

FLAGS:
    -f, --force-encrypt    Encrypt even if doby format is recognized
    -h, --help             Prints help information
    -V, --version          Prints version information

OPTIONS:
    -p, --password <password>          Password used to derive encryption keys
    -b, --block-size <blocksize>       Size of file chunk (in bytes) [default: 65536]
    -c, --cipher <cipher>              Encryption cipher to use [possible values: aes, xchacha20]
    -m, --memory-cost <memory cost>    Argon2 memory cost (in kilobytes) [default: 4096]
    -t, --threads <threads>            Argon2 parallelism (between 1 and 255) [default: 4]
    -i, --iterations <iterations>      Argon2 time cost [default: 10]

ARGS:
    <INPUT>     <PATH> | "-" or empty for stdin
    <OUTPUT>    <PATH> | "-" or empty for stdout
```

# Build

You should verify commits before building the binary. You can download my PGP key from keyservers:

```
gpg --keyserver hkp://pool.sks-keyservers.net --recv-keys 007F84120107191E
```
Fingerprint: `BD56 2147 9E7B 74D3 6A40  5BE8 007F 8412 0107 191E` \
Email: `Hardcore Sushi <hardcore.sushi@disroot.org>`

Once imported:

```bash
git clone --depth=1 https://forge.chapril.org/hardcoresushi/doby.git
cd doby
git verify-commit HEAD
cargo build --release #outputs to ./target/release/doby
```

# Cryptographic details

### Encryption

doby first derives your password with Argon2 (version 19) in Argon2id mode with a 64 bytes long random salt. A `master_key` of 32 bytes is thus generated.

```rust
let master_key: [u8; 32] = argon2id(
    password,
    random_password_salt,
    argon2_time_cost,
    argon2_memory_cost,
    argon2_parallelism,
);
```

Then, doby uses [HKDF](https://en.wikipedia.org/wiki/HKDF) with a new random salt to compute the `encryption_key` and the `authentication_key`.

```rust
let hkdf = Hkdf::new(
    random_hkdf_salt,
    master_key, //ikm
    blake3, //hash function
);
let encryption_key: [u8; 32] = hkdf.expand(b"doby_encryption_key");
let authentication_key: [u8; 32] = hkdf.expand(b"doby_authentication_key");
```

Next, doby initializes a [BLAKE3](https://en.wikipedia.org/wiki/BLAKE_%28hash_function%29#BLAKE3) HMAC with `authentication_key` and add all public encryption parameters to it.

```rust
let hmac = Hmac::new(
    authentication_key,
    blake3, //hash function
);
hmac.update(random_password_salt);
hmac.update(argon2_time_cost);
hmac.update(argon2_memory_cost);
hmac.update(argon2_parallelism);
hmac.update(random_hkdf_salt);
hmac.update(cipher); //1-byte representation of the symmetric cipher used to encrypt (either AES-CTR or XChaCha20)
hmac.update(random_nonce); //random nonce used for encryption (16 bytes for AES-CTR, 24 for XChaCha20)
```

All this parameters are also written in plain text in the header of the doby output.

Now, doby initializes a symmetric cipher with `encryption_key` and `random_nonce` (either AES-CTR or XChaCha20, based on the `--cipher` option) and starts the actual encryption. It reads chunks from the plaintext (according to the `--block-size` parameter), encrypts them with the cipher and updates the HMAC with the ciphertext.

```rust
let cipher = Aes256Ctr::new(encryption_key, random_nonce); //example with AES-CTR
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

### Decryption

doby reads the public encryption values from the input header to get all parameters needed to re-derive the `master_key` from the password with Argon2.

```rust
let master_key: [u8; 32] = argon2id(
    password,
    password_salt_read_from_input,
    argon2_time_cost_read_from_input,
    argon2_memory_cost_read_from_input,
    argon2_parallelism_read_from_input,
);
```

`encryption_key` and `authentication_key` are computed from `master_key` and the HKDF salt in the same way as during encryption. The HMAC is also initialized and updated with the values read from the header.

Then, doby starts decryption.

```rust
let cipher = XChaCha20::new(encryption_key, nonce_read_from_input); //example with XChaCha20
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