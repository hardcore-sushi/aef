% DOBY(1)

# NAME
doby - Simple, secure and lightweight symmetric encryption from the command line

# SYNOPSIS
doby [**-fi**] [**\--password** password] [**-t** time_cost] [**-m** memory_cost] [**-p** parallelism] [**-b** block_size] [**-c**] {aes | xchacha20} [INPUT] [OUTPUT]

doby [**-h** | **\--help**]

doby [**-V** | **\--version**]

# DESCRIPTION
doby aims to be a small, fast and user-friendly command line tool for symmectric encryption of single files. It uses modern cryptography and (obviously) it's built in rust.

doby can operate with files larger than memory but also from stdout/stdin. In addition to encrypt files, doby also use HMAC cryptography to authenticate the data. This means that encrypted files can't be tampered. Encryptions keys are derived from the user password using Argon2, an expensive KDF function that slows down a lot brute force attacks. You can find more details about cryptography on the doby's repository: https://forge.chapril.org/hardcoresushi/doby#cryptographic-details

doby will add a header at the beginning of the encrypted files so that it can know whether it is encrypted or not. That's why you don't need to specify which operation should be performed. doby will detect this automatically.

# OPTIONS
**-h**, **\--help**
: Print help.

**-V**, **\--version**
: Print doby version.

**-f**, **\--force-encrypt**
: Perform encryption even if doby format is recognized in the input file.

**-i**, **\--interactive**
: Prompt before overwriting the output file if it already exists.

**\--password** *password*
: Specify the password which will be used to derive encryption keys. If omitted, the password will be prompted in the terminal.

**-t**, **\--time-cost** *iterations*
: Argon2 time cost used to derive the master key. Default: 10

**-m**, **\--memory-cost** *memory size*
: Argon2 memory cost used to derive the master key (in kilobytes). Default: 4096 KB

**-p,** **\--parallelism** *threads*
: Argon2 parallelism cost used to derive the master key. Default: 4

**-b,** **\--block-size** *blocksize*
: Size of the buffer used when reading the file (in bytes). Default: 65536 B

**-c,** **\--cipher** *cipher*
: Encryption cipher to use. Either "aes" or "xchacha20". If not specified, AES will be used if your CPU supports AES native instructions, XChaCha20 otherwise. Ignored when performing decryption.

**INPUT**
: The file doby will read as input. If it's omitted or set to "-", doby will read from stdin.

**OUTPUT**
: The file doby will write to. If it's omitted or set to "-", doby will write to stdout.

# EXAMPLES
doby my-super-secret-source-code.rs encrypted.doby

doby \--block-size 4096 encrypted.doby decrypted.rs

cat my-super-secret-music.flac | doby \--cipher xchacha20 > encrypted.doby

doby \--password "rockyou" encrypted.doby > decrypted.flac

cat my-super-secret-logs-file.log | doby \--interactive - logs.doby

echo "you-will-never-break-this" | doby \--memory-cost 524288 \--parallelism 16 \--time-cost 40 > my-super-secret-data.doby

# EXIT STATUS
**0**
: Success

**1**
: Error

# REPORTING BUGS
You can open an issues on Gitea (https://forge.chapril.org/hardcoresushi/doby) or on GitHub (https://github.com/hardcore-sushi/doby) if you find an issue or if you have any questions/suggestions.
If you prefer, you can also email me at hardcore.sushi@disroot.org. My PGP key is available on keyservers (fingerprint: 0x007F84120107191E).

# AUTHOR
Hardcore Sushi <hardcore.sushi@disroot.org>

# COPYRIGHT
License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>. This is free software: you are free to change and redistribute it. There is NO WARRANTY, to the extent permitted by law.

# SEE ALSO
**ccrypt**(1), **age**(1), **gocryptfs**(1), **cryfs**(1)