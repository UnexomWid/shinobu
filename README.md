<p align="center">
  <img src="public/shinobu.png" width="450" height="253" alt="shinobu">
</p>

# About <a href="https://www.rust-lang.org/"><img align="right" src="https://img.shields.io/badge/Rust-1%2E73-f74c00?logo=Rust" alt="Rust 1.73" /></a>

**shinobu** is a program that lets you hide files inside one or more MZPE executables (aka `.exe`, `.dll` and `.sys`).

The input files are compressed, optionally encrypted, and the final buffer is split among the cover files (*i.e.* the MZPE files that hide the data).

# Usage

See `shinobu help` for more details.

## Hide files

You can pass as many input and target files as you want.

```sh
shinobu hide file1.txt file2.png ... -- target1.exe target2.exe ...
```

### Hide and encrypt

```sh
shinobu hide --password mypassword file1.txt file2.png ... -- target1.exe target2.exe ...
```

## Unhide files

The hidden files will be extracted to `output_dir`.

```sh
shinobu unhide target1.exe target2.exe ... -o output_dir
```

If the files were encrypted when hidden, you must also provide the password:

```sh
shinobu unhide --password mypassword target1.exe target2.exe ... -o output_dir
```

# How it works

## Hiding

1. the input files are compressed via LZMA, due to its great compression ratio,
and are stored inside a ZIP archive; since the [zip](https://crates.io/crates/zip) crate doesn't yet support LZMA, the compression
is done manually via [xz2](https://crates.io/crates/xz2) and the resulting buffers are stored as-is (this is why you'll see garbage data if
you try to extract this temporary archive with another program)
1. if you provide a password, the ZIP archive is encrypted via AES-256 in CBC mode along with PKCS7;
for key derivation, shinobu uses Argon2id which is the *de facto* standard for password hashing
1. the archive is split equally among all of the target files; each target file
also stores the total number of parts, the part it hides, and other metadata

## Unhiding

1. the target files are parsed and the metadata is extracted
1. all of the metadatas are correlated and checked; if any part is missing or there is a discrepancy,
it's not possible to unhide the data
1. the buffers hidden inside the files are concatenated to form the original ZIP archive
1. if necessary, the archive is decrypted with the user-provided password
1. the files are extracted from the archive to the output path

## Hiding data in MZPE files

Several techniques came to mind:

- tampering with `e_lfanew` and the MS-DOS stub
  - this breaks the section alignment and renders the file unexecutable, unless they are manually fixed
- creating a new section
  - any MZPE parser could detect this special section, so it would be very easy to see
  that there's something hidden
  - this could also break the alignment of the sections that follow it

Shinobu does none of those. Instead, it does the simplest thing that works: it appends all of the data
to the end of the file. Yep. This doesn't break the exes *in most cases*.

### Challenges

There are a few cases in which the EXE won't run after data is appended. Executables
that read themselves will obviously be impacted.

MZPE files that are signed with a digital certificate will be affected.

Some files will be seen as self-extracting archives by Windows, even if it's not the case; you can actually spot this by looking in the `Properties`
of the file.

# TODO

- support for other file formats, so you can hide files in those as well
- support for hiding entire folders
- pretty printing (errors, progress, etc)
- a `--strip` flag that removes the hidden data from the exe after it was unhidden
- find another way to hide stuff in MZPE files

# License <a href="https://github.com/UnexomWid/shinobu/blob/master/LICENSE"><img align="right" src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT" /></a>

**shinobu** was created by [UnexomWid](https://uw.exom.dev). It is licensed under the [MIT](https://github.com/UnexomWid/shinobu/blob/master/LICENSE) license.

I don't own the image shown at the beginning of this readme. That's just Shinobu.