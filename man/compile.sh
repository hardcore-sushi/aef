#!/bin/bash

cargo_toml="../Cargo.toml"
source_md="source.md"

if [ ! -f $cargo_toml ]; then
    echo "Error: $cargo_toml not found." >&2;
    exit 1;
elif [ ! -f $source_md ]; then
    echo "Error: $source_md not found." >&2;
    exit 1;
fi

version=$(grep "^version = " $cargo_toml | cut -d "\"" -f 2)
date=$(date +"%B %Y")
pandoc $source_md -s -t man | sed \
    "s/^\.TH.*$/\.TH \"DOBY\" \"1\" \"$date\" \"doby v$version\" \"doby v$version\"/; \
    s/^\.hy/\.ad l/" | gzip - > doby.1.gz