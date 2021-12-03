#!/bin/bash

set_version() {
    cp $1 /tmp/$(basename $1).original &&
    sed -i "s/VERSION/$version/g" $1
}

restore() {
    mv /tmp/$(basename $1).original $1
}

package_deb() {(
    mkdir -p deb/doby/usr/bin deb/doby/usr/share/man/man1 \
    deb/doby/usr/share/bash-completion/completions \
    deb/doby/usr/share/zsh/vendor-completions &&
    strip -s ../target/release/doby -o deb/doby/usr/bin/doby &&
    cp ../man/doby.1.gz deb/doby/usr/share/man/man1 &&
    cp ../completions/bash deb/doby/usr/share/bash-completion/completions/doby &&
    cp ../completions/zsh deb/doby/usr/share/zsh/vendor-completions/_doby &&
    cd deb && set_version doby/DEBIAN/control && dpkg -b doby &&
    restore doby/DEBIAN/control && mv doby.deb ../doby-$version-x86_64.deb &&
    rm -r doby/usr
)}

package_pkg() {(
    mkdir pkg/src &&
    strip -s ../target/release/doby -o pkg/src/doby &&
    cp ../man/doby.1.gz pkg/src &&
    cp -r ../completions pkg/src &&
    cd pkg && set_version PKGBUILD &&
    makepkg && restore PKGBUILD &&
    mv doby-*.pkg.tar.zst ../doby-$version-x86_64.pkg.tar.zst && rm -r src pkg
)}

package_tarball() {(
    strip -s ../target/x86_64-unknown-linux-musl/release/doby -o tarball/doby/doby &&
    cp ../man/doby.1.gz tarball/doby &&
    cd tarball && tar -chzf ../doby-$version-x86_64.tar.gz doby &&
    rm doby/doby*
)}

if [ "$#" -eq 1 ]; then
    cargo_toml="../Cargo.toml"

    if [ ! -f $cargo_toml ]; then
        echo "Error: $cargo_toml not found." >&2;
        exit 1;
    fi

    version=$(grep "^version = " ../Cargo.toml | cut -d "\"" -f 2)
    echo "Packaging doby v$version..."
    case $1 in
        "deb")
            package_deb
            ;;
        "pkg")
            package_pkg
            ;;
        "tarball")
            package_tarball
            ;;
        "all")
            package_deb
            package_pkg
            package_tarball
            ;;
    esac
else
    echo "usage: $0 <deb|pkg|tarball|all>" >&2
    exit 1;
fi