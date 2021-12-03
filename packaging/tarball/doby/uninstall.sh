#!/bin/sh

if [ $(id -u) -ne 0 ]; then
	echo "Error: root access required" >&2
	exit 1
fi

rm -v /usr/bin/doby
rm -v /usr/share/man/man1/doby.1.gz 2>/dev/null
rm -v /usr/share/bash-completion/completions/doby 2>/dev/null
rm -v /usr/share/zsh/vendor-completions/_doby 2>/dev/null
