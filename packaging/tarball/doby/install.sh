#!/bin/sh

ROOT=$(dirname $0)

if [ $(id -u) -ne 0 ]; then
	echo "Error: root access required" >&2
	exit 1
elif [ ! -f $ROOT/doby ]; then
	echo "Error: doby binary not found in $ROOT" >&2
	exit 1
fi

install -v -g 0 -o 0 $ROOT/doby /usr/bin

MAN_FOLDER=/usr/share/man/man1
if [ -d $MAN_FOLDER ]; then
	install -v -g 0 -o 0 -m 0644 $ROOT/doby.1.gz $MAN_FOLDER
fi

BASH_COMPLETION_FOLDER=/usr/share/bash-completion/completions
if [ -d $BASH_COMPLETION_FOLDER ]; then
	install -v -g 0 -o 0 -m 0644 $ROOT/completions/bash $BASH_COMPLETION_FOLDER/doby
fi

ZSH_COMPLETION_FOLDER=/usr/share/zsh/vendor-completions
if [ -d $ZSH_COMPLETION_FOLDER ]; then
	install -v -g 0 -o 0 -m 0644 $ROOT/completions/zsh $ZSH_COMPLETION_FOLDER/_doby
fi