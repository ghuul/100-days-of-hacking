#!/bin/bash

if [ "$1" == "" ]; then
    echo "Error: Too few arguments."
    exit 1;
fi

if [ ! -f "$1" ]; then
    echo "Error: '$1' is not a file."
    exit 1;
fi

openssl enc -aes-256-cbc -d -in $1 -pbkdf2 | tar xz
