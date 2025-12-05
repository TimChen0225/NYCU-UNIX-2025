#!/bin/bash

cd cryptomod
make clean
make install
cd ..
./qemu.sh