#!/bin/bash

gcc -lsodium streamCipherEncryption.c -o cipherGen
./cipherGen
g++ -Wall -g -O2 streamCipherDecryption.cpp -o messageGen
./messageGen
rm ./*Gen
