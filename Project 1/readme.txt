Members:
    Michael Giraldo (6423028)
    Lucas Arabi (6320457)
    Eddie Rodriguez (6348824)

Language Used: GNU C

Libraries used crypto and openssl
Linker tags include -lcrypto and -lssl

Compile options
gcc -std=gnu1x -Wall -g -I/usr/include/openssl main.c -lcrypto -lssl -L/usr/lib -o monitor

IMPORTANT: Ensure you have the openssl libraries
    libssl-dev on apt
    openssl-devel on yum

