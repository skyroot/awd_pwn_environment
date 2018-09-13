#!/bin/sh
docker build -t "pwn_format" .
docker run -d -p 9999:9999 --name="pwn_format" pwn_format