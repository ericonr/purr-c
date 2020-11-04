#!/bin/sh -x
./configure
make -j all
RATELIMIT=1 make check check-net
