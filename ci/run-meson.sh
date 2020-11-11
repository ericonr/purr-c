#!/bin/sh -x
meson build/
ninja -C build/ all
RATELIMIT=1 ninja -C build/ test
