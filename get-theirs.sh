#!/bin/bash
set -e

openssl s_client -connect "${1}:443" -showcerts -verify 5 < /dev/null 