#!/bin/bash

set -e
cd `dirname $0`

./all.sh pub get
./all.sh pub run test
./all.sh flutter pub get
./all.sh flutter pub run test --platform=vm