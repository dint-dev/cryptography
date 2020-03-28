#!/bin/bash

set -e
cd `dirname $0`

# Test with Dart SDK
./all.sh pub get
./all.sh pub run test

# Test with Flutter SDK
./all.sh flutter pub get
./all.sh flutter pub run test --platform=vm

# Restore Dart SDK dependencies
./all.sh pub get --offline