# !/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e
set -x

# Navigate to the root directory of the project
cd "$(dirname "$0")/.."

# Ensure Flutter dependencies are up to date
flutter pub get

# Run tests on Android emulator
flutter test integration_test -r expanded -d "${ANDROID_DEVICE:=sdk gphone64}"

if [[ "$(uname)" == "Darwin" ]]; then
  # Run tests on iOS simulator
  flutter test integration_test -r expanded -d "${IOS_DEVICE:=iPhone}"

  # Run tests on macOS
  flutter test integration_test -r expanded -d macos
fi