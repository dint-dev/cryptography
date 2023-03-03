## 2.1.1
* Bumps Kotlin Gradle plugin version.

## 2.1.0
* Many, major bug fixes.
* Some breaking changes to the API, but we decided not to increment the major version because we
  don't expect them to affect many developers (while we do want the bug fixes to reach everyone who
  uses the package).
* Many new features.
* We have a completely new test suite that ensures correctness and also reports performance with
  different input sizes.

## 2.0.2

* Fixes ["cryptography_flutter: Fix propagating error to Flutter + fix fallback to non-plugin encrypt/decrypt"](https://github.com/dint-dev/cryptography/pull/76)
* Prints a debug message if a fallback to a Dart implementation happens because of an error.
* Updates dependency constraints and linting rules.

## 2.0.1

* Improves behavior in browsers.
* Improves documentation.

## 2.0.0

* Finishes null safety migration.

## 2.0.0-nullsafety.1

* Fixes SDK and dependency constraints.

## 2.0.0-nullsafety.0

* Upgrades to _package:cryptography_ version 2.x.
* Adds supports for AES and ChaCha20 in Android.

## 1.0.0

* Initial version
