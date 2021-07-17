// Copyright 2019-2020 Gohilla Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import 'package:cryptography/browser.dart';
import 'package:cryptography/cryptography.dart';

import 'flutter_cryptography_impl_vm.dart'
    if (dart.library.html) 'flutter_cryptography_impl_browser.dart';

/// An implementation [Cryptography] that uses native operating system APIs.
///
/// ## Getting started
/// ```
/// import 'package:cryptography_flutter/cryptography_flutter.dart' show FlutterCryptography;
///
/// void main() {
///   // Enables use of Flutter cryptography.
///   //
///   // You can call this anywhere in your application, but we recommend the
///   // main function.
///   FlutterCryptography.enable();
///
///   // ...
/// }
/// ```
///
/// ## Supported algorithms
///   * Android:
///     * [AesCbc]
///     * [AesCtr]
///     * [AesGcm]
///     * [Chacha20.poly1305Aead]
///   * iOS and Mac OS X:
///     * [AesGcm]
///     * [Chacha20.poly1305Aead]
class FlutterCryptography extends BrowserCryptography {
  /// Default instance of [FlutterCryptography].
  static final FlutterCryptography defaultInstance = FlutterCryptography();

  factory FlutterCryptography() = FlutterCryptographyImpl;

  /// Enables use of [FlutterCryptography].
  ///
  /// You can call this method any number of times.
  ///
  /// The method is just a helper for calling [Cryptography.freezeInstance()]:
  /// ```
  /// Cryptography.freezeInstance(FlutterCryptography.defaultInstance);
  /// ```
  static void enable() {
    Cryptography.freezeInstance(defaultInstance);
  }
}
