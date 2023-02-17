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

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/dart.dart';

/// An implementation of [Cryptography] that optimizes performance on browsers.
///
/// The performance is optimized by using implementations that call
/// [Web Cryptography API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
/// on browsers. The implementations themselves are not exported.
///
/// ## Optimized algorithms
/// The following algorithms have Web Cryptography API support on browsers:
///   * [AesCbc]
///   * [AesCtr]
///   * [AesGcm]
///   * [Ecdh.p256]
///   * [Ecdh.p384]
///   * [Ecdh.p521]
///   * [Ecdsa.p256]
///   * [Ecdsa.p384]
///   * [Ecdsa.p521]
///   * [Hkdf]
///   * [Hmac]
///   * [Pbkdf2]
///   * [RsaPss]
///   * [RsaSsaPkcs1v15]
///   * [Sha1]
///   * [Sha256]
///   * [Sha384]
///   * [Sha512]
///
/// The class extends [DartCryptography] so other factories will return pure
/// Dart implementations.
class BrowserCryptography extends DartCryptography {
  static final BrowserCryptography defaultInstance = BrowserCryptography();
}
