// Copyright 2019-2020 Gohilla.
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

import 'dart:math';

import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:cryptography_plus/dart.dart';
import 'package:meta/meta.dart';

/// An implementation of [Cryptography] that uses [Web Cryptography API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
/// for better performance in browsers.
///
/// Browsers support Web Cryptography only in
/// [secure (HTTPS) contexts](https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts).
/// In non-secure contexts, pure Dart implementations will be used. You can
/// check whether Web Cryptography is used in the current environment by reading
/// the value of [BrowserCryptography.isSupported].
///
/// ## Optimized algorithms
/// The following configurations are optimized using Web Cryptography:
///   * [AesCbc]
///     * Only when key length is 128 or 256 bits.
///     * Only when padding is [PaddingAlgorithm.pkcs7].
///   * [AesCtr]
///     * Only when key length is 128 or 256 bits.
///   * [AesGcm]
///     * Only when key length is 128 or 256 bits.
///   * [Ecdh]
///   * [Ecdsa]
///     * Only when `hash` is [Sha256], [Sha384], or [Sha512].
///   * [Hkdf]
///     * Only when `hmac` is [Hmac.sha256], [Hmac.sha384], or [Hmac.sha512].
///   * [Hmac]
///     * Only when `hash` is [Sha256], [Sha384], or [Sha512].
///   * [Pbkdf2]
///   * [RsaPss]
///   * [RsaSsaPkcs1v15]
///   * [Sha1]
///   * [Sha256]
///   * [Sha384]
///   * [Sha512]
///
/// The class extends [DartCryptography] so other factory methods will return
/// pure Dart implementations.
///
class BrowserCryptography extends DartCryptography {
  /// Platform-specific default instance.
  ///
  /// In browsers, the value will be an instance of [BrowserCryptography]. In
  /// other platforms, the value will be [DartCryptography.defaultInstance].
  static final Cryptography defaultInstance = DartCryptography.defaultInstance;

  /// @nodoc
  // TODO: Remove this
  @visibleForTesting
  static bool isDisabledForTesting = false;

  /// Whether Web Cryptography is supported in this platform.
  ///
  /// Browsers support Web Cryptography only in
  /// [secure (HTTPS) contexts](https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts).
  /// In non-secure contexts, the value of this getter is `false`.
  ///
  /// Note that you can still use [BrowserCryptography] or extend the class,
  /// because the fallback implementations implemented in pure Dart are
  /// always available.
  static bool get isSupported => false;

  /// Constructs an instance of [BrowserCryptography].
  ///
  /// If [random] is not given, algorithms will use some cryptographically
  /// secure random number generator (CSRNG) such as [Random.secure].
  BrowserCryptography({Random? random}) : super(random: random);

  @override
  BrowserCryptography withRandom(Random? random) {
    return BrowserCryptography(random: random);
  }
}
