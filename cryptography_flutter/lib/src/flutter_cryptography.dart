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
import 'package:cryptography_flutter_plus/src/flutter/flutter_hmac.dart';
import 'package:flutter/foundation.dart';

import '../cryptography_flutter_plus.dart';
import '_internal.dart';

/// An implementation [Cryptography] that uses native operating system APIs.
///
/// ## Getting started
/// ```
/// import 'package:cryptography_flutter_plus/cryptography_flutter_plus.dart' show FlutterCryptography;
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
class FlutterCryptography extends BrowserCryptography {
  /// Either [FlutterCryptography] or [BrowserCryptography] depending on
  /// [FlutterCryptography.isPluginPresent].
  static final Cryptography defaultInstance =
      kIsWeb ? BrowserCryptography.defaultInstance : FlutterCryptography();

  /// Tells whether the current platform has a plugin.
  ///
  /// Only Android, iOS, and Mac OS X are supported at the moment.
  static bool get isPluginPresent =>
      !kIsWeb && !hasSeenMissingPluginException && (isAndroid || isCupertino);

  Chacha20? _chacha20Poly1305Aead;
  Ed25519? _ed25519;
  X25519? _x25519;

  FlutterCryptography({Random? random}) : super(random: random);

  @override
  AesGcm aesGcm({
    int secretKeyLength = 32,
    int nonceLength = AesGcm.defaultNonceLength,
  }) {
    if (kIsWeb || nonceLength != AesGcm.defaultNonceLength) {
      return super.aesGcm(
        secretKeyLength: secretKeyLength,
        nonceLength: nonceLength,
      );
    }
    if (nonceLength == AesGcm.defaultNonceLength) {
      final platformImpl = FlutterAesGcm(
        secretKeyLength: secretKeyLength,
      );
      if (platformImpl.isSupportedPlatform) {
        return platformImpl;
      }
    }
    return BackgroundAesGcm(
      secretKeyLength: secretKeyLength,
      nonceLength: nonceLength,
    );
  }

  @override
  Chacha20 chacha20Poly1305Aead() {
    if (kIsWeb) {
      return super.chacha20Poly1305Aead();
    }
    return _chacha20Poly1305Aead ??= _chooseChacha20poly1305aead();
  }

  @override
  Ecdh ecdhP256({required int length}) {
    final impl = FlutterEcdh.p256(length: length);
    if (impl.isSupportedPlatform) {
      return impl;
    }
    return super.ecdhP256(length: length);
  }

  @override
  Ecdh ecdhP384({required int length}) {
    final impl = FlutterEcdh.p384(length: length);
    if (impl.isSupportedPlatform) {
      return impl;
    }
    return super.ecdhP384(length: length);
  }

  @override
  Ecdh ecdhP521({required int length}) {
    final impl = FlutterEcdh.p521(length: length);
    if (impl.isSupportedPlatform) {
      return impl;
    }
    return super.ecdhP521(length: length);
  }

  @override
  Ecdsa ecdsaP256(HashAlgorithm hashAlgorithm) {
    final impl = FlutterEcdsa.p256(hashAlgorithm);
    if (impl.isSupportedPlatform) {
      return impl;
    }
    return super.ecdsaP256(hashAlgorithm);
  }

  @override
  Hmac hmac(HashAlgorithm hashAlgorithm) {
    final impl = FlutterHmac(hashAlgorithm);
    if (impl.isSupportedPlatform) {
      return impl;
    }
    return super.hmac(hashAlgorithm);
  }

  @override
  Ecdsa ecdsaP384(HashAlgorithm hashAlgorithm) {
    final impl = FlutterEcdsa.p384(hashAlgorithm);
    if (impl.isSupportedPlatform) {
      return impl;
    }
    return super.ecdsaP384(hashAlgorithm);
  }

  @override
  Ecdsa ecdsaP521(HashAlgorithm hashAlgorithm) {
    final impl = FlutterEcdsa.p521(hashAlgorithm);
    if (impl.isSupportedPlatform) {
      return impl;
    }
    return super.ecdsaP521(hashAlgorithm);
  }

  @override
  Ed25519 ed25519() {
    if (kIsWeb) {
      return super.ed25519();
    }
    return _ed25519 ??= _chooseEd25519();
  }

  @override
  Pbkdf2 pbkdf2({
    required MacAlgorithm macAlgorithm,
    required int iterations,
    required int bits,
  }) {
    // Platform implementation?
    final platformImpl = FlutterPbkdf2(
      macAlgorithm: macAlgorithm,
      iterations: iterations,
      bits: bits,
      fallback: DartPbkdf2(
        macAlgorithm: macAlgorithm,
        iterations: iterations,
        bits: bits,
      ),
    );
    if (platformImpl.isSupported) {
      return platformImpl;
    }

    // Background implementation?
    final backgroundImpl = BackgroundPbkdf2(
      macAlgorithm: macAlgorithm,
      bits: bits,
      iterations: iterations,
    );
    if (backgroundImpl.isSupported) {
      return backgroundImpl;
    }

    // Default
    return super.pbkdf2(
      macAlgorithm: macAlgorithm,
      iterations: iterations,
      bits: bits,
    );
  }

  @override
  FlutterCryptography withRandom(Random? random) =>
      FlutterCryptography(random: random);

  @override
  X25519 x25519() {
    if (kIsWeb) {
      return super.x25519();
    }
    return _x25519 ??= _chooseX25519();
  }

  Chacha20 _chooseChacha20poly1305aead() {
    final platformImpl = FlutterChacha20.poly1305Aead();
    if (platformImpl.isSupportedPlatform) {
      return platformImpl;
    }
    return BackgroundChacha.poly1305Aead();
  }

  Ed25519 _chooseEd25519() {
    final backgroundImpl = DartEd25519();
    final platformImpl = FlutterEd25519(backgroundImpl);
    if (platformImpl.isSupportedPlatform) {
      return platformImpl;
    }
    return backgroundImpl;
  }

  X25519 _chooseX25519() {
    const backgroundImpl = DartX25519();
    final platformImpl = FlutterX25519(backgroundImpl);
    if (platformImpl.isSupportedPlatform) {
      return platformImpl;
    }
    return backgroundImpl;
  }

  @Deprecated(
    'Calling this is no longer necessary.'
    ' Flutter will enable the plugin automatically.',
  )
  static void enable() {
    Cryptography.freezeInstance(defaultInstance);
  }

  /// Called by Flutter when the plugin is registered.
  static void registerWith() {
    Cryptography.instance = defaultInstance;
  }
}
