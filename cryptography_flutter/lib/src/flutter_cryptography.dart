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

import 'package:cryptography/browser.dart';
import 'package:cryptography/cryptography.dart';
import 'package:flutter/foundation.dart';

import '../cryptography_flutter.dart';
import '_internal.dart';
import 'flutter_cryptography_impl_vm.dart'
    if (dart.library.html) 'flutter_cryptography_impl_browser.dart' as internal;

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
class FlutterCryptography extends BrowserCryptography {
  /// Either [FlutterCryptography] or [BrowserCryptography] depending on
  /// [FlutterCryptography.isPluginPresent].
  static final Cryptography defaultInstance =
      internal.flutterCryptographyInstance;

  /// Tells whether the current platform has a plugin.
  ///
  /// Only Android, iOS, and Mac OS X are supported at the moment.
  static bool get isPluginPresent =>
      !kIsWeb && !hasSeenMissingPluginException && (isAndroid || isCupertino);

  Chacha20? _chacha20Poly1305Aead;
  Ed25519? _ed25519;
  X25519? _x25519;

  FlutterCryptography();

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
  Ed25519 ed25519() {
    if (kIsWeb) {
      return super.ed25519();
    }
    return _ed25519 ??= _chooseEd25519();
  }

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
    final backgroundImpl = BackgroundEd25519();
    final platformImpl = FlutterEd25519(backgroundImpl);
    if (platformImpl.isSupportedPlatform) {
      return platformImpl;
    }
    return backgroundImpl;
  }

  X25519 _chooseX25519() {
    final backgroundImpl = BackgroundX25519();
    final platformImpl = FlutterX25519(backgroundImpl);
    if (platformImpl.isSupportedPlatform) {
      return platformImpl;
    }
    return backgroundImpl;
  }

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
