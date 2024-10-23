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

import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:cryptography_plus/helpers.dart';
import 'package:flutter/foundation.dart';

import '../../cryptography_flutter_plus.dart';
import '../_flutter_cryptography_implementation.dart';
import '../_internal.dart';

/// [Ed25519] that uses platform APIs in Android, iOS, and Mac OS X.
///
/// Note that:
///   * Apple's CryptoKit API returns intentionally non-deterministic
///     Ed25519 signatures.
class FlutterEd25519 extends DelegatingEd25519
    implements PlatformCryptographicAlgorithm {
  @override
  final Ed25519 fallback;

  FlutterEd25519(this.fallback);

  @override
  bool get isSupportedPlatform =>
      FlutterCryptography.isPluginPresent && isCupertino;

  @override
  Future<SimpleKeyPair> newKeyPair() async {
    if (!kIsWeb) {
      if (isSupportedPlatform) {
        final result = await invokeMethod('Ed25519.newKeyPair', {});
        return SimpleKeyPairData(
          result['privateKey'] as Uint8List,
          publicKey: SimplePublicKey(
            result['publicKey'] as Uint8List,
            type: KeyPairType.x25519,
          ),
          type: KeyPairType.x25519,
        );
      }
    }
    return fallback.newKeyPair();
  }

  @override
  Future<SimpleKeyPair> newKeyPairFromSeed(List<int> seed) async {
    return await fallback.newKeyPairFromSeed(seed);
  }

  @override
  Future<Signature> sign(
    List<int> message, {
    required KeyPair keyPair,
  }) async {
    if (!kIsWeb) {
      if (keyPair is SimpleKeyPair) {
        if (isSupportedPlatform) {
          final privateKeyBytes = await keyPair.extractPrivateKeyBytes();
          final publicKey = await keyPair.extractPublicKey();
          final publicKeyBytes = Uint8List.fromList(
            publicKey.bytes,
          );
          final result = await invokeMethod(
            'Ed25519.sign',
            {
              'data': asUint8List(message),
              'privateKey': asUint8List(privateKeyBytes),
              'publicKey': asUint8List(publicKeyBytes),
            },
          );
          final error = result['error'];
          if (error is String) {
            throw StateError('error in "package:cryptography_flutter": $error');
          }
          final bytes = result['signature'] as Uint8List;
          return Signature(
            bytes,
            publicKey: publicKey,
          );
        }
      }
    }
    return await fallback.sign(message, keyPair: keyPair);
  }

  @override
  Future<bool> verify(
    List<int> message, {
    required Signature signature,
  }) async {
    if (isSupportedPlatform) {
      final publicKey = signature.publicKey;
      if (publicKey is SimplePublicKey && isSupportedPlatform) {
        final result = await invokeMethod(
          'Ed25519.verify',
          {
            'data': asUint8List(message),
            'signature': asUint8List(signature.bytes),
            'publicKey': asUint8List(publicKey.bytes),
          },
        );
        final error = result['error'];
        if (error is String) {
          throw StateError('error in "package:cryptography_flutter": $error');
        }
        return result['ok'] as bool;
      }
    }
    return await fallback.verify(
      message,
      signature: signature,
    );
  }
}
