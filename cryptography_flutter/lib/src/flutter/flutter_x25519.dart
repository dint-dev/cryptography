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

/// [X25519] that uses platform APIs in Android, iOS, and Mac OS X.
class FlutterX25519 extends DelegatingKeyExchangeAlgorithm
    implements PlatformCryptographicAlgorithm, X25519 {
  @override
  final X25519 fallback;

  FlutterX25519(this.fallback);

  @override
  bool get isSupportedPlatform =>
      FlutterCryptography.isPluginPresent && isCupertino;

  @override
  KeyPairType<KeyPairData, PublicKey> get keyPairType => fallback.keyPairType;

  @override
  Future<SimpleKeyPair> newKeyPair() async {
    if (!kIsWeb) {
      if (isSupportedPlatform) {
        final result = await invokeMethod('X25519.newKeyPair', {});
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
    return await fallback.newKeyPair();
  }

  @override
  Future<SimpleKeyPair> newKeyPairFromSeed(List<int> seed) async {
    return await fallback.newKeyPairFromSeed(seed);
  }

  /// Calculates a shared [SecretKey].
  @override
  Future<SecretKey> sharedSecretKey({
    required KeyPair keyPair,
    required PublicKey remotePublicKey,
  }) async {
    if (!kIsWeb) {
      if (isSupportedPlatform &&
          keyPair is SimpleKeyPairData &&
          remotePublicKey is SimplePublicKey) {
        final privateKey = await keyPair.extractPrivateKeyBytes();
        final publicKey = remotePublicKey.bytes;
        final result = await invokeMethod('X25519.sharedSecretKey', {
          'privateKey': asUint8List(privateKey),
          'publicKey': asUint8List(publicKey),
        });
        return SecretKey(
          result['sharedSecretKey'] as Uint8List,
        );
      }
    }
    return await fallback.sharedSecretKey(
      keyPair: keyPair,
      remotePublicKey: remotePublicKey,
    );
  }
}
