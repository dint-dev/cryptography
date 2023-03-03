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

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/helpers.dart';

import '../../cryptography_flutter.dart';
import '../_internal.dart';

/// [Ecdh] implemented with operating system APIs.
class FlutterEcdh extends DelegatingEcdh
    implements PlatformCryptographicAlgorithm {
  @override
  final Ecdh fallback;

  FlutterEcdh.p256({int length = 32})
      : this._(
          Cryptography.defaultInstance.ecdhP256(length: length),
        );

  FlutterEcdh.p384({int length = 32})
      : this._(
          Cryptography.defaultInstance.ecdhP384(length: length),
        );

  FlutterEcdh.p521({int length = 32})
      : this._(
          Cryptography.defaultInstance.ecdhP521(length: length),
        );

  FlutterEcdh._(this.fallback);

  @override
  bool get isSupportedPlatform =>
      FlutterCryptography.isPluginPresent && isCupertino;

  String get _curveName {
    switch (keyPairType) {
      case KeyPairType.p256:
        return 'p256';
      case KeyPairType.p384:
        return 'p384';
      case KeyPairType.p521:
        return 'p521';
      default:
        throw StateError('Unsupported key pair type: ${fallback.keyPairType}');
    }
  }

  @override
  Future<EcKeyPair> newKeyPair() async {
    if (isSupportedPlatform) {
      final result = await invokeMethod(
        'Ecdh.newKeyPair',
        {
          'curve': _curveName,
        },
      );
      final d = result['d'] as Uint8List;
      final x = result['x'] as Uint8List;
      final y = result['y'] as Uint8List;
      return EcKeyPairData(
        d: d,
        x: x,
        y: y,
        type: keyPairType,
      );
    }
    return await fallback.newKeyPair();
  }

  @override
  Future<SecretKey> sharedSecretKey({
    required KeyPair keyPair,
    required PublicKey remotePublicKey,
  }) async {
    if (isSupportedPlatform) {
      final keyPairData = await keyPair.extract();
      if (keyPairData is! EcKeyPairData) {
        throw ArgumentError.value(
          keyPair,
          'keyPair',
          'Expected EcKeyPair',
        );
      }
      if (remotePublicKey is! EcPublicKey) {
        throw ArgumentError.value(
          remotePublicKey,
          'remotePublicKey',
          'Expected EcPublicKey',
        );
      }
      final result = await invokeMethod(
        'Ecdh.sharedSecretKey',
        {
          'curve': _curveName,
          'privateD': Uint8List.fromList(keyPairData.d),
          'remoteX': Uint8List.fromList(remotePublicKey.x),
        },
      );
      final error = result['error'];
      if (error != null) {
        throw StateError(
          '"package:cryptography_flutter": invalid output from plugin: $error',
        );
      }
      final bytes = result['bytes'] as Uint8List;
      return SecretKey(bytes);
    }
    return await fallback.sharedSecretKey(
      keyPair: keyPair,
      remotePublicKey: remotePublicKey,
    );
  }
}
