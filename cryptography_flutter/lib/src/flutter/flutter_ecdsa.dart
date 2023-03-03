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

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/helpers.dart';
import 'package:flutter/foundation.dart';

import '../../cryptography_flutter.dart';
import '../_internal.dart';

/// [Ecdsa] implemented with operating system APIs.
class FlutterEcdsa extends DelegatingEcdsa
    implements PlatformCryptographicAlgorithm {
  @override
  final Ecdsa fallback;

  FlutterEcdsa.p256(HashAlgorithm hashAlgorithm)
      : this._(
          Cryptography.defaultInstance.ecdsaP256(hashAlgorithm),
        );

  FlutterEcdsa.p384(HashAlgorithm hashAlgorithm)
      : this._(
          Cryptography.defaultInstance.ecdsaP384(hashAlgorithm),
        );

  FlutterEcdsa.p521(HashAlgorithm hashAlgorithm)
      : this._(
          Cryptography.defaultInstance.ecdsaP521(hashAlgorithm),
        );

  FlutterEcdsa._(this.fallback);

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
        'Ecdsa.newKeyPair',
        {
          'curve': keyPairType.name,
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
    return fallback.newKeyPair();
  }

  @override
  Future<Signature> sign(
    List<int> message, {
    required KeyPair keyPair,
  }) async {
    if (isSupportedPlatform) {
      final keyPairData = await keyPair.extract();
      if (keyPairData is! EcKeyPairData) {
        throw ArgumentError.value(
          keyPairData,
          'keyPair',
        );
      }
      final result = await invokeMethod(
        'Ecdsa.sign',
        {
          'curve': _curveName,
          'data': Uint8List.fromList(message),
          'd': Uint8List.fromList(keyPairData.d),
          'x': Uint8List.fromList(keyPairData.x),
          'y': Uint8List.fromList(keyPairData.y),
        },
      );
      final error = result['error'] as String?;
      if (error != null) {
        throw StateError(
          '"package:cryptography_flutter": $runtimeType.sign failed: $error',
        );
      }
      final signature = result['signature'] as Uint8List;
      final publicKey = await keyPairData.extractPublicKey();
      return Signature(signature, publicKey: publicKey);
    }
    return await fallback.sign(message, keyPair: keyPair);
  }

  @override
  Future<bool> verify(List<int> message, {required Signature signature}) async {
    if (isSupportedPlatform) {
      final publicKey = signature.publicKey;
      if (publicKey is! EcPublicKey) {
        throw ArgumentError.value(
          signature,
          'signature',
        );
      }
      final result = await invokeMethod(
        'Ecdsa.verify',
        {
          'curve': _curveName,
          'data': Uint8List.fromList(message),
          'signature': Uint8List.fromList(signature.bytes),
          'x': Uint8List.fromList(publicKey.x),
          'y': Uint8List.fromList(publicKey.y),
        },
      );
      final error = result['error'];
      if (error != null) {
        throw StateError(
          '"package:cryptography_flutter": $runtimeType.verify failed: $error',
        );
      }
      return result['result'] as bool;
    }
    return await fallback.verify(message, signature: signature);
  }
}
