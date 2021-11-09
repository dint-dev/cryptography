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

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/helpers.dart';

import 'internal.dart';

/// [Ecdsa] implemented with operating system APIs.
class FlutterEcdsa extends DelegatingEcdsa
    with FlutterCryptographyImplementation {
  @override
  final Ecdsa fallback;

  final String algorithmName;

  var usePlugin = true;

  FlutterEcdsa.p256(Ecdsa fallback) : this._(fallback, 'Ecdsa.p256');

  FlutterEcdsa.p384(Ecdsa fallback) : this._(fallback, 'Ecdsa.p384');

  FlutterEcdsa.p521(Ecdsa fallback) : this._(fallback, 'Ecdsa.p521');

  FlutterEcdsa._(this.fallback, this.algorithmName);

  @override
  Future<EcKeyPair> newKeyPair() async {
    final result = await invokeMethod(
      'new_ec_secret_key',
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

  @override
  Future<Signature> sign(
    List<int> data, {
    required KeyPair keyPair,
  }) async {
    if (usePlugin) {
      try {
        final keyPairData = await keyPair.extract();
        if (keyPairData is! EcKeyPairData) {
          throw ArgumentError.value(
            keyPairData,
            'keyPair',
          );
        }
        final result = await channel.invokeMethod(
          'Ecdsa.sign',
          {
            'algo': algorithmName,
            'data': Uint8List.fromList(data),
            'privateKey': Uint8List.fromList(keyPairData.d),
          },
        ) as Map;
        final error = result['error'];
        if (error is String) {
          throw StateError(
              '"package:cryptography_flutter": signing failed: $error');
        }
        final signature = List<int>.unmodifiable(
          error['signature'] as Uint8List,
        );
        final publicKey = await keyPairData.extractPublicKey();
        return Signature(signature, publicKey: publicKey);
      } catch (error, stackTrace) {
        usePlugin = false;
        reportError(error, stackTrace);
      }
    }
    return super.sign(data, keyPair: keyPair);
  }

  @override
  Future<bool> verify(List<int> data, {required Signature signature}) async {
    if (usePlugin) {
      try {
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
            'algo': algorithmName,
            'data': Uint8List.fromList(data),
            'signature': Uint8List.fromList(signature.bytes),
            'publicKeyX': Uint8List.fromList(publicKey.x),
            'publicKeyY': Uint8List.fromList(publicKey.y),
          },
        );
        final error = result['error'];
        if (error != null) {
          throw StateError('error in "package:cryptography_flutter": $error');
        }
        return result['result'] as bool;
      } catch (error, stackTrace) {
        usePlugin = false;
        reportError(error, stackTrace);
      }
    }
    return super.verify(data, signature: signature);
  }
}
