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

import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/helpers.dart';

import 'internal.dart';

/// [Ecdh] implemented with operating system APIs.
class FlutterEcdh extends DelegatingEcdh
    with FlutterCryptographyImplementation {
  @override
  final Ecdh fallback;
  final String algorithmName;

  bool usePlugin = true;

  FlutterEcdh.p256(Ecdh fallback) : this._(fallback, 'Ecdh.p256');

  FlutterEcdh.p384(Ecdh fallback) : this._(fallback, 'Ecdh.p384');

  FlutterEcdh.p521(Ecdh fallback) : this._(fallback, 'Ecdh.p521');

  FlutterEcdh._(this.fallback, this.algorithmName);

  bool get isSupportedPlatform => Platform.isAndroid;

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
  Future<SecretKey> sharedSecretKey({
    required KeyPair keyPair,
    required PublicKey remotePublicKey,
  }) async {
    if (usePlugin) {
      try {
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
        final result = await channel.invokeMethod(
          'ecdh.sharedSecretKey',
          {
            'algo': algorithmName,
            'privateKey': Uint8List.fromList(keyPairData.d),
            'remoteX': Uint8List.fromList(remotePublicKey.x),
          },
        );
        if (result is! Map) {
          usePlugin = false;
          throw StateError(
            '"package:cryptography_flutter": invalid output: $result',
          );
        }
        final error = result['error'];
        if (error != null) {
          throw StateError(
            '"package:cryptography_flutter": invalid output from plugin: $error',
          );
        }
        final bytes = result['bytes'] as Uint8List;
        return SecretKey(bytes);
      } catch (error, stackTrace) {
        usePlugin = false;
        reportError(error, stackTrace);
      }
    }
    return super.sharedSecretKey(
      keyPair: keyPair,
      remotePublicKey: remotePublicKey,
    );
  }
}
