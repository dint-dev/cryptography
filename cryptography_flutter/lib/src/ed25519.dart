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

import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/helpers.dart';

import 'internal.dart';

/// [Ed25519] implemented with operating system APIs.
class FlutterEd25519 extends DelegatingSignatureAlgorithm
    with FlutterCryptographyImplementation
    implements Ed25519 {
  @override
  final Ed25519 fallback;

  bool usePlugin = true;

  FlutterEd25519(this.fallback);

  @override
  Future<SimpleKeyPair> newKeyPair() {
    return fallback.newKeyPair();
  }

  @override
  Future<SimpleKeyPair> newKeyPairFromSeed(List<int> bytes) async {
    if (usePlugin) {
      try {
        final result = await channel.invokeMethod(
          'ed25519_new_key',
          {
            'seed': Uint8List.fromList(bytes),
          },
        );
        if (result is! Map) {
          throw StateError('Invalid output');
        }
        final privateKey = result['privateKey'] as Uint8List;
        final publicKey = SimplePublicKey(
          result['privateKey'] as Uint8List,
          type: KeyPairType.ed25519,
        );
        return SimpleKeyPairData(
          privateKey,
          publicKey: publicKey,
          type: KeyPairType.ed25519,
        );
      } catch (error, stackTrace) {
        usePlugin = false;
        reportError(error, stackTrace);
      }
    }
    return fallback.newKeyPairFromSeed(bytes);
  }

  @override
  Future<Signature> sign(
    List<int> data, {
    required KeyPair keyPair,
  }) async {
    if (usePlugin) {
      final keyPairData = await keyPair.extract();
      if (keyPairData is! SimpleKeyPairData) {
        throw ArgumentError.value(
          keyPair,
          'keyPair',
          'Extracted key pair should be `SimpleKeyPairData`, but got: `$keyPairData`',
        );
      }
      final result = await channel.invokeMethod(
        'ed25519_sign',
        {
          'data': Uint8List.fromList(data),
          'secretKey': Uint8List.fromList(keyPairData.bytes),
        },
      );
      final error = result['error'];
      if (error is String) {
        throw StateError('error in "package:cryptography_flutter": $error');
      }
      final bytes = result['signature'] as Uint8List;
      final publicKey = base64Decode(result['publicKey'] as String);
      return Signature(
        bytes,
        publicKey: SimplePublicKey(publicKey, type: KeyPairType.ed25519),
      );
    }
    return super.sign(data, keyPair: keyPair);
  }

  @override
  Future<bool> verify(List<int> data, {required Signature signature}) async {
    if (usePlugin) {
      try {
        final publicKey = signature.publicKey as SimplePublicKey;
        final result = await channel.invokeMethod(
          'ed25519_verify',
          {
            'message': base64Encode(data),
            'signature': base64Encode(signature.bytes),
            'publicKey': base64Encode(publicKey.bytes),
          },
        ) as Map;
        final error = result['error'];
        if (error is String) {
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
