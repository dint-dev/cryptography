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

/// [RsaPss] implemented with operating system APIs.
class FlutterRsaPss extends DelegatingSignatureAlgorithm
    with FlutterCryptographyImplementation
    implements RsaPss {
  @override
  final RsaPss fallback;

  bool usePlugin = true;

  FlutterRsaPss(this.fallback);

  @override
  HashAlgorithm get hashAlgorithm => fallback.hashAlgorithm;

  bool get isSupported => false;

  @override
  Future<RsaKeyPair> newKeyPair({
    int modulusLength = RsaPss.defaultModulusLength,
    List<int> publicExponent = RsaPss.defaultPublicExponent,
  }) {
    return fallback.newKeyPair(
      modulusLength: modulusLength,
      publicExponent: publicExponent,
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
        if (keyPairData is! RsaKeyPairData) {
          throw ArgumentError.value(
            keyPair,
            'keyPair',
          );
        }
        final result = await channel.invokeMethod(
          'rsa_pss_sign',
          {
            'data': base64Encode(data),
            'd': base64Encode(keyPairData.d),
            'e': base64Encode(keyPairData.e),
            'n': base64Encode(keyPairData.n),
            'p': base64Encode(keyPairData.p),
            'q': base64Encode(keyPairData.q),
          },
        );
        if (result is! Map) {
          throw StateError('Invalid output from plugin: $result');
        }
        final bytes = base64Decode(result['bytes'] as String);
        return Signature(bytes,
            publicKey: await keyPairData.extractPublicKey());
      } catch (error) {
        usePlugin = false;
      }
    }
    return super.sign(data, keyPair: keyPair);
  }

  @override
  Future<bool> verify(List<int> data, {required Signature signature}) async {
    if (usePlugin) {
      try {
        final rsaSecretKey = signature.publicKey as RsaPublicKey;
        final result = await channel.invokeMethod(
          'rsa_pss_verify',
          {
            'data': Uint8List.fromList(data),
            'e': Uint8List.fromList(rsaSecretKey.e),
            'n': Uint8List.fromList(rsaSecretKey.n),
          },
        );
        if (result is! Map) {
          throw StateError('Invalid output from plugin: $result');
        }
        return result['result'] as bool;
      } catch (error) {
        usePlugin = false;
      }
    }
    return super.verify(data, signature: signature);
  }
}
