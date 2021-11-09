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

/// [RsaSsaPkcs1v15] implemented with operating system APIs.
class FlutterRsaSsaPkcs1v15 extends DelegatingSignatureAlgorithm
    with FlutterCryptographyImplementation
    implements RsaSsaPkcs1v15 {
  @override
  final RsaSsaPkcs1v15 fallback;

  bool usePlugin = true;

  FlutterRsaSsaPkcs1v15(this.fallback);

  @override
  HashAlgorithm get hashAlgorithm => fallback.hashAlgorithm;

  String get hashAlgorithmName {
    final hashAlgorithm = this.hashAlgorithm;
    if (hashAlgorithm is Sha1) {
      return 'SHA-1';
    }
    if (hashAlgorithm is Sha256) {
      return 'SHA-256';
    }
    if (hashAlgorithm is Sha384) {
      return 'SHA-384';
    }
    if (hashAlgorithm is Sha512) {
      return 'SHA-256';
    }
    return '';
  }

  bool get isSupported => false;

  @override
  Future<RsaKeyPair> newKeyPair({
    int modulusLength = RsaSsaPkcs1v15.defaultModulusLength,
    List<int> publicExponent = RsaSsaPkcs1v15.defaultPublicExponent,
  }) async {
    if (usePlugin) {
      try {
        final result = await channel.invokeMethod(
          'new_rsa_secret_key',
          {},
        );
        if (result is! Map) {
          throw StateError('Invalid output from plugin: $result');
        }
        final d = result['d'] as Uint8List;
        final e = result['e'] as Uint8List;
        final n = result['n'] as Uint8List;
        final p = result['p'] as Uint8List;
        final q = result['q'] as Uint8List;
        return RsaKeyPairData(
          d: d,
          e: e,
          n: n,
          p: p,
          q: q,
        );
      } catch (error) {
        usePlugin = false;
      }
    }
    return fallback.newKeyPair();
  }

  @override
  Future<Signature> sign(List<int> data, {required KeyPair keyPair}) async {
    if (usePlugin) {
      try {
        final rsaKeyPair = await keyPair.extract();
        if (rsaKeyPair is! RsaKeyPairData) {
          throw ArgumentError.value(
            keyPair,
            'keyPair',
          );
        }
        final result = await channel.invokeMethod(
          'rsa_ssa_pkcs1v15_sign',
          {
            'data': Uint8List.fromList(data),
            'hash': hashAlgorithmName,
            'd': Uint8List.fromList(rsaKeyPair.d),
            'e': Uint8List.fromList(rsaKeyPair.e),
            'n': Uint8List.fromList(rsaKeyPair.n),
            'p': Uint8List.fromList(rsaKeyPair.p),
            'q': Uint8List.fromList(rsaKeyPair.q),
          },
        );
        if (result is! Map) {
          throw StateError('Invalid output from plugin: $result');
        }
        final bytes = base64Decode(result['bytes'] as String);
        return Signature(bytes, publicKey: await rsaKeyPair.extractPublicKey());
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
          'rsa_ssa_pkcs1v15_verify',
          {
            'data': Uint8List.fromList(data),
            'hash': hashAlgorithmName,
            'e': Uint8List.fromList(rsaSecretKey.e),
            'n': Uint8List.fromList(rsaSecretKey.n),
          },
        );
        if (result is! Map) {
          throw StateError('Invalid output from plugin: $result');
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
