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

import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:cryptography_plus/helpers.dart';

import '../_flutter_cryptography_implementation.dart';
import '../_internal.dart';

/// [RsaSsaPkcs1v15] that uses platform APIs in Android.
class FlutterRsaSsaPkcs1v15 extends DelegatingSignatureAlgorithm
    implements PlatformCryptographicAlgorithm, RsaSsaPkcs1v15 {
  @override
  final RsaSsaPkcs1v15 fallback;

  FlutterRsaSsaPkcs1v15(this.fallback);

  @override
  HashAlgorithm get hashAlgorithm => fallback.hashAlgorithm;

  String get hashAlgorithmName {
    final hashAlgorithm = this.hashAlgorithm;
    if (hashAlgorithm is Sha512) {
      return 'SHA-512';
    }
    if (hashAlgorithm is Sha384) {
      return 'SHA-384';
    }
    if (hashAlgorithm is Sha256) {
      return 'SHA-256';
    }
    if (hashAlgorithm is Sha1) {
      return 'SHA-1';
    }
    return '';
  }

  // TODO: Change this once the implementation is done.
  @override
  bool get isSupportedPlatform => false;

  @override
  Future<RsaKeyPair> newKeyPair({
    int modulusLength = RsaSsaPkcs1v15.defaultModulusLength,
    List<int> publicExponent = RsaSsaPkcs1v15.defaultPublicExponent,
  }) async {
    if (isSupportedPlatform) {
      final result = await invokeMethod(
        'RsaSsaPkcs1v15.newKeyPair',
        {
          'modulusLength': modulusLength,
          'publicExponent': publicExponent,
        },
      );
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
    }
    return await fallback.newKeyPair();
  }

  @override
  Future<Signature> sign(List<int> message, {required KeyPair keyPair}) async {
    if (isSupportedPlatform) {
      final rsaKeyPair = await keyPair.extract();
      if (rsaKeyPair is! RsaKeyPairData) {
        throw ArgumentError.value(
          keyPair,
          'keyPair',
        );
      }
      final result = await invokeMethod(
        'RsaSsaPkcs1v15.sign',
        {
          'data': Uint8List.fromList(message),
          'hash': hashAlgorithmName,
          'd': Uint8List.fromList(rsaKeyPair.d),
          'e': Uint8List.fromList(rsaKeyPair.e),
          'n': Uint8List.fromList(rsaKeyPair.n),
          'p': Uint8List.fromList(rsaKeyPair.p),
          'q': Uint8List.fromList(rsaKeyPair.q),
        },
      );
      final bytes = base64Decode(result['bytes'] as String);
      return Signature(bytes, publicKey: await rsaKeyPair.extractPublicKey());
    }
    return await fallback.sign(message, keyPair: keyPair);
  }

  @override
  Future<bool> verify(List<int> message, {required Signature signature}) async {
    if (isSupportedPlatform) {
      final rsaPublicKey = signature.publicKey as RsaPublicKey;
      final result = await invokeMethod(
        'RsaSsaPkcs1v15.verify',
        {
          'data': Uint8List.fromList(message),
          'hash': hashAlgorithmName,
          'e': Uint8List.fromList(rsaPublicKey.e),
          'n': Uint8List.fromList(rsaPublicKey.n),
        },
      );
      return result['ok'] as bool;
    }
    return await fallback.verify(message, signature: signature);
  }
}
