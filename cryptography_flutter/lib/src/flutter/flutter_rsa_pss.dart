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

/// [RsaPss] that uses platform APIs in Android.
class FlutterRsaPss extends DelegatingRsaPss
    implements PlatformCryptographicAlgorithm {
  @override
  final RsaPss fallback;

  FlutterRsaPss(this.fallback);

  @override
  HashAlgorithm get hashAlgorithm => fallback.hashAlgorithm;

  // TODO: Change this once the implementation is done.
  @override
  bool get isSupportedPlatform => false;

  @override
  Future<RsaKeyPair> newKeyPair({
    int modulusLength = RsaPss.defaultModulusLength,
    List<int> publicExponent = RsaPss.defaultPublicExponent,
  }) async {
    if (isSupportedPlatform) {
      final result = await invokeMethod(
        'RsaPss.newKeyPair',
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
    return await fallback.newKeyPair(
      modulusLength: modulusLength,
      publicExponent: publicExponent,
    );
  }

  @override
  Future<Signature> sign(
    List<int> message, {
    required KeyPair keyPair,
  }) async {
    if (isSupportedPlatform) {
      final keyPairData = await keyPair.extract();
      if (keyPairData is! RsaKeyPairData) {
        throw ArgumentError.value(
          keyPair,
          'keyPair',
        );
      }
      final result = await invokeMethod(
        'RsaPss.sign',
        {
          'data': base64Encode(message),
          'd': base64Encode(keyPairData.d),
          'e': base64Encode(keyPairData.e),
          'n': base64Encode(keyPairData.n),
          'p': base64Encode(keyPairData.p),
          'q': base64Encode(keyPairData.q),
        },
      );
      final bytes = base64Decode(result['bytes'] as String);
      return Signature(
        bytes,
        publicKey: await keyPairData.extractPublicKey(),
      );
    }
    return await fallback.sign(
      message,
      keyPair: keyPair,
    );
  }

  @override
  Future<bool> verify(List<int> message, {required Signature signature}) async {
    if (isSupportedPlatform) {
      final rsaPublicKey = signature.publicKey as RsaPublicKey;
      final result = await invokeMethod(
        'RsaPss.verify',
        {
          'data': Uint8List.fromList(message),
          'e': Uint8List.fromList(rsaPublicKey.e),
          'n': Uint8List.fromList(rsaPublicKey.n),
        },
      );
      return result['ok'] as bool;
    }
    return await fallback.verify(
      message,
      signature: signature,
    );
  }
}
