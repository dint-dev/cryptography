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

import '../_internal.dart';

/// [Pbkdf2] that uses platform APIs in Android.
class FlutterPbkdf2 extends Pbkdf2 {
  @override
  final int bits;

  @override
  final int iterations;

  @override
  final MacAlgorithm macAlgorithm;

  final Pbkdf2? fallback;

  FlutterPbkdf2({
    required this.macAlgorithm,
    required this.bits,
    required this.iterations,
    this.fallback,
  }) : super.constructor();

  bool get isSupported => _macNameFor(macAlgorithm) != null;

  @override
  Future<SecretKey> deriveKeyFromPassword({
    required String password,
    required List<int> nonce,
  }) async {
    final macName = _macNameFor(macAlgorithm);
    if (macName != null) {
      final result = await invokeMethod(
        'pbkdf2',
        {
          'mac': macName,
          'bits': bits,
          'iterations': iterations,
          'password': password,
          'nonce': asUint8List(nonce),
        },
      );
      return SecretKeyData(result['hash'] as List<int>);
    }
    final fallback = this.fallback;
    if (fallback == null) {
      throw UnsupportedError('Unsupported and no fallback');
    }
    return fallback.deriveKeyFromPassword(
      password: password,
      nonce: nonce,
    );
  }

  static String? _macNameFor(MacAlgorithm macAlgorithm) {
    // Currently we support only Android
    if (isAndroid) {
      if (macAlgorithm is Hmac) {
        final hashAlgorithm = macAlgorithm.hashAlgorithm;
        if (hashAlgorithm is Sha1) {
          return 'HMAC-SHA1';
        }
        if (hashAlgorithm is Sha224) {
          return 'HMAC-SHA224';
        }
        if (hashAlgorithm is Sha256) {
          return 'HMAC-SHA256';
        }
        if (hashAlgorithm is Sha384) {
          return 'HMAC-SHA384';
        }
        if (hashAlgorithm is Sha512) {
          return 'HMAC-SHA512';
        }
      }
    }
    return null;
  }

  @override
  Future<SecretKey> deriveKey(
      {required SecretKey secretKey, required List<int> nonce}) {
    final fallback = this.fallback;
    if (fallback == null) {
      throw UnsupportedError('Unsupported and no fallback');
    }
    return fallback.deriveKey(
      secretKey: secretKey,
      nonce: nonce,
    );
  }
}
