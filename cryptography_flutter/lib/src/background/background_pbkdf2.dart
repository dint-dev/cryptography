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
import 'package:cryptography_plus/dart.dart';
import 'package:flutter/foundation.dart';

/// [Pbkdf2] that's optimized to use [compute].
class BackgroundPbkdf2 extends Pbkdf2 {
  static const _debugLabel = 'BackgroundPbkdf2.deriveKey';

  @override
  final int bits;

  @override
  final int iterations;

  @override
  final MacAlgorithm macAlgorithm;

  BackgroundPbkdf2({
    required this.macAlgorithm,
    required this.bits,
    required this.iterations,
  }) : super.constructor();

  bool get isSupported {
    final macAlgorithm = this.macAlgorithm;
    if (macAlgorithm is Hmac) {
      final hashAlgorithm = macAlgorithm.hashAlgorithm;
      if (hashAlgorithm is Blake2s) {
        return true;
      }
      if (hashAlgorithm is Sha256) {
        return true;
      }
      if (hashAlgorithm is Sha512) {
        return true;
      }
    }
    return false;
  }

  @override
  Future<SecretKey> deriveKey({
    required SecretKey secretKey,
    required List<int> nonce,
  }) async {
    final macAlgorithm = this.macAlgorithm;
    if (macAlgorithm is Hmac) {
      final hashAlgorithm = macAlgorithm.hashAlgorithm;
      if (hashAlgorithm is Blake2s) {
        final result = await compute(
          _computeDeriveKeyHmacBlake2s,
          await _args(secretKey, nonce),
          debugLabel: _debugLabel,
        );
        return SecretKeyData(result);
      }
      if (hashAlgorithm is Sha256) {
        final result = await compute(
          _computeDeriveKeyHmacSha256,
          await _args(secretKey, nonce),
          debugLabel: _debugLabel,
        );
        return SecretKeyData(result);
      }
      if (hashAlgorithm is Sha512) {
        final result = await compute(
          _computeDeriveKeyHmacSha512,
          await _args(secretKey, nonce),
          debugLabel: _debugLabel,
        );
        return SecretKeyData(result);
      }
    }
    return await DartPbkdf2(
      macAlgorithm: macAlgorithm,
      iterations: iterations,
      bits: bits,
    ).deriveKey(
      secretKey: secretKey,
      nonce: nonce,
    );
  }

  Future<List> _args(SecretKey secretKey, List<int> nonce) async {
    return [bits, iterations, await secretKey.extractBytes(), nonce];
  }

  static Future<List<int>> _compute(
      List args, MacAlgorithm macAlgorithm) async {
    final bits = args[0];
    final iterations = args[1];
    final secretKeyBytes = args[2] as List<int>;
    final nonce = args[3] as List<int>;
    final pbkdf2 = DartPbkdf2(
      bits: bits,
      iterations: iterations,
      macAlgorithm: macAlgorithm,
    );
    final derivedSecretKey = await pbkdf2.deriveKey(
      secretKey: SecretKeyData(secretKeyBytes),
      nonce: nonce,
    );
    return await derivedSecretKey.extractBytes();
  }

  static Future<List<int>> _computeDeriveKeyHmacBlake2s(List args) async {
    return _compute(args, const DartHmac(DartBlake2s()));
  }

  static Future<List<int>> _computeDeriveKeyHmacSha256(List args) async {
    return _compute(args, const DartHmac(DartSha256()));
  }

  static Future<List<int>> _computeDeriveKeyHmacSha512(List args) async {
    return _compute(args, const DartHmac(DartSha512()));
  }
}
