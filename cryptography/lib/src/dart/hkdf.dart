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

import 'dart:typed_data';

import 'package:cryptography_plus/cryptography_plus.dart';

/// [Hkdf] implemented in pure Dart.
///
/// For examples and more information about the algorithm, see documentation for
/// the class [Hkdf].
class DartHkdf extends Hkdf {
  @override
  final Hmac hmac;

  @override
  final int outputLength;

  const DartHkdf({required this.hmac, required this.outputLength})
      : super.constructor();

  @override
  Future<SecretKeyData> deriveKey({
    required SecretKey secretKey,
    List<int> nonce = const <int>[],
    List<int> info = const <int>[],
  }) async {
    // Calculate a pseudorandom key
    final secretKeyBytes = await secretKey.extractBytes();
    final nonceAsSecretKey = SecretKey(nonce);
    final prkMac = await hmac.calculateMac(
      secretKeyBytes,
      secretKey: nonceAsSecretKey,
      nonce: nonce,
    );

    final prk = SecretKey(prkMac.bytes);

    // T(0)
    var bytes = const <int>[];

    // T(1), T(2), ...
    final hashLength = hmac.hashAlgorithm.hashLengthInBytes;
    final n = outputLength ~/ hashLength;
    final result = Uint8List(outputLength);
    for (var i = 0; i <= n; i++) {
      final sink = await hmac.newMacSink(secretKey: prk);
      sink.add(bytes);
      if (info.isNotEmpty) {
        sink.add(info);
      }
      final added = <int>[0xFF & (1 + i)];
      sink.add(added);
      sink.close();
      final mac = await sink.mac();
      bytes = mac.bytes;
      final offset = i * hashLength;
      if (offset + bytes.length <= result.length) {
        result.setAll(offset, bytes);
      } else {
        result.setAll(offset, bytes.take(result.length - offset));
      }
    }
    return SecretKeyData(result);
  }
}
