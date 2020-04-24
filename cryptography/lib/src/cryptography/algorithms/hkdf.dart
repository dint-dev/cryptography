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
import 'package:meta/meta.dart';

/// HKDF key derivation algorithm ([RFC 5869](https://tools.ietf.org/html/rfc5869)).
///
/// An example:
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// void main() async {
///   final hkdf = Hkdf(Hmac(Sha256));
///   final input = SecretKey([1,2,3]);
///   final output = await hkdf.deriveKey(input, outputLength: 32);
/// }
/// ```
class Hkdf {
  /// HMAC used by this HKDF instance.
  final Hmac hmac;

  const Hkdf(this.hmac);

  /// Generates a secret key of the specified length.
  Future<SecretKey> deriveKey(
    SecretKey input, {
    @required int outputLength,
    Nonce nonce,
    List<int> info,
  }) async {
    final hashLength = hmac.hashAlgorithm.hashLengthInBytes;
    final inputBytes = await input.extract();
    final nonceBytes = nonce == null ? Uint8List(hashLength) : nonce.bytes;

    // Calculate a pseudorandom key
    final prkMac = await hmac.calculateMac(
      inputBytes,
      secretKey: SecretKey(nonceBytes),
    );
    final prk = SecretKey(prkMac.bytes);

    // T(0)
    var bytes = const <int>[];

    // T(1), T(2), ...
    final n = outputLength ~/ hashLength;
    final result = Uint8List(outputLength);
    for (var i = 0; i <= n; i++) {
      final sink = hmac.newSink(secretKey: prk);
      sink.add(bytes);
      if (info != null) {
        sink.add(info);
      }
      final added = <int>[0xFF & (1 + i)];
      sink.add(added);
      sink.close();
      bytes = sink.mac.bytes;
      final offset = i * hashLength;
      if (offset + bytes.length <= result.length) {
        result.setAll(offset, bytes);
      } else {
        result.setAll(offset, bytes.take(result.length - offset));
      }
    }
    return SecretKey(result);
  }
}
