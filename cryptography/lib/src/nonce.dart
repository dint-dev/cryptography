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

import 'dart:math';
import 'dart:typed_data';

import 'package:collection/collection.dart';

import 'utils/random_bytes.dart';

/// A nonce (sometimes known as _Initialization Vector_, _IV_ or _salt_).
///
/// Usually nonces do not need to be kept secret.
///
/// You can generate random nonces with [Nonce.randomBytes].
///
/// ## Example
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// void main() {
///   // Generate a random 512 bit nonce
///   final nonce = Nonce.randomBytes(64);
///
///   print('Nonce: ${nonce.bytes}');
/// }
/// ```
class Nonce {
  /// Bytes of the nonce.
  final List<int> bytes;

  Nonce(this.bytes) {
    ArgumentError.checkNotNull(bytes, 'bytes');
  }

  /// Generates _N_ random bytes with a cryptographically secure random number
  /// generator.
  ///
  /// A description of the random number generator:
  ///   * In browsers, `window.crypto.getRandomValues() is used directly.
  ///   * In Dart, _dart:math_ [Random.secure()] is used.
  ///
  /// You can give a custom random number generator. This can be useful for
  /// deterministic tests.
  ///
  /// ```
  /// import 'package:cryptography/cryptography.dart';
  ///
  /// void main() {
  ///   // Generate random 32 bytes (= 256 bits).
  ///   final nonce = Nonce.randomBytes(32);
  ///
  ///   print('Nonce: ${nonce.bytes}');
  /// }
  /// ```
  factory Nonce.randomBytes(int length, {Random random}) {
    final data = Uint8List(length);
    fillBytesWithSecureRandomNumbers(data, random: random);
    return Nonce(data);
  }

  @override
  int get hashCode {
    return const ListEquality<int>().hash(bytes);
  }

  @override
  bool operator ==(other) {
    return other is Nonce &&
        const ListEquality<int>().equals(bytes, other.bytes);
  }

  /// Returns a nonce incremented by 1. Uses big endian byte order.
  Nonce increment([int n = 1]) {
    if (n == 0) {
      return this;
    }
    final result = Uint8List.fromList(bytes);
    loop:
    while (n != 0) {
      for (var i = result.length - 1; i >= 0; i--) {
        final newByte = result[i] + n;
        result[i] = 0xFF & newByte;

        // No carry?
        if (newByte <= 0xFF) {
          break loop;
        }

        n = newByte ~/ 0x100;
      }
    }
    return Nonce(result);
  }

  @override
  String toString() {
    return "Nonce(['${bytes.join(', ')}'])";
  }
}
