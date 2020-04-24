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

import 'dart:math' show Random;
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/utils.dart';

/// Private key part of [KeyPair].
///
/// Equality operator for private keys uses [constantTimeBytesEquality].
///
/// An example of obtaining a private key:
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// void main() {
///   final keyPair = x25519.newKeyPairSync();
///   final privateKey = keyPair.privateKey;
/// }
/// ```
abstract class PrivateKey {
  static final _random = Random.secure();

  /// Constructs a private key with the bytes.
  const factory PrivateKey(List<int> bytes) = _PrivateKey;

  /// Constructor for subclasses.
  const PrivateKey.constructor();

  /// Generates N random bytes.
  ///
  /// You can optionally give a random number generator that's used.
  factory PrivateKey.randomBytes(int length, {Random random}) {
    random ??= _random;
    final data = Uint8List(length);
    for (var i = 0; i < length; i++) {
      data[i] = random.nextInt(256);
    }
    return PrivateKey(data);
  }

  /// Extracts the bytes.
  ///
  /// Throws [UnsupportedError] if extraction is not supported.
  Future<List<int>> extract() => Future<List<int>>(() => extractSync());

  /// Extracts the bytes synchronously.
  /// Throws [UnsupportedError] if extraction is not supported.
  List<int> extractSync();
}

class _PrivateKey extends PrivateKey {
  /// Bytes of the key. May be null.
  final List<int> _bytes;

  const _PrivateKey(this._bytes)
      : assert(_bytes != null),
        super.constructor();

  @override
  int get hashCode {
    var h = 0;
    final bytes = _bytes;
    for (var i = 0; i < bytes.length; i++) {
      final b = bytes[i];

      // Exposes at most 31 bits
      h = 0x7FFFFFFF & ((31 * h) ^ b);
    }

    // For short values, expose max 15 bits.
    if (bytes.length < 8) {
      h = 0x7FFF & h;
    }

    return h;
  }

  @override
  bool operator ==(other) {
    return other is _PrivateKey &&
        constantTimeBytesEquality.equals(_bytes, other._bytes);
  }

  @override
  List<int> extractSync() => _bytes;

  @override
  String toString() => 'PrivateKey(...)';
}
