// Copyright 2019 Gohilla (opensource@gohilla.com).
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

import 'package:cryptography/math.dart';

/// A secret sequence of bits.
class SecretKey {
  static final _random = Random.secure();

  /// Bytes of the key. May be null.
  final List<int> bytes;

  /// Constructs a secret key on the heap.
  SecretKey(this.bytes) {
    ArgumentError.checkNotNull(bytes, "bytes");
  }

  factory SecretKey.randomBytes(int length, {Random random}) {
    random ??= SecretKey._random;
    final data = Uint8List(length);
    for (var i = 0; i < data.length; i++) {
      data[i] = random.nextInt(256);
    }
    return SecretKey(data);
  }

  @override
  int get hashCode {
    /// Exposes maximum 16 bits of the key.
    var h = 0;
    final data = this.bytes;
    for (var i = 0; i < data.length; i++) {
      final b = data[i];
      h ^= (b << (i % 16)) ^ (b >> (16 - (i % 16)));
    }
    return h;
  }

  @override
  bool operator ==(other) {
    return other is SecretKey &&
        const ConstantTimeBytesEquality().equals(bytes, other.bytes);
  }

  /// Increments the 96-bit Chacha20 nonce.
  SecretKey increment() {
    final bytes = this.bytes;
    final result = Uint8List.fromList(bytes);
    for (var i = result.length - 1; i >= 0; i--) {
      result[i]++;
      if (result[i] != 0) {
        break;
      }
    }
    return SecretKey(result);
  }

  String toHex() {
    return hexFromBytes(bytes);
  }

  @override
  String toString() => hexFromBytes(bytes);
}
