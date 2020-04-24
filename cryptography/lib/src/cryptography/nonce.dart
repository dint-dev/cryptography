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

/// A nonce. A nonce is sometimes called Initialization Vector (IV) or salt.
///
/// ```
/// // Generate a random 512 bit nonce
/// final nonce = Nonce.randomBytes(64);
/// ```
class Nonce {
  static final _random = Random.secure();

  /// Bytes of the nonce.
  final List<int> bytes;

  Nonce(this.bytes) {
    ArgumentError.checkNotNull(bytes, 'bytes');
  }

  /// Generates N random bytes.
  ///
  /// You can optionally give a random number generator that's used.
  factory Nonce.randomBytes(int length, {Random random}) {
    random ??= _random;
    final data = Uint8List(length);
    for (var i = 0; i < data.length; i++) {
      data[i] = random.nextInt(256);
    }
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

  /// Returns a nonce incremented by 1.
  Nonce increment([int n = 1]) {
    if (n < 0 || n > 0xFF) {
      throw ArgumentError.value(n, 'n');
    }
    final result = Uint8List.fromList(bytes);
    for (var i = result.length - 1; i >= 0; i--) {
      final newByte = result[i] + n;
      result[i] = 0xFF & newByte;

      // No carry?
      if (newByte <= 0xFF) {
        break;
      }

      // Carry (1)
      n = 1;
    }
    return Nonce(result);
  }

  @override
  String toString() {
    return "Nonce(['${bytes.join(', ')}'])";
  }
}
