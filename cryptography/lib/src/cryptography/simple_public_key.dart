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

import 'package:collection/collection.dart';
import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:meta/meta.dart';

/// A [PublicKey] that is a sequence of bytes.
///
/// This is used by [Ed25519] and [X25519].
@sealed
class SimplePublicKey extends PublicKey implements Comparable<SimplePublicKey> {
  final List<int> bytes;

  @override
  final KeyPairType type;

  SimplePublicKey(this.bytes, {required this.type});

  @override
  int get hashCode => const ListEquality<int>().hash(bytes) ^ type.hashCode;

  @override
  bool operator ==(other) =>
      other is SimplePublicKey &&
      type == other.type &&
      const ListEquality<int>().equals(bytes, other.bytes);

  @override
  int compareTo(SimplePublicKey other) {
    final a = bytes;
    final b = other.bytes;
    var n = a.length <= b.length ? a.length : b.length;
    for (var i = 0; i < n; i++) {
      final x = a[i].compareTo(b[i]);
      if (x != 0) {
        return x;
      }
    }
    return a.length.compareTo(b.length);
  }

  @override
  String toString() {
    return "SimplePublicKey([${bytes.join(',')}], type: $type)";
  }
}
