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

import 'package:collection/collection.dart';

/// Constant-time comparison of bytes.
///
/// The comparison takes a different time than normally only when:
///   * Either argument is null
///   * Lengths are non-equal
///
/// The implementation of [hash] produces a 16-bit hash by using XOR.
class ConstantTimeBytesEquality implements Equality<List<int>> {
  const ConstantTimeBytesEquality();

  @override
  int hash(List<int> e) {
    var h = 0;
    for (var i = 0; i < e.length; i++) {
      final b = e[i];
      h ^= (b << (i % 16)) ^ (b >> (16 - (i % 16)));
    }
    return h;
  }

  @override
  bool isValidKey(Object o) {
    return o is List<int>;
  }

  @override
  bool equals(List<int> left, List<int> right) {
    if (left == null || right == null || left.length != right.length) {
      return false;
    }
    var result = 0;
    for (var i = 0; i < left.length; i++) {
      result |= (left[i] ^ right[i]);
    }
    return result == 0;
  }
}
