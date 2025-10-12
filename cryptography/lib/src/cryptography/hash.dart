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
import 'package:cryptography_plus/helpers.dart';
import 'package:meta/meta.dart';

/// A digest calculated with some [HashAlgorithm].
///
/// Two instances of this class are equal if the bytes are equal.
///
/// Note that [toString()] exposes the bytes.
@sealed
class Hash {
  /// Bytes of the hash.
  final List<int> bytes;

  @literal
  const Hash(this.bytes);

  @override
  int get hashCode => constantTimeBytesEquality.hash(bytes);

  @override
  bool operator ==(other) =>
      other is Hash && constantTimeBytesEquality.equals(bytes, other.bytes);

  @override
  String toString() => 'Hash([${bytes.join(',')}])';
}
