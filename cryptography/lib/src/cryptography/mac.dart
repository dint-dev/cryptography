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

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/utils.dart';

/// A Message Authentication Code (MAC).
///
/// A MAC can be calculated with some [MacAlgorithm].
class Mac {
  /// Bytes of the MAC.
  final List<int> bytes;

  Mac(this.bytes) {
    ArgumentError.checkNotNull(bytes);
  }

  @override
  int get hashCode => constantTimeBytesEquality.hash(bytes);

  @override
  bool operator ==(other) =>
      other is Mac && constantTimeBytesEquality.equals(other.bytes, bytes);

  @override
  String toString() => hexFromBytes(bytes);
}
