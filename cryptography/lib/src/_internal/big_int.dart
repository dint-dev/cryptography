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

final _byteMask = BigInt.from(255);

/// Converts bytes to [BigInt]. Uses little-endian byte order.
BigInt bigIntFromBytes(List<int> bytes) {
  var result = BigInt.zero;
  for (var i = bytes.length - 1; i >= 0; i--) {
    result = (result << 8) + BigInt.from(bytes[i]);
  }
  return result;
}

/// Converts [BigInt] to bytes. Uses little-endian byte order.
Uint8List bigIntToBytes(BigInt? value, List<int> result,
    [int start = 0, int? length]) {
  final original = value;
  length ??= result.length - start;
  for (var i = 0; i < length; i++) {
    result[start + i] = (_byteMask & value!).toInt();
    value >>= 8;
  }
  if (value != BigInt.zero) {
    throw ArgumentError.value(original);
  }
  return result as Uint8List;
}
