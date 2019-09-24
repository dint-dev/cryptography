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

import 'dart:typed_data';

/// Unpacks Uint8x32 into Uint16x16 (Int32List).
void unpack256(Int32List result, Uint8List packed) {
  final byteData = ByteData.view(packed.buffer, packed.offsetInBytes, 32);
  for (var i = 0; i < 16; i++) {
    result[i] = byteData.getUint16(2 * i, Endian.little);
  }
}

/// Packs Uint16x16 (Int32List) into Uint8x32.
void pack256(Uint8List result, Int32List unpacked) {
  final byteData = ByteData.view(result.buffer, result.offsetInBytes, 32);
  for (var i = 0; i < 16; i++) {
    byteData.setUint16(2 * i, unpacked[i], Endian.little);
  }
}
