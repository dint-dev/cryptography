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

import 'dart:typed_data';

/// Interpret bytes a big endian integer and add an [int].
void bytesAsBigEndianAddInt(List<int> list, int n) {
  if (n < 0) {
    throw ArgumentError.value(n);
  }
  for (var i = list.length - 1; n != 0 && i >= 0; i--) {
    final newByte = list[i] + n;
    list[i] = 0xFF & newByte;
    n = newByte >> 8;
  }
}

Uint8List bytesToUint8ListWithLength(List<int> bytes, int length) {
  if (length == null || length == bytes.length) {
    return bytes is Uint8List ? bytes : Uint8List.fromList(bytes);
  }
  if (length < bytes.length) {
    return bytes is Uint8List
        ? Uint8List.view(bytes.buffer, bytes.offsetInBytes, length)
        : Uint8List.fromList(bytes.sublist(0, length));
  }
  final newBytes = Uint8List(length);
  newBytes.setAll(0, bytes);
  return newBytes;
}
