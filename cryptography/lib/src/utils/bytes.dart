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

/// Interprets the bytes a big endian integer and increments them by [int].
///
/// ## Example
/// ```
/// final bytes = [0,2,255];
/// bytesIncrementBigEndian(bytes, 5);
/// // bytes become [0,3,4]
/// ```
void bytesIncrementBigEndian(Uint8List bytes, int n) {
  if (n < 0) {
    throw ArgumentError.value(n, 'n');
  }
  // For each byte from the beginning
  for (var i = bytes.length - 1; n != 0 && i >= 0; i--) {
    final newByte = bytes[i] + n;
    bytes[i] = newByte % 0x100;

    // Carry
    n = newByte ~/ 0x100;
  }
}

Uint8List bytesToUint8ListWithLength(List<int> bytes, int length) {
  if (length == bytes.length) {
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
