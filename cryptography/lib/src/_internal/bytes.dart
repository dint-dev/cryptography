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

/// Changes [Uint32List] endian unless the current system endian is the given.
void flipUint32ListEndianUnless(Uint32List list, Endian endian) {
  if (endian == Endian.host) {
    return;
  }
  final byteData =
      ByteData.view(list.buffer, list.offsetInBytes, list.lengthInBytes);
  for (var i = 0; i < list.length; i++) {
    list[i] = byteData.getUint32(i * 4, endian);
  }
}

/// Changes [Uint64List] endian unless the current system endian is the given.
void flipUint64ListEndianUnless(Uint32List list, Endian endian) {
  if (endian == Endian.host) {
    return;
  }
  final byteData =
      ByteData.view(list.buffer, list.offsetInBytes, list.lengthInBytes);
  for (var i = 0; i < list.length; i++) {
    list[i] = byteData.getUint32(i * 4, endian);
  }
}
