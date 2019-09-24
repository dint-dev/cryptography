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

import 'dart:convert';

import 'package:collection/collection.dart';
import 'package:cryptography/math.dart';

/// A public key.
class PublicKey {
  final List<int> bytes;

  PublicKey(this.bytes) {
    ArgumentError.checkNotNull(bytes, "bytes");
  }

  @override
  int get hashCode {
    return const ListEquality<int>().hash(bytes);
  }

  @override
  bool operator ==(other) {
    return other is PublicKey &&
        const ListEquality<int>().equals(bytes, other.bytes);
  }

  /// Builds a Base64 string from the bytes.
  String toBase64() {
    if (bytes == null) {
      return null;
    }
    return base64Encode(bytes);
  }

  /// Builds a hexadecimal string from the bytes.
  String toHex() {
    if (bytes == null) {
      return null;
    }
    final sb = StringBuffer();
    for (var b in bytes) {
      sb.write((b ~/ 16).toRadixString(16));
      sb.write((b % 16).toRadixString(16));
    }
    return sb.toString();
  }

  @override
  String toString() {
    return "PublicKey.parseHex('${toHex()}')";
  }

  /// Parses a hex key.
  static PublicKey parseHex(String s) {
    return PublicKey(hexToBytes(s));
  }
}
