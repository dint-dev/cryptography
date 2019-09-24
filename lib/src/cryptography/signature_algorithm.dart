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

import 'package:collection/collection.dart';
import 'package:cryptography/cryptography.dart';
import 'package:cryptography/math.dart';

abstract class SignatureAlgorithm {
  String get name;

  Signature sign(List<int> input, KeyPair keyPair);
}

class Signature {
  final Uint8List bytes;
  final PublicKey publicKey;

  Signature(this.bytes, {this.publicKey});

  @override
  int get hashCode => const ListEquality<int>().hash(bytes);

  @override
  operator ==(other) =>
      other is Signature &&
      const ListEquality<int>().equals(bytes, other.bytes) &&
      publicKey == other.publicKey;

  String toHex() {
    return hexFromBytes(bytes);
  }

  @override
  String toString() => toHex();
}
