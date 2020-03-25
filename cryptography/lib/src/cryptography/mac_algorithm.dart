// Copyright 2019 Gohilla Ltd (https://gohilla.com).
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

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/utils.dart';
import 'package:meta/meta.dart';

/// Superclass for message authentication code algorithms.
///
/// Examples:
///   * [Hmac]
///   * [poly1305]
abstract class MacAlgorithm {
  const MacAlgorithm();

  Future<Mac> calculateMac(List<int> input, {@required SecretKey secretKey}) {
    return Future<Mac>.value(calculateMacSync(
      input,
      secretKey: secretKey,
    ));
  }

  Mac calculateMacSync(List<int> input, {@required SecretKey secretKey}) {
    ArgumentError.checkNotNull(input);
    ArgumentError.checkNotNull(secretKey);
    final sink = newSink(secretKey: secretKey);
    sink.addSlice(input, 0, input.length, true);
    return sink.closeSync();
  }

  MacSink newSink({@required SecretKey secretKey});
}

/// Superclass for message authentication code builders.
abstract class MacSink implements ByteConversionSink {
  @override
  void add(List<int> chunk) {
    addSlice(chunk, 0, chunk.length, false);
  }

  @override
  Future<Mac> close() {
    return Future<Mac>(() => closeSync());
  }

  Mac closeSync();
}

/// A Message Authentication Code (MAC) calculated by [MacAlgorithm].
class Mac {
  final List<int> bytes;

  const Mac(this.bytes) : assert(bytes != null);

  @override
  int get hashCode => constantTimeBytesEquality.hash(bytes);

  @override
  bool operator ==(other) =>
      other is Mac && constantTimeBytesEquality.equals(other.bytes, bytes);

  @override
  String toString() => hexFromBytes(bytes);
}
