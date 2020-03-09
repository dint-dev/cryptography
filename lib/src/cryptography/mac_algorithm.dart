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

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/utils.dart';
import 'package:meta/meta.dart';
import 'package:typed_data/typed_buffers.dart';

/// Superclass for message authentication code algorithms.
///
/// Examples:
///   * [Hmac]
///   * [poly1305]
abstract class MacAlgorithm {
  const MacAlgorithm();

  Future<Mac> calculateMac(List<int> input, {@required SecretKey secretKey});

  MacSink newSink({@required SecretKey secretKey}) {
    return _MacSink(this, secretKey);
  }
}

/// Superclass for message authentication code builders.
abstract class MacSink implements Sink<List<int>> {
  @override
  Future<Mac> close();
}

class _MacSink extends MacSink {
  final MacAlgorithm _algorithm;
  final SecretKey _secretKey;
  final Uint8Buffer _bytes = Uint8Buffer();

  _MacSink(this._algorithm, this._secretKey);

  @override
  void add(List<int> bytes) {
    _bytes.addAll(bytes);
  }

  @override
  Future<Mac> close() async {
    return _algorithm.calculateMac(_bytes, secretKey: _secretKey);
  }
}

/// A Message Authentication Code (MAC).
class Mac {
  final List<int> bytes;

  const Mac(this.bytes) : assert(bytes != null);

  @override
  int get hashCode => const ConstantTimeBytesEquality().hash(bytes);

  @override
  bool operator ==(other) =>
      other is Mac &&
      const ConstantTimeBytesEquality().equals(other.bytes, bytes);

  @override
  String toString() => hexFromBytes(bytes);
}
