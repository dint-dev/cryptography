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

import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/utils.dart';
import 'package:meta/meta.dart';

/// A Message Authentication Code (MAC) calculated by [MacAlgorithm].
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

/// Superclass for message authentication code algorithms.
///
/// Examples:
///   * [Hmac]
///   * [poly1305]
abstract class MacAlgorithm {
  const MacAlgorithm();

  /// Number of bytes in the message authentication code.
  int get macLengthInBytes;

  /// Asynchronously calculates message authentication code for the input.
  Future<Mac> calculateMac(List<int> input,
      {@required SecretKey secretKey}) async {
    return calculateMacSync(
      input,
      secretKey: secretKey,
    );
  }

  /// Calculates message authentication code for the input.
  Mac calculateMacSync(List<int> data, {@required SecretKey secretKey}) {
    ArgumentError.checkNotNull(data);
    ArgumentError.checkNotNull(secretKey);
    final sink = newSink(secretKey: secretKey);
    sink.addSlice(data, 0, data.length, true);
    final mac = sink.mac;
    assert(mac != null);
    return mac;
  }

  /// Returns a sink that writes Mac to t
  MacSink newSink({@required SecretKey secretKey});
}

/// Enables calculation of [Mac] for inputs larger than fit in the memory.
abstract class MacSink extends ByteConversionSink {
  /// Result after calling `close()`.
  Mac get mac;

  @override
  void add(List<int> chunk) {
    ArgumentError.checkNotNull(chunk);
    addSlice(chunk, 0, chunk.length, false);
  }
}

/// Thrown when calculated [Mac] doesn't equal the correct digest.
class MacValidationException implements Exception {
  @override
  String toString() => 'Message authentication code (MAC) is invalid';
}
