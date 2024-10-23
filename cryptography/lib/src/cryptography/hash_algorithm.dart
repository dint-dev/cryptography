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

import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:cryptography_plus/dart.dart';

/// A hash algorithm that produces a [Hash].
///
/// ## Available algorithms
///   * [Blake2b]
///   * [Blake2s]
///   * [Sha1]
///   * [Sha224] (SHA2-224)
///   * [Sha256] (SHA2-256)
///   * [Sha384] (SHA2-384)
///   * [Sha512] (SHA2-512)
///
/// ## Example: simple usage
/// ```
/// import 'package:cryptography_plus/cryptography_plus.dart';
///
/// void main() async {
///   final algorithm = Sha256();
///   final hash = await algorithm.hash([1,2,3]);
///   print('Hash: ${hash.bytes}');
/// }
/// ```
///
/// ## Example: hashing many chunks
/// ```
/// import 'package:cryptography_plus/cryptography_plus.dart';
///
/// void main() async {
///   // Create a sink
///   final algorithm = Sha256();
///   final sink = algorithm.newHashSink();
///
///   // Add all parts
///   sink.add(<int>[1,2,3]);
///   sink.add(<int>[4,5]);
///
///   // Calculate hash
///   sink.close();
///   final hash = await sink.hash();
///
///   print('Hash: ${hash.bytes}');
/// }
/// ```
abstract class HashAlgorithm {
  const HashAlgorithm();

  /// The internal block size in bytes. This information is required by some
  /// algorithms such as [Hmac].
  int get blockLengthInBytes;

  @override
  int get hashCode;

  /// Digest size in bytes.
  int get hashLengthInBytes;

  @override
  bool operator ==(other);

  /// Calculates hash for the argument.
  Future<Hash> hash(List<int> input);

  /// Constructs a sink for hashing chunks.
  ///
  /// ## Example
  /// An example with [Sha256]:
  /// ```
  /// import 'package:cryptography_plus/cryptography_plus.dart';
  ///
  /// void main() async {
  ///   // Create a sink
  ///   final algorithm = Sha256();
  ///   final sink = algorithm.newHashSink();
  ///
  ///   // Add all parts
  ///   sink.add(<int>[1,2,3]);
  ///   sink.add(<int>[4,5]);
  ///
  ///   // Calculate hash
  ///   sink.close();
  ///   final hash = await sink.hash();
  ///
  ///   print('Hash: ${hash.bytes}');
  /// }
  /// ```
  HashSink newHashSink() => _HashSink(this);

  @override
  String toString() => '$runtimeType()';

  /// For synchronous computations, returns a pure Dart implementation of the
  /// hash algorithm.
  DartHashAlgorithm toSync();
}

/// A sink for calculating [Hash] for long sequences.
///
/// ## Example
/// An example with [Sha256]:
/// ```
/// import 'package:cryptography_plus/cryptography_plus.dart';
///
/// void main() async {
///   // Create a sink
///   final algorithm = Sha256();
///   final sink = algorithm.newHashSink();
///
///   // Add all parts
///   sink.add(<int>[1,2,3]);
///   sink.add(<int>[4,5]);
///
///   // Calculate hash
///   sink.close();
///   final hash = await sink.hash();
///
///   print('Hash: ${hash.bytes}');
/// }
/// ```
abstract class HashSink extends ByteConversionSink {
  @override
  void add(List<int> chunk) {
    addSlice(chunk, 0, chunk.length, false);
  }

  /// Result after calling `close()`.
  Future<Hash> hash();
}

class _HashSink extends HashSink {
  final HashAlgorithm hashAlgorithm;
  final _bytesBuilder = BytesBuilder();
  var _isClosed = false;

  _HashSink(this.hashAlgorithm);

  @override
  void addSlice(List<int> chunk, int start, int end, bool isLast) {
    if (_isClosed) {
      throw StateError('Sink is closed');
    }
    if (start != 0 || end != chunk.length) {
      chunk = chunk.sublist(start, end);
    }
    _bytesBuilder.add(chunk);
    if (isLast) {
      close();
    }
  }

  @override
  void close() {
    _isClosed = true;
  }

  @override
  Future<Hash> hash() async {
    if (!_isClosed) {
      throw StateError('Sink is not closed');
    }
    return hashAlgorithm.hash(_bytesBuilder.toBytes());
  }

  void reset() {
    _bytesBuilder.clear();
    _isClosed = false;
  }
}
