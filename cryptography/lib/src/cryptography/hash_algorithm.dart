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

/// A hash algorithm that produces a [Hash].
///
/// ## Algorithms
///   * [blake2s]
///   * [sha1]
///   * [sha224] (SHA2-224)
///   * [sha256] (SHA2-256)
///   * [sha384] (SHA2-384)
///   * [sha512] (SHA2-512)
///
/// ## Example
/// We [blake2s] in this example:
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// void main() {
///   // Create a sink
///   final sink = blake2s.newSink();
///
///   // Add all parts
///   sink.add(<int>[1,2,3]);
///   sink.add(<int>[4,5]);
///
///   // Calculate hash
///   sink.close();
///   final hash = sink.hash;
///
///   print('Hash: ${hash.bytes}');
/// }
/// ```
abstract class HashAlgorithm {
  const HashAlgorithm();

  /// The internal block size in bytes. This information is required by some
  /// algorithms such as [Hmac].
  int get blockLengthInBytes;

  /// Digest size in bytes.
  int get hashLengthInBytes;

  /// A descriptive algorithm name for debugging purposes.
  ///
  /// Examples:
  ///   * "blake2s"
  ///   * "sha256"
  String get name;

  /// Calculates hash for the argument.
  Future<Hash> hash(List<int> input) async {
    return Future<Hash>.value(await hashSync(input));
  }

  /// Calculates hash for the argument synchronously.
  ///
  /// This method is synchronous and may have lower performance than
  /// asynchronous [hash] because this method can't take advantage of
  /// asynchronous platform API such as _Web Cryptography API_.
  Hash hashSync(List<int> data) {
    ArgumentError.checkNotNull(data);
    var sink = newSink();
    sink.add(data);
    sink.close();
    return sink.hash;
  }

  /// Constructs a sink for calculating a hash.
  ///
  /// ## Example
  /// An example with [sha256]:
  /// ```
  /// import 'package:cryptography/cryptography.dart';
  ///
  /// void main() {
  ///   // Create a sink
  ///   final sink = sha256.newSink();
  ///
  ///   // Add any number of chunks
  ///   sink.add([1,2,3]);
  ///   sink.add([4,5]);
  ///
  ///   // Close
  ///   sink.close();
  ///
  ///   // We have a hash
  ///   final hash = sink.hash;
  ///
  ///   print('Hash: ${hash.bytes}');
  /// }
  /// ```
  HashSink newSink();

  @override
  String toString() => name;
}

/// Enables calculation of [Hash] for inputs larger than fit in the memory.
///
/// ## Example
/// An example with [sha256]:
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// void main() {
///   // Create a sink
///   final sink = sha256.newSink();
///
///   // Add any number of chunks
///   sink.add([1,2,3]);
///   sink.add([4,5]);
///
///   // Close
///   sink.close();
///
///   // We have a hash
///   final hash = sink.hash;
///
///   print('Hash: ${hash.bytes}');
/// }
/// ```
abstract class HashSink extends ByteConversionSink {
  /// Result after calling `close()`.
  Hash get hash;

  @override
  void add(List<int> chunk) {
    ArgumentError.checkNotNull(chunk);
    addSlice(chunk, 0, chunk.length, false);
  }
}
