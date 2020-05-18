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
import 'package:meta/meta.dart';

/// A Message Authentication Code (MAC) algorithm.
///
/// ## Algorithms
///   * [Hmac]
///   * [poly1305]
/// ```
abstract class MacAlgorithm {
  const MacAlgorithm();

  @deprecated
  int get macLengthInBytes => macLength;

  /// Number of bytes in the message authentication code.
  int get macLength;

  /// A descriptive algorithm name for debugging purposes.
  ///
  /// Examples:
  ///   * "Hmac(sha256)"
  ///   * "poly1305"
  String get name;

  /// Calculates message authentication code.
  Future<Mac> calculateMac(
    List<int> input, {
    @required SecretKey secretKey,
  }) async {
    return calculateMacSync(
      input,
      secretKey: secretKey,
    );
  }

  /// Calculates message authentication code synchronously.
  ///
  /// This method is synchronous and may have lower performance than
  /// asynchronous [calculateMac] because this method can't take advantage of
  /// asynchronous platform API such as _Web Cryptography API_.
  Mac calculateMacSync(
    List<int> data, {
    @required SecretKey secretKey,
  }) {
    ArgumentError.checkNotNull(data);
    ArgumentError.checkNotNull(secretKey);
    final sink = newSink(secretKey: secretKey);
    sink.addSlice(data, 0, data.length, true);
    final mac = sink.mac;
    assert(mac != null);
    return mac;
  }

  /// Constructs a sink for calculating a [Mac].
  ///
  /// ## Example
  /// ```
  /// import 'package:cryptography/cryptography.dart';
  ///
  /// void main() {
  ///   final secretKey = SecretKey([1,2,3]);
  ///
  ///   // Create a sink
  ///   final sink = Hmac(sha256).newSink(
  ///     secretKey: secretKey,
  ///   );
  ///
  ///   // Add chunks of data
  ///   sink.add([4,5,6]);
  ///   sink.add([7,8]);
  ///
  ///   // Close
  ///   sink.close();
  ///
  ///   // We now have a MAC
  ///   final mac = sink.mac;
  ///
  ///   print('MAC: ${mac.bytes');
  /// }
  /// ```
  MacSink newSink({@required SecretKey secretKey});
}

/// A sink for calculating a [Mac].
///
/// ## Example
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// void main() {
///   final secretKey = SecretKey([1,2,3]);
///
///   // Create a sink
///   final sink = Hmac(sha256).newSink(
///     secretKey: secretKey,
///   );
///
///   // Add chunks of data
///   sink.add([4,5,6]);
///   sink.add([7,8]);
///
///   // Close
///   sink.close();
///
///   // We now have a MAC
///   final mac = sink.mac;
///
///   print('MAC: ${mac.bytes');
/// }
/// ```
abstract class MacSink extends ByteConversionSink {
  /// Result after calling `close()`. Null if [close] has not been called.
  Mac get mac;

  @override
  void add(List<int> chunk) {
    ArgumentError.checkNotNull(chunk);
    addSlice(chunk, 0, chunk.length, false);
  }
}
