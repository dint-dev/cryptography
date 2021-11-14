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
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

/// A Message Authentication Code (MAC) algorithm.
///
/// ## Available algorithms
///   * [Hmac]
///   * [MacAlgorithm.empty]
///   * [Poly1305]
abstract class MacAlgorithm {
  /// MAC algorithm that always returns [Mac.empty].
  static const MacAlgorithm empty = _EmptyMacAlgorithm();

  const MacAlgorithm();

  /// Number of bytes in the message authentication code.
  int get macLength;

  /// Whether the algorithm supports Associated Authenticated Data (AAD).
  bool get supportsAad => false;

  /// Calculates message authentication code.
  ///
  /// The parameter `secretKey` must be non-empty.
  ///
  /// The parameter `nonce` is optional and rarely required by MAC algorithms.
  /// The default value is [const <int>[]].
  ///
  /// The parameter `aad` is Associated Authenticated Data (AAD). It can be
  /// empty. If it's non-empty and the algorithm does not support AAD, the
  /// the method throws [ArgumentError].
  Future<Mac> calculateMac(
    List<int> bytes, {
    required SecretKey secretKey,
    List<int> nonce = const <int>[],
    List<int> aad = const <int>[],
  });

  /// Constructs a sink for calculating a [Mac].
  ///
  /// The parameter `secretKey` must be non-empty.
  ///
  /// The parameter `nonce` can be [const <int>[]].
  ///
  /// The parameter `aad` is Associated Authenticated Data (AAD). It can be
  /// empty. If it's non-empty and the algorithm does not support AAD, the
  /// the method throws [ArgumentError].
  ///
  /// ## Example
  /// ```
  /// import 'package:cryptography/cryptography.dart';
  ///
  /// void main() {
  ///   final secretKey = SecretKey([1,2,3]);
  ///
  ///   // Create a sink
  ///   final sink = await Hmac.sha256().newMacSink(
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
  ///   final mac = await sink.mac();
  ///
  ///   print('MAC: ${mac.bytes');
  /// }
  /// ```
  Future<MacSink> newMacSink({
    required SecretKey secretKey,
    List<int> nonce = const <int>[],
    List<int> aad = const <int>[],
  }) async {
    final secretKeyBytes = await secretKey.extractBytes();
    if (secretKeyBytes.isEmpty) {
      throw ArgumentError.value(
        secretKey,
        'secretKey',
        'SecretKey bytes must be non-empty',
      );
    }
    if (aad.isNotEmpty && !supportsAad) {
      throw ArgumentError.value(
        aad,
        'aad',
        'AAD is not supported',
      );
    }
    return _MacSink(
      this,
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
    );
  }

  /// {@nodoc}
  @Deprecated('Use newMacSink()')
  Future<MacSink> newSink({
    required SecretKey secretKey,
    List<int> nonce = const <int>[],
    List<int> aad = const <int>[],
  }) {
    return newMacSink(
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
    );
  }
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
  @override
  void add(List<int> chunk) {
    addSlice(chunk, 0, chunk.length, false);
  }

  /// Calculates current MAC.
  Future<Mac> mac();
}

class _EmptyMacAlgorithm extends MacAlgorithm {
  const _EmptyMacAlgorithm();

  @override
  int get macLength => 0;

  @override
  Future<Mac> calculateMac(
    List<int> input, {
    required SecretKey secretKey,
    List<int> nonce = const <int>[],
    List<int> aad = const <int>[],
  }) {
    return Future<Mac>.value(Mac.empty);
  }

  @override
  String toString() => 'MacAlgorithm.empty';
}

class _MacSink extends MacSink {
  final MacAlgorithm macAlgorithm;
  final SecretKey secretKey;
  final List<int> nonce;
  final List<int> aad;
  final BytesBuilder _input = BytesBuilder();
  Future<Mac>? _macFuture;

  _MacSink(
    this.macAlgorithm, {
    required this.secretKey,
    required this.nonce,
    required this.aad,
  });

  @override
  void addSlice(List<int> chunk, int start, int end, bool isLast) {
    if (_macFuture != null) {
      throw StateError('Sink is closed');
    }
    if (start != 0 || end != chunk.length) {
      chunk = chunk.sublist(start, end);
    }
    _input.add(chunk);
  }

  @override
  void close() {
    _macFuture ??= macAlgorithm.calculateMac(
      _input.toBytes(),
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
    );
  }

  @override
  Future<Mac> mac() {
    final macFuture = _macFuture;
    if (macFuture == null) {
      throw StateError('Sink is not closed');
    }
    return macFuture;
  }
}
