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

import 'dart:async';
import 'dart:typed_data';

import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:meta/meta.dart';

abstract class DartMacAlgorithm extends MacAlgorithm {
  /// Computes a MAC synchronously (unlike [calculateMac]).
  Mac calculateMacSync(
    List<int> cipherText, {
    required SecretKeyData secretKeyData,
    required List<int> nonce,
    List<int> aad = const <int>[],
  });

  /// Returns [DartMacSinkMixin], which can be used synchronously.
  DartMacSinkMixin newMacSinkSync({
    required SecretKeyData secretKeyData,
    List<int> nonce = const <int>[],
    List<int> aad = const <int>[],
  });
}

/// A mixin for pure Dart implementations of [MacAlgorithm].
mixin DartMacAlgorithmMixin implements DartMacAlgorithm {
  @protected
  void afterData() {}

  @protected
  void beforeData({
    required SecretKeyData secretKey,
    required List<int> nonce,
    List<int> aad = const [],
  }) {}

  @override
  Future<Mac> calculateMac(
    List<int> bytes, {
    required SecretKey secretKey,
    List<int> nonce = const <int>[],
    List<int> aad = const <int>[],
  }) async {
    final sink = await newMacSink(
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
    );
    sink.addSlice(bytes, 0, bytes.length, true);
    return await sink.mac();
  }

  @override
  Mac calculateMacSync(
    List<int> bytes, {
    // TODO: A breaking change: Rename parameter as `secretKey` for consistency?
    required SecretKeyData secretKeyData,
    required List<int> nonce,
    List<int> aad = const <int>[],
  }) {
    final sink = newMacSinkSync(
      secretKeyData: secretKeyData,
      nonce: nonce,
      aad: aad,
    );
    sink.addSlice(bytes, 0, bytes.length, true);
    return sink.macSync();
  }

  @override
  Future<DartMacSinkMixin> newMacSink({
    required SecretKey secretKey,
    List<int> nonce = const <int>[],
    List<int> aad = const <int>[],
  }) async {
    final secretKeyData = await secretKey.extract();
    return newMacSinkSync(
      secretKeyData: secretKeyData,
      nonce: nonce,
      aad: aad,
    );
  }

  @override
  DartMacSinkMixin newMacSinkSync({
    // TODO: A breaking change: Rename parameter as `secretKey` for consistency?
    required SecretKeyData secretKeyData,
    List<int> nonce = const <int>[],
    List<int> aad = const <int>[],
  });
}

/// A mixin for pure Dart implementations of [MacSink]
mixin DartMacSinkMixin implements MacSink {
  /// Unsafe view at the current MAC bytes.
  ///
  /// You must copy the bytes if you want to keep them.
  Uint8List get macBytes;

  /// Re-initializes the sink.
  void initializeSync({
    required SecretKeyData secretKey,
    required List<int> nonce,
    List<int> aad = const [],
  });

  @override
  Future<Mac> mac() {
    final mac = macSync();
    return Future<Mac>.value(mac);
  }

  /// Computes the MAC synchronously.
  Mac macSync() {
    if (!isClosed) {
      throw StateError('Sink is not closed');
    }
    return Mac(Uint8List.fromList(macBytes));
  }
}
