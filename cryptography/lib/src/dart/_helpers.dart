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

import 'package:crypto/crypto.dart' as other;
import 'package:meta/meta.dart';

import '../../cryptography_plus.dart';
import '../../dart.dart';

/// Throws an error if the system is not little-endian.
void checkSystemIsLittleEndian() {
  if (Endian.host != Endian.little) {
    throw UnimplementedError('The platform should be little-endian.');
  }
}

/// A helper for using "package:crypto" hash algorithms.
class PackageCryptoDigestCaptureSink implements Sink<other.Digest> {
  Hash? _result;

  PackageCryptoDigestCaptureSink();

  @override
  void add(other.Digest data) {
    assert(_result == null);
    final hash = Hash(data.bytes);
    _result = hash;
  }

  @override
  void close() {
    assert(_result != null);
  }
}

/// A helper for using "package:crypto" hash algorithms.
mixin PackageCryptoHashMixin implements DartHashAlgorithmMixin, HashAlgorithm {
  @override
  int get blockLengthInBytes => impl.blockSize;

  @internal
  @protected
  other.Hash get impl;

  @override
  Future<Hash> hash(List<int> input) {
    final digest = impl.convert(input);
    return Future<Hash>.value(Hash(digest.bytes));
  }

  @override
  Hash hashSync(List<int> data) {
    final digest = impl.convert(data);
    return Hash(digest.bytes);
  }

  @override
  DartHashSink newHashSink() {
    final captureSink = PackageCryptoDigestCaptureSink();
    final implSink = impl.startChunkedConversion(captureSink);
    return PackageCryptoHashSink(
      Uint8List(hashLengthInBytes),
      impl,
      implSink,
      captureSink,
    );
  }
}

/// A helper for using "package:crypto" hash algorithms.
class PackageCryptoHashSink extends DartHashSink {
  final other.Hash hashAlgorithm;
  ByteConversionSink _sink;
  final PackageCryptoDigestCaptureSink _captureSink;
  int _length = 0;
  bool _isClosed = false;

  @override
  final Uint8List hashBytes;

  PackageCryptoHashSink(
      this.hashBytes, this.hashAlgorithm, this._sink, this._captureSink);

  @override
  bool get isClosed => _isClosed;

  @override
  int get length => _length;

  @override
  void add(List<int> chunk) {
    if (isClosed) {
      throw StateError('Already closed');
    }
    _length += chunk.length;
    _sink.add(chunk);
  }

  @override
  void addSlice(List<int> chunk, int start, int end, bool isLast) {
    if (isClosed) {
      throw StateError('Already closed');
    }
    RangeError.checkValidRange(start, end, chunk.length);
    _length += end - start;
    _sink.addSlice(chunk, start, end, isLast);
    if (isLast) {
      close();
    }
  }

  @override
  void close() {
    if (_isClosed) {
      return;
    }
    _isClosed = true;
    _sink.close();
    hashBytes.setAll(0, _captureSink._result!.bytes);
  }

  @override
  void reset() {
    _captureSink._result = null;
    _sink = hashAlgorithm.startChunkedConversion(_captureSink);
    _isClosed = false;
    _length = 0;
  }
}
