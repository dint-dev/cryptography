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

import 'package:crypto/crypto.dart' as impl;
import 'package:cryptography/cryptography.dart';
import 'package:cryptography/dart.dart';
import 'package:meta/meta.dart';

/// [Sha1] implemented by using in [package:crypto](https://pub.dev/packages/crypto)
/// (a package by Google).
class DartSha1 extends Sha1 with DartHashAlgorithmMixin, _HashMixin {
  @literal
  const DartSha1() : super.constructor();

  @override
  impl.Hash get _impl => impl.sha1;
}

/// [Sha224] implemented by using in [package:crypto](https://pub.dev/packages/crypto)
/// (a package by Google).
class DartSha224 extends Sha224 with DartHashAlgorithmMixin, _HashMixin {
  @literal
  const DartSha224() : super.constructor();

  @override
  impl.Hash get _impl => impl.sha224;
}

/// [Sha256] implemented by using in [package:crypto](https://pub.dev/packages/crypto)
/// (a package by Google).
class DartSha256 extends Sha256 with DartHashAlgorithmMixin, _HashMixin {
  @literal
  const DartSha256() : super.constructor();

  @override
  impl.Hash get _impl => impl.sha256;
}

/// [Sha385] implemented by using in [package:crypto](https://pub.dev/packages/crypto)
/// (a package by Google).
class DartSha384 extends Sha384 with DartHashAlgorithmMixin, _HashMixin {
  @literal
  const DartSha384() : super.constructor();

  @override
  impl.Hash get _impl => impl.sha384;
}

/// [Sha512] implemented by using in [package:crypto](https://pub.dev/packages/crypto)
/// (a package by Google).
class DartSha512 extends Sha512 with DartHashAlgorithmMixin, _HashMixin {
  @literal
  const DartSha512() : super.constructor();

  @override
  impl.Hash get _impl => impl.sha512;
}

mixin _HashMixin implements HashAlgorithm {
  @override
  int get blockLengthInBytes => _impl.blockSize;

  impl.Hash get _impl;

  @override
  Future<Hash> hash(List<int> input) {
    final digest = _impl.convert(input);
    final unmodifiableBytes = List<int>.unmodifiable(digest.bytes);
    return Future<Hash>.value(Hash(unmodifiableBytes));
  }

  @override
  DartHashSink newHashSink() {
    final captureSink = _ImplDigestCaptureSink();
    final implSink = _impl.startChunkedConversion(captureSink);
    return _HashSink(
      implSink,
      captureSink,
    );
  }
}

class _HashSink extends DartHashSink {
  final ByteConversionSink _sink;
  final _ImplDigestCaptureSink _captureSink;

  bool _isClosed = false;

  _HashSink(this._sink, this._captureSink);

  @override
  void add(List<int> chunk) {
    if (_isClosed) {
      throw StateError('Already closed');
    }
    _sink.add(chunk);
  }

  @override
  void addSlice(List<int> chunk, int start, int end, bool isLast) {
    if (_isClosed) {
      throw StateError('Already closed');
    }
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
  }

  @override
  Hash hashSync() {
    if (!_isClosed) {
      throw StateError('Sink is not closed');
    }
    return Hash(List<int>.unmodifiable(_captureSink._result!.bytes));
  }
}

class _ImplDigestCaptureSink extends Sink<impl.Digest> {
  Hash? _result;

  _ImplDigestCaptureSink();

  @override
  void add(impl.Digest implDigest) {
    assert(_result == null);
    final hash = Hash(List<int>.unmodifiable(implDigest.bytes));
    _result = hash;
  }

  @override
  void close() {
    assert(_result != null);
  }
}
