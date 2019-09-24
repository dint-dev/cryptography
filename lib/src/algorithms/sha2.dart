// Copyright 2019 Gohilla (opensource@gohilla.com).
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

import 'dart:typed_data';

import 'package:crypto/crypto.dart' as impl;
import 'package:crypto/src/digest_sink.dart' as impl;
import 'package:cryptography/cryptography.dart';

/// Implements SHA224 (224-bit SHA-2).
const HashAlgorithm sha224 = _Sha224();

/// Implements SHA256 (256-bit SHA-2).
const HashAlgorithm sha256 = _Sha256();

/// Implements SHA385 (384-bit SHA-2).
const HashAlgorithm sha384 = _Sha384();

/// Implements SHA512 (512-bit SHA-2).
const HashAlgorithm sha512 = _Sha512();

class _Sha224 extends HashAlgorithm {
  const _Sha224();

  @override
  int get blockLength => 32;

  @override
  HashSink newSink() {
    return _PackageCryptoHashSink(impl.sha224);
  }
}

class _Sha256 extends HashAlgorithm {
  const _Sha256();

  @override
  int get blockLength => 32;

  @override
  HashSink newSink() {
    return _PackageCryptoHashSink(impl.sha256);
  }
}

class _Sha384 extends HashAlgorithm {
  const _Sha384();

  @override
  int get blockLength => 64;

  @override
  HashSink newSink() {
    return _PackageCryptoHashSink(impl.sha384);
  }
}

class _Sha512 extends HashAlgorithm {
  const _Sha512();

  @override
  int get blockLength => 64;

  @override
  HashSink newSink() {
    return _PackageCryptoHashSink(impl.sha512);
  }
}

class _PackageCryptoHashSink extends HashSink {
  final _DigestSink _digestSink;
  Sink<List<int>> _sink;

  factory _PackageCryptoHashSink(impl.Hash hash) {
    final digestSink = _DigestSink();
    final sink = hash.startChunkedConversion(digestSink);
    return _PackageCryptoHashSink._(digestSink, sink);
  }

  _PackageCryptoHashSink._(this._digestSink, this._sink);

  @override
  void add(List<int> data) {
    _sink.add(data);
  }

  @override
  Hash close() {
    _sink.close();
    return Hash(_digestSink._digest);
  }
}

class _DigestSink implements Sink<impl.Digest> {
  Uint8List _digest;

  @override
  void add(impl.Digest data) {
    _digest = data.bytes;
  }

  @override
  void close() {}
}
