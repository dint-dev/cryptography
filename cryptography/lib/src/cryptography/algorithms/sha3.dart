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

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:meta/meta.dart';
import 'package:pointycastle/digests/sha3.dart' as pointycastle;

/// SHA3-224 hash function.
///
/// SHA3 family of functions is a NIST standard that is specified in
/// [FIPS 202](https://csrc.nist.gov/publications/detail/fips/202/final).
const HashAlgorithm sha3V224 = _Sha3(
  name: 'sha3V224',
  blockLength: 144,
  hashLengthInBytes: 28,
);

/// SHA3-256 hash function.
///
/// SHA3 family of functions is a NIST standard that is specified in
/// [FIPS 202](https://csrc.nist.gov/publications/detail/fips/202/final).
const HashAlgorithm sha3V256 = _Sha3(
  name: 'sha3V256',
  blockLength: 136,
  hashLengthInBytes: 32,
);

/// SHA3-384 hash function.
///
/// SHA3 family of functions is a NIST standard that is specified in
/// [FIPS 202](https://csrc.nist.gov/publications/detail/fips/202/final).
const HashAlgorithm sha3V384 = _Sha3(
  name: 'sha3V384',
  blockLength: 104,
  hashLengthInBytes: 48,
);

/// SHA3-512 hash function.
///
/// SHA3 family of functions is a NIST standard that is specified in
/// [FIPS 202](https://csrc.nist.gov/publications/detail/fips/202/final).
const HashAlgorithm sha3V512 = _Sha3(
  name: 'sha3V512',
  blockLength: 72,
  hashLengthInBytes: 64,
);

class _Sha3 extends HashAlgorithm {
  @override
  final int blockLength;

  @override
  final int hashLengthInBytes;

  @override
  final String name;

  const _Sha3({
    @required this.name,
    @required this.blockLength,
    @required this.hashLengthInBytes,
  });

  @override
  HashSink newSink() {
    return _Sha3Sink(
      pointycastle.SHA3Digest(8 * hashLengthInBytes, false),
      hashLengthInBytes,
    );
  }
}

class _Sha3Sink extends HashSink {
  final pointycastle.SHA3Digest _digest;
  final int _hashLengthInBytes;

  _Sha3Sink(this._digest, this._hashLengthInBytes);

  @override
  void addSlice(List<int> chunk, int start, int end, bool isLast) {
    _digest.update(Uint8List.fromList(chunk), start, end);
  }

  @override
  Hash closeSync() {
    final hashBytes = Uint8List(_hashLengthInBytes);
    final n = _digest.doFinal(hashBytes, 0);
    if (n != _hashLengthInBytes) {
      throw StateError('Unsupported length');
    }
    return Hash(hashBytes);
  }
}
