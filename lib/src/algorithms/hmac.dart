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

import 'package:cryptography/cryptography.dart';

const Hmac hmacSha224 = Hmac(sha224);
const Hmac hmacSha256 = Hmac(sha256);
const Hmac hmacSha384 = Hmac(sha384);
const Hmac hmacSha512 = Hmac(sha512);

/// Implements HMAC.
class Hmac extends MacAlgorithm {
  final HashAlgorithm hashAlgorithm;

  const Hmac(this.hashAlgorithm);

  @override
  Mac calculateMac(Uint8List input, SecretKey secretKey) {
    final hashAlgorithm = this.hashAlgorithm;
    final blockLength = hashAlgorithm.blockLength;
    final secretBytes = _secretKeyToBlock(secretKey, blockLength);
    final innerPad = Uint8List(blockLength);
    final outerPad = Uint8List(blockLength);
    for (var i = 0; i < blockLength; i++) {
      final b = secretBytes[i];
      innerPad[i] = b ^ 0x36;
      outerPad[i] = b ^ 0x5c;
    }
    final innerHashBuilder = hashAlgorithm.newSink();
    innerHashBuilder.add(innerPad);
    innerHashBuilder.add(input);
    final innerHash = innerHashBuilder.close();
    final outerHashBuilder = hashAlgorithm.newSink();
    outerHashBuilder.add(outerPad);
    outerHashBuilder.add(innerHash.bytes);
    return Mac(outerHashBuilder.close().bytes);
  }

  Uint8List _secretKeyToBlock(SecretKey secretKey, int blockLength) {
    final data = secretKey.bytes;
    if (data == null) {
      throw ArgumentError.value(secretKey, "secretKey");
    }
    if (data.length > blockLength) {
      return hashAlgorithm.hash(data).bytes;
    }
    if (data.length < blockLength) {
      final result = Uint8List(blockLength);
      result.setAll(0, data);
      return result;
    }
    return data;
  }
}
