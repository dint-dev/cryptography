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

/// HMAC ("hash-based message authentication code").
///
/// An example:
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// void main() {
///   final hmac = const Hmac(sha256);
///   final mac = hmac.calculateMac([1,2,3], secretKey:SecretKey([1,2,3]);
///   sink.add(<int>[1,2,3]);
///   final hash = sink.close();
/// }
/// ```
class Hmac extends MacAlgorithm {
  final HashAlgorithm hashAlgorithm;

  const Hmac(this.hashAlgorithm);

  @override
  Future<Mac> calculateMac(List<int> input, {SecretKey secretKey}) async {
    final hashAlgorithm = this.hashAlgorithm;
    final blockLength = hashAlgorithm.hashLengthInBytes;
    final secretBytes = await _secretKeyToBlock(secretKey, blockLength);
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
    final innerHash = await innerHashBuilder.close();
    final outerHashBuilder = hashAlgorithm.newSink();
    outerHashBuilder.add(outerPad);
    outerHashBuilder.add(innerHash.bytes);
    final outerHash = await outerHashBuilder.close();
    return Mac(outerHash.bytes);
  }

  Future<Uint8List> _secretKeyToBlock(
      SecretKey secretKey, int blockLength) async {
    final data = secretKey.bytes;
    if (data == null) {
      throw ArgumentError.value(secretKey, 'secretKey');
    }
    if (data.length > blockLength) {
      final hash = await hashAlgorithm.hash(data);
      return hash.bytes;
    }
    if (data.length < blockLength) {
      final result = Uint8List(blockLength);
      result.setAll(0, data);
      return result;
    }
    return data;
  }
}
