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

import 'dart:typed_data';

import 'package:cryptography_plus/cryptography_plus.dart';

import 'benchmark_helpers.dart';

Future<void> main() async {
  // ignore: constant_identifier_names
  const MB = 1000000;

  {
    const messageLength = 100;
    print('10k x 100 byte messages (total 1 MB):');

    await _Encrypt(
      Chacha20(macAlgorithm: MacAlgorithm.empty),
      MB,
      messageLength,
    ).report();
    await _Encrypt(
      Chacha20.poly1305Aead(),
      MB,
      messageLength,
    ).report();
    await _Encrypt(
      AesCbc.with256bits(macAlgorithm: MacAlgorithm.empty),
      MB,
      messageLength,
    ).report();
    await _Encrypt(
      AesCbc.with256bits(macAlgorithm: Hmac(Sha256())),
      MB,
      messageLength,
    ).report();
    await _Encrypt(
      AesCtr.with256bits(macAlgorithm: MacAlgorithm.empty),
      MB,
      messageLength,
    ).report();
    await _Encrypt(
      AesCtr.with256bits(macAlgorithm: Hmac(Sha256())),
      MB,
      messageLength,
    ).report();
    await _Encrypt(
      AesGcm.with256bits(),
      MB,
      messageLength,
    ).report();
    print('');
  }

  {
    print('1 MB messages:');

    await _Encrypt(
      Chacha20(macAlgorithm: MacAlgorithm.empty),
      MB,
    ).report();
    await _Encrypt(
      Chacha20.poly1305Aead(),
      MB,
    ).report();

    await _Encrypt(
      AesCbc.with256bits(macAlgorithm: MacAlgorithm.empty),
      MB,
    ).report();
    await _Encrypt(
      AesCbc.with256bits(macAlgorithm: Hmac(Sha256())),
      MB,
    ).report();
    await _Encrypt(
      AesCtr.with256bits(macAlgorithm: MacAlgorithm.empty),
      MB,
    ).report();
    await _Encrypt(
      AesCtr.with256bits(macAlgorithm: Hmac(Sha256())),
      MB,
    ).report();
    await _Encrypt(
      AesGcm.with256bits(),
      MB,
    ).report();
    print('');
  }
}

class _Encrypt extends SimpleBenchmark {
  final Cipher algorithm;
  final int totalLength;
  final int messageLength;
  late SecretKey secretKey;
  late List<int> nonce;
  late Uint8List cleartext;
  Uint8List? result;

  _Encrypt(this.algorithm, this.totalLength, [int? messageLength])
      : messageLength = messageLength ?? totalLength,
        super('$algorithm.encrypt()');

  @override
  Future<void> run() async {
    final futures = <Future>[];
    for (var i = 0; i < totalLength ~/ messageLength; i++) {
      futures.add(algorithm.encrypt(
        cleartext,
        secretKey: secretKey,
        nonce: nonce,
      ));
    }
    await Future.wait(futures);
  }

  @override
  void setup() async {
    cleartext = Uint8List(messageLength);
    for (var i = 0; i < cleartext.lengthInBytes; i++) {
      cleartext[i] = 0xFF & i;
    }
    secretKey = await algorithm.newSecretKey();
    nonce = algorithm.newNonce();
    result = Uint8List(cleartext.lengthInBytes);
  }
}
