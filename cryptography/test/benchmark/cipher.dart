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

import 'dart:typed_data';

import 'package:benchmark_harness/benchmark_harness.dart';
import 'package:cryptography/cryptography.dart';

const million = 1000000;

void main() {
  print('Benchmarks:');
  print('');
  Chacha20StreamBenchmark(chacha20, million).report();
  Chacha20StreamBenchmark(chacha20Poly1305Aead, million).report();

  Chacha20StreamBenchmark(aesCbc, million).report();
  Chacha20StreamBenchmark(CipherWithAppendedMac(aesCbc, Hmac(sha256)), million)
      .report();

  Chacha20StreamBenchmark(aesCtr, million).report();
  Chacha20StreamBenchmark(CipherWithAppendedMac(aesCtr, Hmac(sha256)), million)
      .report();
  print('');

  Chacha20NumerousSmallMessagesBenchmark(chacha20, million, 100).report();
  Chacha20NumerousSmallMessagesBenchmark(chacha20Poly1305Aead, million, 100)
      .report();
  Chacha20NumerousSmallMessagesBenchmark(aesCbc, million, 100).report();
  Chacha20NumerousSmallMessagesBenchmark(
          CipherWithAppendedMac(aesCbc, Hmac(sha256)), million, 100)
      .report();
  Chacha20NumerousSmallMessagesBenchmark(aesCtr, million, 100).report();
  Chacha20NumerousSmallMessagesBenchmark(
          CipherWithAppendedMac(aesCtr, Hmac(sha256)), million, 100)
      .report();
  print('');
}

class Chacha20StreamBenchmark extends BenchmarkBase {
  final Cipher cipher;
  final int totalLength;
  SecretKey secretKey;
  Nonce nonce;
  Uint8List cleartext;
  Uint8List result;

  Chacha20StreamBenchmark(this.cipher, this.totalLength)
      : super(
            '${(cipher.name + ':').padRight(20)} ${totalLength ~/ million} MB stream');

  @override
  void setup() {
    // 100 MB cleartext
    cleartext = Uint8List(totalLength);
    for (var i = 0; i < cleartext.lengthInBytes; i++) {
      cleartext[i] = 0xFF & i;
    }
    secretKey = cipher.newSecretKeySync();
    nonce = cipher.newNonce();
    result = Uint8List(cleartext.length);
  }

  @override
  void run() {
    cipher.encryptSync(
      cleartext,
      secretKey: secretKey,
      nonce: nonce,
    );
  }

  @override
  void exercise() {
    run();
  }
}

class Chacha20NumerousSmallMessagesBenchmark extends BenchmarkBase {
  final Cipher cipher;
  final int totalLength;
  final int messageLength;
  SecretKey secretKey;
  Nonce nonce;
  Uint8List cleartext;
  Uint8List result;

  Chacha20NumerousSmallMessagesBenchmark(
      this.cipher, this.totalLength, this.messageLength)
      : super(
            '${(cipher.name + ':').padRight(20)} ${totalLength ~/ million} MB in ${messageLength} byte long messages');

  @override
  void setup() {
    cleartext = Uint8List(messageLength);
    for (var i = 0; i < cleartext.lengthInBytes; i++) {
      cleartext[i] = 0xFF & i;
    }
    secretKey = cipher.newSecretKeySync();
    nonce = cipher.newNonce();
    result = Uint8List(cleartext.lengthInBytes);
  }

  @override
  void run() {
    cipher.encryptSync(
      cleartext,
      secretKey: secretKey,
      nonce: nonce,
    );
  }

  @override
  void exercise() {
    for (var i = 0; i < totalLength ~/ messageLength; i++) {
      run();
    }
  }
}
