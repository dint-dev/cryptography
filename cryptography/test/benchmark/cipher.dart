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

import 'package:cryptography/cryptography.dart';

import 'benchmark_helpers.dart';

Future<void> main() async {
  const MB = 1000000;
  {
    const messageLength = 100;

    print('10k x 100b messages:');
    await _Encrypt(chacha20, MB, messageLength).report();
    await _EncryptSync(chacha20, MB, messageLength).report();
    await _Encrypt(chacha20Poly1305Aead, MB, messageLength).report();
    await _Encrypt(aesCbc, MB, messageLength).report();
    await _EncryptSync(aesCbc, MB, messageLength).report();
    await _Encrypt(
            CipherWithAppendedMac(aesCbc, Hmac(sha256)), MB, messageLength)
        .report();
    await _EncryptSync(
            CipherWithAppendedMac(aesCbc, Hmac(sha256)), MB, messageLength)
        .report();
    await _Encrypt(aesCtr, MB, messageLength).report();
    await _EncryptSync(aesCtr, MB, messageLength).report();
    await _Encrypt(
            CipherWithAppendedMac(aesCtr, Hmac(sha256)), MB, messageLength)
        .report();
    print('');
  }

  print('1 MB messages:');
  await _Encrypt(chacha20, MB).report();
  await _EncryptSync(chacha20, MB).report();
  await _Encrypt(chacha20Poly1305Aead, MB).report();

  await _Encrypt(aesCbc, MB).report();
  await _EncryptSync(aesCbc, MB).report();
  await _Encrypt(CipherWithAppendedMac(aesCbc, Hmac(sha256)), MB).report();
  await _EncryptSync(CipherWithAppendedMac(aesCbc, Hmac(sha256)), MB).report();

  await _Encrypt(aesCtr, MB).report();
  await _EncryptSync(aesCtr, MB).report();
  await _Encrypt(CipherWithAppendedMac(aesCtr, Hmac(sha256)), MB).report();
  print('');
}

class _Encrypt extends SimpleBenchmark {
  final Cipher cipher;
  final int totalLength;
  final int messageLength;
  SecretKey secretKey;
  Nonce nonce;
  Uint8List cleartext;
  Uint8List result;

  _Encrypt(this.cipher, this.totalLength, [int messageLength])
      : messageLength = messageLength ?? totalLength,
        super('${cipher.name}.encrypt()');

  @override
  Future<void> run() async {
    for (var i = 0; i < totalLength ~/ messageLength; i++) {
      await cipher.encrypt(
        cleartext,
        secretKey: secretKey,
        nonce: nonce,
      );
    }
  }

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
}

class _EncryptSync extends SimpleBenchmark {
  final Cipher cipher;
  final int totalLength;
  final int messageLength;
  SecretKey secretKey;
  Nonce nonce;
  Uint8List cleartext;
  Uint8List result;

  _EncryptSync(this.cipher, this.totalLength, [int messageLength])
      : messageLength = messageLength ?? totalLength,
        super('${cipher.name}.encryptSync()');

  @override
  Future<void> run() async {
    for (var i = 0; i < totalLength ~/ messageLength; i++) {
      await cipher.encryptSync(
        cleartext,
        secretKey: secretKey,
        nonce: nonce,
      );
    }
  }

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
}
