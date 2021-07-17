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

/// [Xchacha20] implemented in pure Dart.
class DartXchacha20 extends Xchacha20 {
  @override
  final MacAlgorithm macAlgorithm;

  final Chacha20 _chacha20;
  final Hchacha20 _hchacha20;

  DartXchacha20({
    required this.macAlgorithm,
  })  : _chacha20 = Chacha20(macAlgorithm: MacAlgorithm.empty),
        _hchacha20 = Hchacha20(),
        super.constructor();

  @override
  int get nonceLength => 24;

  @override
  Future<List<int>> decrypt(
    SecretBox secretBox, {
    required SecretKey secretKey,
    List<int> aad = const <int>[],
    int keyStreamIndex = 0,
  }) async {
    // Validate arguments
    final secretKeyData = await secretKey.extract();
    if (secretKeyData.bytes.length != 32) {
      throw ArgumentError.value(
        secretKey,
        'secretKey',
        'Must have 32 bytes',
      );
    }
    final nonce = secretBox.nonce;
    if (nonce.length != 24) {
      throw ArgumentError.value(
        secretBox,
        'secretBox',
        'Must have 24 bytes',
      );
    }
    await secretBox.checkMac(
      macAlgorithm: macAlgorithm,
      secretKey: secretKey,
      aad: aad,
    );

    // Create a new secret key with hchacha20.
    final nonceBytes = Uint8List.fromList(nonce);
    final newSecretKey = await _hchacha20.deriveKey(
      secretKey: secretKeyData,
      nonce: Uint8List.view(nonceBytes.buffer, 0, 16),
    );

    // Create new nonce.
    // The first 4 bytes will be zeroes.
    // The last 8 bytes will be the last 8 bytes of the original nonce.
    final newNonce = Uint8List(12);
    for (var i = 0; i < 8; i++) {
      newNonce[4 + i] = nonceBytes[16 + i];
    }

    // Decrypt with chacha20
    return _chacha20.decrypt(
      SecretBox(
        secretBox.cipherText,
        nonce: newNonce,
        mac: Mac.empty,
      ),
      secretKey: newSecretKey,
      keyStreamIndex: keyStreamIndex,
    );
  }

  @override
  Future<SecretBox> encrypt(
    List<int> data, {
    required SecretKey secretKey,
    List<int>? nonce,
    List<int> aad = const <int>[],
    int keyStreamIndex = 0,
  }) async {
    // Validate arguments
    final secretKeyData = await secretKey.extract();
    if (secretKeyData.bytes.length != 32) {
      throw ArgumentError.value(
        secretKey,
        'secretKey',
        'Must have 32 bytes',
      );
    }
    nonce ??= this.newNonce();
    if (nonce.length != 24) {
      throw ArgumentError.value(
        nonce,
        'nonce',
        'Must have 24 bytes',
      );
    }

    // Create a new secret key with hchacha20.
    final nonceBytes = Uint8List.fromList(nonce);
    final newSecretKey = await _hchacha20.deriveKey(
      secretKey: secretKeyData,
      nonce: Uint8List.view(nonceBytes.buffer, 0, 16),
    );

    // Create new nonce.
    // The first 4 bytes will be zeroes.
    // The last 8 bytes will be the last 8 bytes of the original nonce.
    final newNonceBytes = Uint8List(12);
    for (var i = 0; i < 8; i++) {
      newNonceBytes[4 + i] = nonceBytes[16 + i];
    }
    final newNonce = newNonceBytes;

    // Encrypt with chacha20
    final resultWithNewNonce = await _chacha20.encrypt(
      data,
      secretKey: newSecretKey,
      nonce: newNonce,
      keyStreamIndex: keyStreamIndex,
    );
    final cipherText = resultWithNewNonce.cipherText;

    // Calculate MAC
    // (it's different from one returned by _chacha20)
    final mac = await macAlgorithm.calculateMac(
      cipherText,
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
    );

    return SecretBox(
      cipherText,
      nonce: nonce,
      mac: mac,
    );
  }
}
