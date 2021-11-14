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
import 'package:cryptography/dart.dart';

Uint8List _xchacha20Nonce(List<int> nonce) {
  final nonce96Bits = Uint8List(12);
  for (var i = 0; i < 8; i++) {
    nonce96Bits[4 + i] = nonce[16 + i];
  }
  return nonce96Bits;
}

Future<SecretKeyData> _xchacha20SecretKey({
  required SecretKey secretKey,
  required List<int> nonce,
}) async {
  final secretKeyData = await secretKey.extract();
  return const DartHChacha20().deriveKeySync(
    secretKeyData: secretKeyData,
    nonce: nonce.sublist(0, 16),
  );
}

/// [Xchacha20] implemented in pure Dart.
class DartXchacha20 extends StreamingCipher implements Xchacha20 {
  final Chacha20 _chacha20;

  @override
  final MacAlgorithm macAlgorithm;

  factory DartXchacha20.poly1305Aead() =>
      DartXchacha20._poly1305Aead(Chacha20.poly1305Aead());

  DartXchacha20({required this.macAlgorithm})
      : _chacha20 = Chacha20(macAlgorithm: macAlgorithm);

  DartXchacha20._poly1305Aead(Chacha20 chacha20)
      : _chacha20 = chacha20,
        macAlgorithm = _DartXChacha20Poly1305Aead(chacha20.macAlgorithm);

  @override
  int get nonceLength => 24;

  @override
  int get secretKeyLength => 32;

  @override
  Future<List<int>> decrypt(
    SecretBox secretBox, {
    required SecretKey secretKey,
    List<int> aad = const <int>[],
    int keyStreamIndex = 0,
  }) async {
    // Secret key for normal Chacha20
    final derivedSecretKey = await _xchacha20SecretKey(
      secretKey: secretKey,
      nonce: secretBox.nonce,
    );

    // Nonce for normal Chacha20
    final derivedNonce = _xchacha20Nonce(secretBox.nonce);

    // New secret box
    final derivedSecretBox = SecretBox(
      secretBox.cipherText,
      nonce: derivedNonce,
      mac: secretBox.mac,
    );

    // Decrypt
    final clearText = await _chacha20.decrypt(
      derivedSecretBox,
      secretKey: derivedSecretKey,
      aad: aad,
      keyStreamIndex: keyStreamIndex,
    );

    return clearText;
  }

  @override
  Future<SecretBox> encrypt(
    List<int> clearText, {
    required SecretKey secretKey,
    List<int>? nonce,
    List<int> aad = const <int>[],
    int keyStreamIndex = 0,
  }) async {
    nonce ??= newNonce();

    // New secret key for normal Chacha20
    final derivedSecretKey = await _xchacha20SecretKey(
      secretKey: secretKey,
      nonce: nonce,
    );

    // New nonce for normal Chacha20
    final derivedNonce = _xchacha20Nonce(nonce);

    // Encrypt
    final secretBox = await _chacha20.encrypt(
      clearText,
      secretKey: derivedSecretKey,
      nonce: derivedNonce,
      aad: aad,
      keyStreamIndex: keyStreamIndex,
    );

    // New secret box
    return SecretBox(
      secretBox.cipherText,
      nonce: nonce,
      mac: secretBox.mac,
    );
  }
}

class _DartXChacha20Poly1305Aead extends MacAlgorithm {
  final MacAlgorithm _macAlgorithm;

  _DartXChacha20Poly1305Aead(this._macAlgorithm);

  @override
  int get macLength => _macAlgorithm.macLength;

  @override
  bool get supportsAad => _macAlgorithm.supportsAad;

  @override
  Future<Mac> calculateMac(
    List<int> bytes, {
    required SecretKey secretKey,
    List<int> nonce = const <int>[],
    List<int> aad = const <int>[],
  }) async {
    // New secret key
    final derivedSecretKey = await _xchacha20SecretKey(
      secretKey: secretKey,
      nonce: nonce,
    );

    // New nonce
    final derivedNonce = _xchacha20Nonce(nonce);

    final mac = await _macAlgorithm.calculateMac(
      bytes,
      secretKey: derivedSecretKey,
      nonce: derivedNonce,
      aad: aad,
    );
    return mac;
  }

  @override
  Future<MacSink> newMacSink({
    required SecretKey secretKey,
    List<int> nonce = const <int>[],
    List<int> aad = const <int>[],
  }) async {
    // New secret key
    final derivedSecretKey = await _xchacha20SecretKey(
      secretKey: secretKey,
      nonce: nonce,
    );

    // New nonce
    final derivedNonce = _xchacha20Nonce(nonce);

    return _macAlgorithm.newMacSink(
      secretKey: derivedSecretKey,
      nonce: derivedNonce,
      aad: aad,
    );
  }
}
