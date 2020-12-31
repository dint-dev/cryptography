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

part of noise_protocol;

/// _CipherState_ in the [specification](https://noiseprotocol.org/noise.html).
class CipherState {
  /// Exclusive max for counter.
  static const int _maxCounter = 1 << 47;

  /// Cipher used for encrypting/decrypting.
  final NoiseCipher cipher;

  // In the Noise specification, this is known as _k_.
  SecretKeyData? _secretKey;

  // In the Noise specification, this is known as _n_.
  int _counter = 0;

  CipherState({required this.cipher});

  /// 64-bit counter. We throw an exception if it becomes too high to be
  /// represented as double.
  ///
  /// In the [Noise protocol specification](https://noiseprotocol.org/noise.html),
  /// this is known as _n_.
  int get counter => _counter;

  /// Secret key.
  ///
  /// In the [Noise protocol specification](https://noiseprotocol.org/noise.html),
  /// this is known as _k_.
  SecretKeyData? get secretKey => _secretKey;

  /// Decrypts the bytes and increments the nonce. You can optionally give
  /// Associated Authenticated Data (AAD).
  ///
  /// In the [Noise protocol specification](https://noiseprotocol.org/noise.html),
  /// this is known as _decryptAd_.
  Future<List<int>> decrypt(
    List<int> cipherText, {
    List<int> aad = const <int>[],
  }) async {
    final secretKey = _secretKey;
    if (secretKey == null) {
      return cipherText;
    }
    final result = await cipher.implementation.decrypt(
      SecretBox(
        cipherText,
        nonce: cipher.nonce(counter),
        mac: Mac.empty,
      ),
      secretKey: secretKey,
      aad: aad,
    );
    _counter++;
    if (counter == _maxCounter) {
      throw StateError('Counter is too high');
    }
    return result;
  }

  /// Encrypts the bytes and increments the nonce. You can optionally give
  /// Associated Authenticated Data (AAD).
  ///
  /// In the [Noise protocol specification](https://noiseprotocol.org/noise.html),
  /// this is known as _encryptAd_.
  Future<List<int>> encrypt(
    List<int> clearText, {
    List<int> aad = const <int>[],
  }) async {
    final secretKey = _secretKey;
    if (secretKey == null) {
      return clearText;
    }
    final result = await cipher.implementation.encrypt(
      clearText,
      secretKey: secretKey,
      nonce: cipher.nonce(counter),
      aad: aad,
    );
    _counter++;
    if (counter == _maxCounter) {
      throw StateError('Counter is too high');
    }
    return result.cipherText;
  }

  /// Initializes the cipher state.
  ///
  /// In the [Noise protocol specification](https://noiseprotocol.org/noise.html),
  /// this is known as _initializeKey_.
  void initialize(SecretKeyData? secretKey) {
    _secretKey = secretKey;
    _counter = 0;
  }

  /// See the [Noise protocol specification](https://noiseprotocol.org/noise.html).
  Future<void> rekey() async {
    throw UnimplementedError();
  }
}
