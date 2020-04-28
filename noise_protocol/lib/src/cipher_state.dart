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

  // Cipher used for encrypting/decrypting.
  final NoiseCipher cipher;

  // The Noise specification refers to this with _k_.
  SecretKey _secretKey;

  // The Noise specification refers to this with _n_.
  int _counter;

  CipherState({@required this.cipher}) : assert(cipher != null);

  /// 64-bit counter. We throw an exception if it becomes too high to be
  /// represented as double.
  ///
  /// The [Noise specification](https://noiseprotocol.org/noise.html) refers to
  /// this with _n_.
  int get counter => _counter;

  /// Secret key.
  ///
  /// The [Noise specification](https://noiseprotocol.org/noise.html) refers to
  /// this with _k_.
  SecretKey get secretKey => _secretKey;

  /// Decrypts the bytes and increments the nonce. You can optionally give
  /// Associated Authenticated Data (AAD).
  ///
  /// The [Noise specification](https://noiseprotocol.org/noise.html) refers to
  /// this with _decryptAd_.
  Future<List<int>> decrypt(List<int> cipherText, {List<int> aad}) async {
    if (_secretKey == null) {
      return cipherText;
    }
    final result = await cipher.implementation.decrypt(
      cipherText,
      secretKey: _secretKey,
      nonce: cipher.nonce(counter),
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
  /// The [Noise specification](https://noiseprotocol.org/noise.html) refers to
  /// this with _encryptAd_.
  Future<List<int>> encrypt(List<int> plainText, {List<int> aad}) async {
    if (_secretKey == null) {
      return plainText;
    }
    final result = await cipher.implementation.encrypt(
      plainText,
      secretKey: _secretKey,
      nonce: cipher.nonce(counter),
      aad: aad,
    );
    _counter++;
    if (counter == _maxCounter) {
      throw StateError('Counter is too high');
    }
    return result;
  }

  /// Initializes the cipher state.
  ///
  /// The [Noise specification](https://noiseprotocol.org/noise.html) refers to
  /// this with _initializeKey_.
  void initialize(SecretKey secretKey) {
    _secretKey = secretKey;
    _counter = 0;
  }

  /// See the [specification](https://noiseprotocol.org/noise.html).
  Future<void> rekey() async {
    throw UnimplementedError();
  }
}
