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

part of web_crypto;

abstract class _WebAesCipher extends Cipher {
  const _WebAesCipher();

  Cipher get dartImplementation;

  @override
  bool get isAuthenticated => dartImplementation.isAuthenticated;

  @override
  String get name => dartImplementation.name;

  @override
  int get nonceLength => dartImplementation.nonceLength;

  @override
  int get nonceLengthMax => dartImplementation.nonceLengthMax;

  @override
  int get nonceLengthMin => dartImplementation.nonceLengthMin;

  @override
  int get secretKeyLength => dartImplementation.secretKeyLength;

  @override
  Set<int> get secretKeyValidLengths =>
      dartImplementation.secretKeyValidLengths;

  @override
  bool get supportsAad => dartImplementation.supportsAad;

  @override
  Future<Uint8List> decrypt(
    List<int> cipherText, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) async {
    checkCipherParameters(
      this,
      secretKeyLength: null,
      nonce: nonce,
      aad: aad != null,
      keyStreamIndex: keyStreamIndex,
    );
    return _decrypt(
      cipherText,
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
    );
  }

  @override
  Uint8List decryptSync(
    List<int> input, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) {
    return dartImplementation.decryptSync(
      input,
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
      keyStreamIndex: keyStreamIndex,
    );
  }

  @override
  Future<Uint8List> encrypt(
    List<int> plainText, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) async {
    checkCipherParameters(
      this,
      secretKeyLength: null,
      nonce: nonce,
      aad: aad != null,
      keyStreamIndex: keyStreamIndex,
    );
    return _encrypt(
      plainText,
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
    );
  }

  @override
  Uint8List encryptSync(
    List<int> input, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) {
    return dartImplementation.encryptSync(
      input,
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
      keyStreamIndex: keyStreamIndex,
    );
  }

  Future<Uint8List> _decrypt(
    List<int> input, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    @required List<int> aad,
  });

  Future<Uint8List> _encrypt(
    List<int> input, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    @required List<int> aad,
  });

  /// Returns CryptoKey javascript object.
  Future<web_crypto.CryptoKey> _getCryptoKey(
    SecretKey secretKey,
    String name,
  ) async {
    // Is it cached?
    final cached = secretKey.cachedValues[this];
    if (cached != null) {
      return cached as web_crypto.CryptoKey;
    }

    // Construct it
    final secretKeyBytes = await secretKey.extract();
    final result = await js.promiseToFuture<web_crypto.CryptoKey>(
      web_crypto.subtle.importKey(
        'raw',
        _jsArrayBufferFrom(secretKeyBytes),
        web_crypto.AesKeyGenParams(
          name: name,
          length: 8 * secretKeyBytes.length,
        ),
        true,
        ['decrypt', 'encrypt'],
      ),
    );

    // Cache it
    secretKey.cachedValues[this] = result;

    return result;
  }
}
