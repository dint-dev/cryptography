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

/// AES key generator.
Future<SecretKey> aesNewSecretKey({
  @required String name,
  @required int bits,
}) async {
  final cryptoKey = await js.promiseToFuture<web_crypto.CryptoKey>(
    web_crypto.generateKey(
      web_crypto.AesKeyGenParams(
        name: name,
        length: bits,
      ),
      true,
      const ['encrypt', 'decrypt'],
    ),
  );
  final byteBuffer = await js.promiseToFuture<ByteBuffer>(
    web_crypto.exportKey(
      'raw',
      cryptoKey,
    ),
  );
  final secretKey = SecretKey(Uint8List.view(byteBuffer));
  secretKey.cachedValues[_webCryptoKeyCachingKey] = cryptoKey;
  return secretKey;
}

/// AES-CBC decryption.
Future<Uint8List> aesCbcDecrypt(
  List<int> input, {
  @required SecretKey secretKey,
  @required Nonce nonce,
}) async {
  final byteBuffer = await js.promiseToFuture<ByteBuffer>(
    web_crypto.decrypt(
      web_crypto.AesCbcParams(
        name: 'AES-CBC',
        iv: _jsArrayBufferFrom(nonce.bytes),
      ),
      await _aesCryptoKey(secretKey, 'AES-CBC'),
      _jsArrayBufferFrom(input),
    ),
  );
  return Uint8List.view(byteBuffer);
}

/// AES-CBC encryption.
Future<Uint8List> aesCbcEncrypt(
  List<int> input, {
  @required SecretKey secretKey,
  @required Nonce nonce,
}) async {
  final byteBuffer = await js.promiseToFuture<ByteBuffer>(
    web_crypto.encrypt(
      web_crypto.AesCbcParams(
        name: 'AES-CBC',
        iv: _jsArrayBufferFrom(nonce.bytes),
      ),
      await _aesCryptoKey(secretKey, 'AES-CBC'),
      _jsArrayBufferFrom(input),
    ),
  );
  return Uint8List.view(byteBuffer);
}

/// Returns CryptoKey javascript object.
Future<web_crypto.CryptoKey> _aesCryptoKey(
  SecretKey secretKey,
  String name,
) async {
  // Is it cached?
  final cached = secretKey.cachedValues[_webCryptoKeyCachingKey];
  if (cached != null) {
    return cached as web_crypto.CryptoKey;
  }

  // Construct it
  final secretKeyBytes = await secretKey.extract();
  final result = await js.promiseToFuture<web_crypto.CryptoKey>(
    web_crypto.importKey(
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
  secretKey.cachedValues[_webCryptoKeyCachingKey] = result;

  return result;
}

@override
Future<Uint8List> aesCtrDecrypt(
  List<int> cipherText, {
  @required SecretKey secretKey,
  @required Nonce nonce,
}) async {
  ArgumentError.checkNotNull(cipherText, 'plainText');
  ArgumentError.checkNotNull(secretKey, 'secretKey');
  ArgumentError.checkNotNull(nonce, 'nonce');
  var counterBytes = Uint8List(16);
  counterBytes.setAll(0, nonce.bytes);
  final byteBuffer = await js.promiseToFuture<ByteBuffer>(
    web_crypto.decrypt(
      web_crypto.AesCtrParams(
        name: 'AES-CTR',
        counter: counterBytes.buffer,
        length: 64,
      ),
      await _aesCryptoKey(secretKey, 'AES-CTR'),
      _jsArrayBufferFrom(cipherText),
    ),
  );
  return Uint8List.view(byteBuffer);
}

@override
Future<Uint8List> aesCtrEncrypt(
  List<int> plainText, {
  @required SecretKey secretKey,
  @required Nonce nonce,
}) async {
  ArgumentError.checkNotNull(plainText, 'plainText');
  ArgumentError.checkNotNull(secretKey, 'secretKey');
  ArgumentError.checkNotNull(nonce, 'nonce');
  var counterBytes = Uint8List(16);
  counterBytes.setAll(0, nonce.bytes);
  final byteBuffer = await js.promiseToFuture<ByteBuffer>(
    web_crypto.encrypt(
      web_crypto.AesCtrParams(
        name: 'AES-CTR',
        counter: counterBytes.buffer,
        length: 64,
      ),
      await _aesCryptoKey(secretKey, 'AES-CTR'),
      _jsArrayBufferFrom(plainText),
    ),
  );
  return Uint8List.view(byteBuffer);
}

Future<Uint8List> aesGcmDecrypt(
  List<int> cipherText, {
  @required SecretKey secretKey,
  @required Nonce nonce,
  @required List<int> aad,
}) async {
  try {
    ArgumentError.checkNotNull(cipherText, 'cipherText');
    ArgumentError.checkNotNull(secretKey, 'secretKey');
    ArgumentError.checkNotNull(nonce, 'nonce');
    aad ??= const <int>[];
    final byteBuffer = await js.promiseToFuture<ByteBuffer>(
      web_crypto.decrypt(
        web_crypto.AesGcmParams(
          name: 'AES-GCM',
          iv: _jsArrayBufferFrom(nonce.bytes),
          additionalData: _jsArrayBufferFrom(aad),
          tagLength: 128,
        ),
        await _aesCryptoKey(secretKey, 'AES-GCM'),
        _jsArrayBufferFrom(cipherText),
      ),
    );
    return Uint8List.view(byteBuffer);
  } on html.DomException catch (e) {
    if (e.name == 'OperationError') {
      throw MacValidationException();
    }
    rethrow;
  }
}

Future<Uint8List> aesGcmEncrypt(
  List<int> plainText, {
  @required SecretKey secretKey,
  @required Nonce nonce,
  @required List<int> aad,
}) async {
  ArgumentError.checkNotNull(plainText, 'plainText');
  ArgumentError.checkNotNull(secretKey, 'secretKey');
  ArgumentError.checkNotNull(nonce, 'nonce');
  aad ??= const <int>[];
  final byteBuffer = await js.promiseToFuture<ByteBuffer>(
    web_crypto.encrypt(
      web_crypto.AesGcmParams(
        name: 'AES-GCM',
        iv: _jsArrayBufferFrom(nonce.bytes),
        additionalData: _jsArrayBufferFrom(aad),
        tagLength: 128,
      ),
      await _aesCryptoKey(secretKey, 'AES-GCM'),
      _jsArrayBufferFrom(plainText),
    ),
  );
  return Uint8List.view(byteBuffer);
}

final _webCryptoKeyCachingKey = Object();
