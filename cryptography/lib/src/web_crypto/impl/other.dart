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

Future<Hash> hash(List<int> bytes, String name) async {
  ArgumentError.checkNotNull(bytes);
  final byteBuffer = await js.promiseToFuture<ByteBuffer>(
    web_crypto.digest(name, _jsArrayBufferFrom(bytes)),
  );
  return Hash(Uint8List.view(byteBuffer));
}

final _hmacCachingKeys = {
  'SHA-1': Object(),
  'SHA-256': Object(),
  'SHA-384': Object(),
  'SHA-512': Object(),
};

Future<web_crypto.CryptoKey> _hmacSecretKeyToJs(
    SecretKey secretKey, String hashName) async {
  final cachingKey = _hmacCachingKeys[hashName];
  if (cachingKey != null) {
    final result = secretKey.cachedValues[cachingKey];
    if (result != null) {}
  }

  final secretKeyBytes = await secretKey.extract();
  final result = await js.promiseToFuture<web_crypto.CryptoKey>(
    web_crypto.importKey(
      'raw',
      _jsArrayBufferFrom(secretKeyBytes),
      web_crypto.HmacImportParams(
        name: 'HMAC',
        hash: hashName,
      ),
      true,
      const ['sign'],
    ),
  );

  if (cachingKey != null) {
    secretKey.cachedValues[cachingKey] = result;
  }

  return result;
}

Future<List<int>> hkdf(
  List<int> bytes, {
  @required String hashName,
  @required List<int> salt,
  @required List<int> info,
  @required int bits,
}) async {
  ArgumentError.checkNotNull(bytes);
  salt ??= const <int>[];

  final jsCryptoKey = await js.promiseToFuture<web_crypto.CryptoKey>(
    web_crypto.importKey(
      'raw',
      _jsArrayBufferFrom(bytes),
      'HKDF',
      false,
      const ['deriveBits'],
    ),
  );

  final byteBuffer = await js.promiseToFuture<ByteBuffer>(
    web_crypto.deriveBits(
      web_crypto.HkdfParams(
        name: 'HKDF',
        hash: hashName,
        salt: _jsArrayBufferFrom(salt),
        info: _jsArrayBufferFrom(info),
      ),
      jsCryptoKey,
      bits,
    ),
  );

  return Uint8List.view(byteBuffer);
}

Future<Mac> hmac(
  List<int> bytes, {
  @required SecretKey secretKey,
  @required String hashName,
}) async {
  ArgumentError.checkNotNull(bytes);
  final jsCryptoKey = await _hmacSecretKeyToJs(secretKey, hashName);
  final byteBuffer = await js.promiseToFuture<ByteBuffer>(
    web_crypto.sign(
      'HMAC',
      jsCryptoKey,
      _jsArrayBufferFrom(bytes),
    ),
  );
  return Mac(Uint8List.view(byteBuffer));
}

Future<Uint8List> pbkdf2(
  List<int> input, {
  @required String hashName,
  @required int bits,
  @required int iterations,
  @required Nonce nonce,
}) async {
  ArgumentError.checkNotNull(nonce, 'nonce');
  ArgumentError.checkNotNull(bits, 'bits');
  ArgumentError.checkNotNull(iterations, 'iterations');

  // importKey(...)
  final cryptoKey = await js.promiseToFuture<web_crypto.CryptoKey>(
    web_crypto.importKey(
      'raw',
      _jsArrayBufferFrom(input),
      'PBKDF2',
      false,
      ['deriveBits'],
    ),
  );

  // deriveBits(...)
  final byteBuffer = await js.promiseToFuture<ByteBuffer>(
    web_crypto.deriveBits(
      web_crypto.Pkdf2Params(
        name: 'PBKDF2',
        hash: hashName,
        salt: _jsArrayBufferFrom(nonce.bytes),
        iterations: iterations,
      ),
      cryptoKey,
      bits,
    ),
  );

  return Uint8List.view(byteBuffer);
}
