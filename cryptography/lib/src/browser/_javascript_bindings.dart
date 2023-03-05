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

@JS()
library web_crypto_api;

import 'dart:convert' show base64Url;
import 'dart:html' show CryptoKey;
import 'dart:html' as html;
import 'dart:typed_data';

import 'package:js/js.dart';
import 'package:js/js_util.dart' show promiseToFuture;

export 'dart:html' show CryptoKey;

/// Note that browsers support Web Cryptography only in secure contexts.
final bool isWebCryptoAvailable =
    _subtle != null && (html.window.isSecureContext ?? false);

@JS('crypto.subtle')
external Object? get _subtle;

Uint8List base64UrlDecode(String s) {
  switch (s.length % 4) {
    case 1:
      return base64Url.decode('$s===');
    case 2:
      return base64Url.decode('$s==');
    case 3:
      return base64Url.decode('$s=');
    default:
      return base64Url.decode(s);
  }
}

Uint8List base64UrlDecodeUnmodifiable(String s) {
  final bytes = base64UrlDecode(s);
  // UnmodifiableUint8ListView has bugs so we removed it
  return bytes;
}

Uint8List? base64UrlDecodeUnmodifiableMaybe(String? s) {
  if (s == null) {
    return null;
  }
  final bytes = base64UrlDecode(s);
  // UnmodifiableUint8ListView has bugs so we removed it
  return bytes;
}

String base64UrlEncode(List<int> data) {
  var s = base64Url.encode(data);
  // Remove trailing '=' characters
  var length = s.length;
  while (s.startsWith('=', length - 1)) {
    length--;
  }
  return s.substring(0, length);
}

String? base64UrlEncodeMaybe(List<int>? data) {
  if (data == null) {
    return null;
  }
  return base64UrlEncode(data);
}

Future<ByteBuffer> decrypt(
  dynamic algorithm,
  CryptoKey key,
  ByteBuffer data,
) {
  return promiseToFuture(
    _decrypt(algorithm, key, data),
  );
}

Future<ByteBuffer> deriveBits(
  dynamic algorithm,
  CryptoKey cryptoKey,
  int bits,
) {
  return promiseToFuture(
    _deriveBits(algorithm, cryptoKey, bits),
  );
}

Future<CryptoKey> deriveKey(
  dynamic algorithm,
  CryptoKey baseKey,
  dynamic derivedKeyAlgorithm,
  dynamic extractable,
  List<String> keyUsages,
) {
  return promiseToFuture(
    _deriveKey(
      algorithm,
      baseKey,
      derivedKeyAlgorithm,
      extractable,
      keyUsages,
    ),
  );
}

Future<ByteBuffer> digest(
  String name,
  ByteBuffer data,
) {
  return promiseToFuture(
    _digest(name, data),
  );
}

Future<ByteBuffer> encrypt(
  dynamic algorithm,
  CryptoKey key,
  ByteBuffer data,
) {
  return promiseToFuture(
    _encrypt(algorithm, key, data),
  );
}

Future<Jwk> exportKeyWhenJwk(CryptoKey key) {
  return promiseToFuture<Jwk>(
    _exportKey('jwk', key),
  );
}

Future<ByteBuffer> exportKeyWhenRaw(CryptoKey key) {
  return promiseToFuture<ByteBuffer>(
    _exportKey('raw', key),
  );
}

Future<CryptoKey> generateKeyWhenKey(
  Object algorithm,
  bool extractable,
  List<String> keyUsages,
) {
  return promiseToFuture<CryptoKey>(
    _generateKey(algorithm, extractable, keyUsages),
  );
}

Future<CryptoKeyPair> generateKeyWhenKeyPair(
  Object algorithm,
  bool extractable,
  List<String> keyUsages,
) {
  return promiseToFuture<CryptoKeyPair>(
    _generateKey(algorithm, extractable, keyUsages),
  );
}

Future<CryptoKey> importKeyWhenJwk(
  Jwk keyData,
  dynamic algorithm,
  bool extractable,
  List<String> keyUsages,
) {
  return promiseToFuture(
    _importKey(
      'jwk',
      keyData,
      algorithm,
      extractable,
      keyUsages,
    ),
  );
}

Future<CryptoKey> importKeyWhenRaw(
  ByteBuffer keyData,
  dynamic algorithm,
  bool extractable,
  List<String> keyUsages,
) {
  return promiseToFuture(
    _importKey(
      'raw',
      keyData,
      algorithm,
      extractable,
      keyUsages,
    ),
  );
}

ByteBuffer jsArrayBufferFrom(List<int> data) {
  // Avoid copying if possible
  //
  if (data is Uint8List &&
      data.offsetInBytes == 0 &&
      data.lengthInBytes == data.buffer.lengthInBytes) {
    // We need to check the type because UnmodifiableByteBufferView would cause
    // an error.
    final buffer = data.buffer;
    if (identical(buffer.runtimeType, ByteBuffer)) {
      return buffer;
    }
  }

  // Copy
  return Uint8List.fromList(data).buffer;
}

Future<ByteBuffer> sign(
  dynamic algorithm,
  CryptoKey key,
  ByteBuffer data,
) {
  return promiseToFuture(
    _sign(algorithm, key, data),
  );
}

Future<bool> verify(
  dynamic algorithm,
  CryptoKey key,
  ByteBuffer signature,
  ByteBuffer data,
) {
  return promiseToFuture(
    _verify(algorithm, key, signature, data),
  );
}

@JS('crypto.subtle.decrypt')
external Promise<ByteBuffer> _decrypt(
  dynamic algorithm,
  CryptoKey key,
  ByteBuffer data,
);

@JS('crypto.subtle.deriveBits')
external Promise<ByteBuffer> _deriveBits(
  dynamic algorithm,
  CryptoKey cryptoKey,
  int bits,
);

@JS('crypto.subtle.deriveKey')
external Promise<CryptoKey> _deriveKey(
  dynamic algorithm,
  CryptoKey baseKey,
  dynamic derivedKeyAlgorithm,
  dynamic extractable,
  List<String> keyUsages,
);

@JS('crypto.subtle.digest')
external Promise<ByteBuffer> _digest(
  String name,
  ByteBuffer data,
);

@JS('crypto.subtle.encrypt')
external Promise<ByteBuffer> _encrypt(
  dynamic algorithm,
  CryptoKey key,
  ByteBuffer data,
);

@JS('crypto.subtle.exportKey')
external Promise _exportKey(
  String format,
  CryptoKey key,
);

@JS('crypto.subtle.generateKey')
external Promise _generateKey(
  Object algorithm,
  bool extractable,
  List<String> keyUsages,
);

@JS('crypto.subtle.importKey')
external Promise<CryptoKey> _importKey(
  String format,
  dynamic keyData,
  dynamic algorithm,
  bool extractable,
  List<String> keyUsages,
);

@JS('crypto.subtle.sign')
external Promise<ByteBuffer> _sign(
  dynamic algorithm,
  CryptoKey key,
  ByteBuffer data,
);

@JS('crypto.subtle.verify')
external Promise<bool> _verify(
  dynamic algorithm,
  CryptoKey key,
  ByteBuffer signature,
  ByteBuffer data,
);

@JS()
@anonymous
class AesCbcParams {
  external factory AesCbcParams({
    required String name,
    required ByteBuffer iv,
  });
}

@JS()
@anonymous
class AesCtrParams {
  external factory AesCtrParams({
    required String name,
    required ByteBuffer counter,
    required int length,
  });
}

@JS()
@anonymous
class AesGcmParams {
  external factory AesGcmParams({
    required String name,
    required ByteBuffer iv,
    ByteBuffer? additionalData,
    required int tagLength,
  });
}

@JS()
@anonymous
class AesKeyGenParams {
  external factory AesKeyGenParams({
    required String name,
    required int length,
  });
}

@JS('CryptoKeyPair')
class CryptoKeyPair {
  external factory CryptoKeyPair._();

  external CryptoKey get privateKey;

  external CryptoKey get publicKey;
}

@JS()
@anonymous
class EcdhKeyDeriveParams {
  external factory EcdhKeyDeriveParams({
    required String name,
    required CryptoKey public,
  });
}

@JS()
@anonymous
class EcdhParams {
  external factory EcdhParams({
    required String name,
    required String namedCurve,
  });
}

@JS()
@anonymous
class EcdsaParams {
  external factory EcdsaParams({
    required String name,
    required String hash,
  });
}

@JS()
@anonymous
class EcKeyGenParams {
  external factory EcKeyGenParams({
    required String name,
    required String namedCurve,
  });
}

@JS()
@anonymous
class EcKeyImportParams {
  external factory EcKeyImportParams({
    required String name,
    required String namedCurve,
  });
}

@JS()
@anonymous
class HkdfParams {
  external factory HkdfParams({
    required String name,
    required String hash,
    required ByteBuffer salt,
    required ByteBuffer info,
  });
}

@JS()
@anonymous
class HmacImportParams {
  external factory HmacImportParams({
    required String name,
    required String hash,
    int? length,
  });
}

@JS()
@anonymous
class HmacKeyGenParams {
  external factory HmacKeyGenParams({
    required String name,
    required String hash,
    required int length,
  });
}

@JS()
@anonymous
class Jwk {
  external factory Jwk({
    String? crv,
    String? n,
    String? e,
    String? d,
    String? p,
    String? q,
    String? dp,
    String? dq,
    String? qi,
    bool? ext,
    // ignore: non_constant_identifier_names
    List<String>? key_ops,
    required String kty,
    String? x,
    String? y,
  });

  external String? get crv;

  external String? get d;

  external String? get dp;

  external String? get dq;

  external String? get e;

  external bool get ext;

  // ignore: non_constant_identifier_names
  external List<String> get key_ops;

  external String get kty;

  external String? get n;

  external String? get p;

  external String? get q;

  external String? get qi;

  external String? get x;

  external String? get y;
}

@JS()
@anonymous
class Pkdf2Params {
  external factory Pkdf2Params({
    required String name,
    required String hash,
    required ByteBuffer salt,
    required int iterations,
  });
}

@JS('Promise')
class Promise<T> {
  external factory Promise._();
}

@JS()
@anonymous
class RsaHashedImportParams {
  external factory RsaHashedImportParams({
    required String name,
    required String hash,
  });
}

@JS()
@anonymous
class RsaHashedKeyGenParams {
  external factory RsaHashedKeyGenParams({
    required String name,
    required int modulusLength,
    required dynamic publicExponent,
    required String hash,
  });
}

@JS()
@anonymous
class RsaPssParams {
  external factory RsaPssParams({
    required String name,
    int? saltLength,
  });
}

@JS()
@anonymous
class SignParams {
  external factory SignParams({
    required String name,
  });
}

@JS()
@anonymous
class VerifyParams {
  external factory VerifyParams({
    required String name,
  });
}
