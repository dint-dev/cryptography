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
library;

import 'dart:convert' show base64Url;
import 'package:web/web.dart';
import 'dart:typed_data';
import 'dart:js_interop';

export 'package:web/web.dart';

/// Note that browsers support Web Cryptography only in secure contexts.
final bool isWebCryptoAvailable = _subtle != null && window.isSecureContext;

@JS('crypto.subtle')
external JSAny? get _subtle;

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

Future<JSArrayBuffer> decrypt(JSAny? algorithm, CryptoKey key, JSArrayBuffer data) {
  return _decrypt(algorithm, key, data).toDart;
}

Future<JSArrayBuffer> deriveBits(JSAny? algorithm, CryptoKey cryptoKey, JSNumber bits) {
  return _deriveBits(algorithm, cryptoKey, bits).toDart;
}

Future<CryptoKey> deriveKey(
  JSAny? algorithm,
  CryptoKey baseKey,
  JSAny? derivedKeyAlgorithm,
  JSAny? extractable,
  JSArray<JSString> keyUsages,
) {
  return _deriveKey(algorithm, baseKey, derivedKeyAlgorithm, extractable, keyUsages).toDart;
}

Future<JSArrayBuffer> digest(JSString name, JSArrayBuffer data) {
  return _digest(name, data).toDart;
}

Future<JSArrayBuffer> encrypt(JSAny? algorithm, CryptoKey key, JSArrayBuffer data) {
  return _encrypt(algorithm, key, data).toDart;
}

Future<JsonWebKey> exportKeyWhenJwk(CryptoKey key) async {
  return (await _exportKey('jwk'.toJS, key).toDart) as JsonWebKey;
}

Future<JSArrayBuffer> exportKeyWhenRaw(CryptoKey key) async {
  return (await _exportKey('raw'.toJS, key).toDart) as JSArrayBuffer;
}

Future<CryptoKey> generateKeyWhenKey(
  JSAny? algorithm,
  JSBoolean extractable,
  JSArray<JSString> keyUsages,
) async {
  return (await _generateKey(algorithm, extractable, keyUsages).toDart) as CryptoKey;
}

Future<CryptoKeyPair> generateKeyWhenKeyPair(
  JSAny? algorithm,
  JSBoolean extractable,
  JSArray<JSString> keyUsages,
) async {
  return (await _generateKey(algorithm, extractable, keyUsages).toDart) as CryptoKeyPair;
}

Future<CryptoKey> importKeyWhenJwk(
  JsonWebKey keyData,
  JSAny? algorithm,
  JSBoolean extractable,
  JSArray<JSString> keyUsages,
) {
  return _importKey('jwk'.toJS, keyData, algorithm, extractable, keyUsages).toDart;
}

Future<CryptoKey> importKeyWhenRaw(
  JSArrayBuffer keyData,
  JSAny? algorithm,
  JSBoolean extractable,
  JSArray<JSString> keyUsages,
) {
  return _importKey('raw'.toJS, keyData, algorithm, extractable, keyUsages).toDart;
}

JSArrayBuffer jsArrayBufferFrom(List<int> data) {
  // Avoid copying if possible
  //
  if (data is Uint8List &&
      data.offsetInBytes == 0 &&
      data.lengthInBytes == data.buffer.lengthInBytes) {
    // We need to check the type because UnmodifiableByteBufferView would cause
    // an error.
    final buffer = data.buffer;
    if (identical(buffer.runtimeType, ByteBuffer)) {
      return buffer.toJS;
    }
  }

  // Copy
  return Uint8List.fromList(data).buffer.toJS;
}

Future<JSArrayBuffer> sign(JSAny? algorithm, CryptoKey key, JSArrayBuffer data) {
  return _sign(algorithm, key, data).toDart;
}

Future<JSBoolean> verify(
  JSAny? algorithm,
  CryptoKey key,
  JSArrayBuffer signature,
  JSArrayBuffer data,
) {
  return _verify(algorithm, key, signature, data).toDart;
}

@JS('crypto.subtle.decrypt')
external JSPromise<JSArrayBuffer> _decrypt(JSAny? algorithm, CryptoKey key, JSArrayBuffer data);

@JS('crypto.subtle.deriveBits')
external JSPromise<JSArrayBuffer> _deriveBits(JSAny? algorithm, CryptoKey cryptoKey, JSNumber bits);

@JS('crypto.subtle.deriveKey')
external JSPromise<CryptoKey> _deriveKey(
  JSAny? algorithm,
  CryptoKey baseKey,
  JSAny? derivedKeyAlgorithm,
  JSAny? extractable,
  JSArray<JSString> keyUsages,
);

@JS('crypto.subtle.digest')
external JSPromise<JSArrayBuffer> _digest(JSString name, JSArrayBuffer data);

@JS('crypto.subtle.encrypt')
external JSPromise<JSArrayBuffer> _encrypt(JSAny? algorithm, CryptoKey key, JSArrayBuffer data);

@JS('crypto.subtle.exportKey')
external JSPromise _exportKey(JSString format, CryptoKey key);

@JS('crypto.subtle.generateKey')
external JSPromise _generateKey(
  JSAny? algorithm,
  JSBoolean extractable,
  JSArray<JSString> keyUsages,
);

@JS('crypto.subtle.importKey')
external JSPromise<CryptoKey> _importKey(
  JSString format,
  JSAny? keyData,
  JSAny? algorithm,
  JSBoolean extractable,
  JSArray<JSString> keyUsages,
);

@JS('crypto.subtle.sign')
external JSPromise<JSArrayBuffer> _sign(JSAny? algorithm, CryptoKey key, JSArrayBuffer data);

@JS('crypto.subtle.verify')
external JSPromise<JSBoolean> _verify(
  JSAny? algorithm,
  CryptoKey key,
  JSArrayBuffer signature,
  JSArrayBuffer data,
);

@JS()
@anonymous
external AesCbcParams get aesCbcParams;
extension type AesCbcParams._(JSObject _) implements JSObject {
  external factory AesCbcParams({required JSString name, required JSArrayBuffer iv});
}

@JS()
@anonymous
external AesCtrParams get aesCtrParams;
extension type AesCtrParams._(JSObject _) implements JSObject {
  external factory AesCtrParams({
    required JSString name,
    required JSArrayBuffer counter,
    required JSNumber length,
  });
}

@JS()
@anonymous
external AesGcmParams get aesGcmParams;
extension type AesGcmParams._(JSObject _) implements JSObject {
  external factory AesGcmParams({
    required JSString name,
    required JSArrayBuffer iv,
    JSArrayBuffer? additionalData,
    required JSNumber tagLength,
  });
}

@JS()
@anonymous
external AesKeyGenParams get aesKeyGenParams;
extension type AesKeyGenParams._(JSObject _) implements JSObject {
  external factory AesKeyGenParams({required JSString name, required JSNumber length});
}

@JS('CryptoKeyPair')
external CryptoKeyPair get cryptoKeyPair;
extension type CryptoKeyPair._(JSObject _) implements JSObject {
  external CryptoKey get privateKey;

  external CryptoKey get publicKey;
}

@JS()
@anonymous
external EcdhKeyDeriveParams get ecdhKeyDeriveParams;
extension type EcdhKeyDeriveParams._(JSObject _) implements JSObject {
  external factory EcdhKeyDeriveParams({required JSString name, required CryptoKey public});
}

@JS()
@anonymous
external EcdhParams get ecdhParams;
extension type EcdhParams._(JSObject _) implements JSObject {
  external factory EcdhParams({required JSString name, required JSString namedCurve});
}

@JS()
@anonymous
external EcdsaParams get ecdsaParams;
extension type EcdsaParams._(JSObject _) implements JSObject {
  external factory EcdsaParams({required JSString name, required JSString hash});
}

@JS()
@anonymous
external EcKeyGenParams get ecKeyGenParams;
extension type EcKeyGenParams._(JSObject _) implements JSObject {
  external factory EcKeyGenParams({required JSString name, required JSString namedCurve});
}

@JS()
@anonymous
external EcKeyImportParams get ecKeyImportParams;
extension type EcKeyImportParams._(JSObject _) implements JSObject {
  external factory EcKeyImportParams({required JSString name, required JSString namedCurve});
}

@JS()
@anonymous
external HkdfParams get hkdfParams;
extension type HkdfParams._(JSObject _) implements JSObject {
  external factory HkdfParams({
    required JSString name,
    required JSString hash,
    required JSArrayBuffer salt,
    required JSArrayBuffer info,
  });
}

@JS()
@anonymous
external HmacImportParams get hmacImportParams;

extension type HmacImportParams._(JSObject _) implements JSObject {
  external factory HmacImportParams({
    required JSString name,
    required JSString hash,
    JSNumber? length,
  });
}

@JS()
@anonymous
external HmacKeyGenParams get hmacKeyGenParams;
extension type HmacKeyGenParams._(JSObject _) implements JSObject {
  external factory HmacKeyGenParams({
    required JSString name,
    required JSString hash,
    required JSNumber length,
  });
}

// @JS()
// @anonymous
// external Jwk get jwk;
// extension type Jwk._(JSObject _) implements JsonWebKey {
//   external factory Jwk({
//     JSString? crv,
//     JSString? n,
//     JSString? e,
//     JSString? d,
//     JSString? p,
//     JSString? q,
//     JSString? dp,
//     JSString? dq,
//     JSString? qi,
//     JSBoolean? ext,
//     // ignore: non_constant_identifier_names
//     JSArray<JSString>? key_ops,
//     required JSString kty,
//     JSString? x,
//     JSString? y,
//   });

//   external JSString? get crv;

//   external JSString? get d;

//   external JSString? get dp;

//   external JSString? get dq;

//   external JSString? get e;

//   external JSBoolean get ext;

//   // ignore: non_constant_identifier_names
//   external JSArray<JSString> get key_ops;

//   external JSString get kty;

//   external JSString? get n;

//   external JSString? get p;

//   external JSString? get q;

//   external JSString? get qi;

//   external JSString? get x;

//   external JSString? get y;
// }

@JS()
@anonymous
external Pkdf2Params get pkdf2Params;
extension type Pkdf2Params._(JSObject _) implements JSObject {
  external factory Pkdf2Params({
    required JSString name,
    required JSString hash,
    required JSArrayBuffer salt,
    required JSNumber iterations,
  });
}

@JS()
@anonymous
external RsaHashedImportParams get rsaHashedImportParams;
extension type RsaHashedImportParams._(JSObject _) implements JSObject {
  external factory RsaHashedImportParams({required JSString name, required JSString hash});
}

@JS()
@anonymous
external RsaHashedKeyGenParams get rsaHashedKeyGenParams;
extension type RsaHashedKeyGenParams._(JSObject _) implements JSObject {
  external factory RsaHashedKeyGenParams({
    required JSString name,
    required JSNumber modulusLength,
    required JSAny? publicExponent,
    required JSString hash,
  });
}

@JS()
@anonymous
external RsaPssParams get rsaPssParams;
extension type RsaPssParams._(JSObject _) implements JSObject {
  external factory RsaPssParams({required JSString name, JSNumber? saltLength});
}

@JS()
@anonymous
external SignParams get signParams;
extension type SignParams._(JSObject _) implements JSObject {
  external factory SignParams({required JSString name});
}

@JS()
@anonymous
external VerifyParams get verifyParams;
extension type VerifyParams._(JSObject _) implements JSObject {
  external factory VerifyParams({required JSString name});
}
