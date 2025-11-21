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
import 'dart:js_interop';
import 'dart:typed_data';

import 'package:meta/meta.dart';

/// Note that browsers support Web Cryptography only in secure contexts.
@internal
final bool isWebCryptoAvailable =
    _subtle.isDefinedAndNotNull && _isSecureContext.toDart;

@JS('window.isSecureContext')
external JSBoolean get _isSecureContext;

@JS('crypto.subtle')
external JSAny get _subtle;

@internal
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

@internal
Uint8List? base64UrlDecodeMaybe(String? s) {
  return s == null ? null : base64UrlDecode(s);
}

@internal
String base64UrlEncode(List<int> data) {
  var s = base64Url.encode(data);
  // Remove trailing '=' characters
  var length = s.length;
  while (s.startsWith('=', length - 1)) {
    length--;
  }
  return s.substring(0, length);
}

@internal
String? base64UrlEncodeMaybe(List<int>? data) {
  if (data == null) {
    return null;
  }
  return base64UrlEncode(data);
}

@internal
Future<ByteBuffer> decrypt(
  JSAny algorithm,
  CryptoKey key,
  JSUint8Array data,
) async {
  final js = await _decrypt(algorithm, key, data).toDart;
  return js.toDart;
}

@internal
Future<Uint8List> deriveBits(
  JSAny algorithm,
  CryptoKey cryptoKey,
  JSNumber bits,
) async {
  final js = await _deriveBits(algorithm, cryptoKey, bits).toDart;
  return js.toDart.asUint8List();
}

@internal
Future<CryptoKey> deriveKey(
  JSObject algorithm,
  CryptoKey baseKey,
  JSObject derivedKeyAlgorithm,
  JSBoolean extractable,
  JSArray<JSString> keyUsages,
) async {
  final js = await _deriveKey(
    algorithm,
    baseKey,
    derivedKeyAlgorithm,
    extractable,
    keyUsages,
  ).toDart;
  return js;
}

@internal
Future<ByteBuffer> digest(
  String name,
  JSUint8Array data,
) async {
  final js = await _digest(name.toJS, data).toDart;
  return js.toDart;
}

@internal
Future<ByteBuffer> encrypt(
  JSAny algorithm,
  CryptoKey key,
  JSUint8Array data,
) async {
  final js = await _encrypt(algorithm, key, data).toDart;
  return js.toDart;
}

@internal
Future<Jwk> exportKeyWhenJwk(CryptoKey key) async {
  final js = await _exportKey('jwk'.toJS, key).toDart;
  return js as Jwk;
}

@internal
Future<Uint8List> exportKeyWhenRaw(CryptoKey key) async {
  final js = await _exportKey('raw'.toJS, key).toDart;
  return (js as JSArrayBuffer).toDart.asUint8List();
}

@internal
Future<CryptoKey> generateKeyWhenKey(
  JSAny algorithm,
  JSBoolean extractable,
  JSArray<JSString> keyUsages,
) async {
  final js = await _generateKey(algorithm, extractable, keyUsages).toDart;
  return js as CryptoKey;
}

@internal
Future<CryptoKeyPair> generateKeyWhenKeyPair(
  JSObject algorithm,
  JSBoolean extractable,
  JSArray<JSString> keyUsages,
) async {
  final js = await _generateKey(algorithm, extractable, keyUsages).toDart;
  return js as CryptoKeyPair;
}

@internal
Future<CryptoKey> importKeyWhenJwk(
  Jwk keyData,
  JSAny algorithm,
  JSBoolean extractable,
  JSArray<JSString> keyUsages,
) async {
  final js = await _importKey(
    'jwk'.toJS,
    keyData.jsObject,
    algorithm,
    extractable,
    keyUsages,
  ).toDart;
  return js;
}

@internal
Future<CryptoKey> importKeyWhenRaw(
  JSUint8Array keyData,
  JSAny algorithm,
  JSBoolean extractable,
  JSArray<JSString> keyUsages,
) async {
  final js = await _importKey(
    'raw'.toJS,
    keyData,
    algorithm,
    extractable,
    keyUsages,
  ).toDart;
  return js;
}

@internal
JSUint8Array jsUint8ListFrom(List<int> data) {
  if (data is Uint8List) {
    return data.toJS;
  }
  return Uint8List.fromList(data).toJS;
}

@internal
Future<Uint8List> sign(
  JSAny algorithm,
  CryptoKey key,
  JSUint8Array data,
) async {
  final js = await _sign(algorithm, key, data).toDart;
  return js.toDart.asUint8List();
}

@internal
Future<bool> verify(
  JSAny algorithm,
  CryptoKey key,
  JSUint8Array signature,
  JSUint8Array data,
) async {
  final js = await _verify(algorithm, key, signature, data).toDart;
  return js.toDart;
}

@JS('crypto.subtle.decrypt')
external JSPromise<JSArrayBuffer> _decrypt(
  JSAny algorithm,
  CryptoKey key,
  JSUint8Array data,
);

@JS('crypto.subtle.deriveBits')
external JSPromise<JSArrayBuffer> _deriveBits(
  JSAny algorithm,
  CryptoKey cryptoKey,
  JSNumber bits,
);

@JS('crypto.subtle.deriveKey')
external JSPromise<CryptoKey> _deriveKey(
  JSAny algorithm,
  CryptoKey baseKey,
  JSAny derivedKeyAlgorithm,
  JSBoolean extractable,
  JSArray<JSString> keyUsages,
);

@JS('crypto.subtle.digest')
external JSPromise<JSArrayBuffer> _digest(
  JSString name,
  JSUint8Array data,
);

@JS('crypto.subtle.encrypt')
external JSPromise<JSArrayBuffer> _encrypt(
  JSAny algorithm,
  CryptoKey key,
  JSUint8Array data,
);

@JS('crypto.subtle.exportKey')
external JSPromise _exportKey(
  JSString format,
  CryptoKey key,
);

@JS('crypto.subtle.generateKey')
external JSPromise _generateKey(
  JSAny algorithm,
  JSBoolean extractable,
  JSArray<JSString> keyUsages,
);

@JS('crypto.subtle.importKey')
external JSPromise<CryptoKey> _importKey(
  JSString format,
  JSAny keyData,
  JSAny algorithm,
  JSBoolean extractable,
  JSArray<JSString> keyUsages,
);

@JS('crypto.subtle.sign')
external JSPromise<JSArrayBuffer> _sign(
  JSAny algorithm,
  CryptoKey key,
  JSUint8Array data,
);

@JS('crypto.subtle.verify')
external JSPromise<JSBoolean> _verify(
  JSAny algorithm,
  CryptoKey key,
  JSUint8Array signature,
  JSUint8Array data,
);

@internal
extension type AesCbcParams._(JSObject jsObject) {
  external factory AesCbcParams({
    required JSString name,
    required JSUint8Array iv,
  });
}

@internal
extension type AesCtrParams._(JSObject jsObject) {
  external factory AesCtrParams({
    required JSString name,
    required JSUint8Array counter,
    required JSNumber length,
  });
}

@internal
extension type AesGcmParams._(JSObject jsObject) {
  external factory AesGcmParams({
    required JSString name,
    required JSUint8Array iv,
    JSUint8Array? additionalData,
    required JSNumber tagLength,
  });
}

@internal
extension type AesKeyGenParams._(JSObject jsObject) {
  external factory AesKeyGenParams({
    required JSString name,
    required JSNumber length,
  });
}

@internal
extension type AlgorithmNameParams._(JSObject jsObject) {
  external factory AlgorithmNameParams({
    required JSString name,
  });
}

@internal
extension type CryptoKey._(JSObject _) implements JSObject {
  external JSObject get algorithm;

  external bool get extractable;

  external JSAny get type;

  external JSObject get usages;
}

@internal
extension type CryptoKeyPair._(JSObject jsObject) {
  external CryptoKey get privateKey;

  external CryptoKey get publicKey;
}

@internal
extension type DeriveParamsWhenPublicKey._(JSObject jsObject) {
  external factory DeriveParamsWhenPublicKey({
    required JSString name,
    required CryptoKey public,
  });
}

@internal
extension type EcdhParams._(JSObject jsObject) {
  external factory EcdhParams({
    required JSString name,
    required JSString namedCurve,
  });
}

@internal
extension type EcdsaParams._(JSObject jsObject) {
  external factory EcdsaParams({
    required JSString name,
    required JSString hash,
  });
}

@internal
extension type EcKeyGenParams._(JSObject jsObject) {
  external factory EcKeyGenParams({
    required JSString name,
    required JSString namedCurve,
  });
}

@internal
extension type EcKeyImportParams._(JSObject jsObject) {
  external factory EcKeyImportParams({
    required JSString name,
    required JSString namedCurve,
  });
}

@internal
extension type HkdfParams._(JSObject jsObject) {
  external factory HkdfParams({
    required JSString name,
    required JSString hash,
    required JSUint8Array salt,
    required JSUint8Array info,
  });
}

@internal
extension type HmacImportParams._(JSObject jsObject) {
  external factory HmacImportParams({
    required JSString name,
    required JSString hash,
    JSNumber? length,
  });
}

@internal
extension type HmacKeyGenParams._(JSObject jsObject) {
  external factory HmacKeyGenParams({
    required JSString name,
    required JSString hash,
    required JSNumber length,
  });
}

@internal
extension type Jwk._(JSObject jsObject) {
  external factory Jwk({
    JSString? crv,
    JSString? n,
    JSString? e,
    JSString? d,
    JSString? p,
    JSString? q,
    JSString? dp,
    JSString? dq,
    JSString? qi,
    JSBoolean? ext,
    // ignore: non_constant_identifier_names
    JSArray<JSString>? key_ops,
    required JSString kty,
    JSString? x,
    JSString? y,
  });

  external JSString? get crv;

  external JSString? get d;

  external JSString? get dp;

  external JSString? get dq;

  external JSString? get e;

  external JSBoolean get ext;

  // ignore: non_constant_identifier_names
  external JSArray<JSString> get key_ops;

  external JSString get kty;

  external JSString? get n;

  external JSString? get p;

  external JSString? get q;

  external JSString? get qi;

  external JSString? get x;

  external JSString? get y;
}

@internal
extension type Pkdf2Params._(JSObject jsObject) {
  external factory Pkdf2Params({
    required JSString name,
    required JSString hash,
    required JSUint8Array salt,
    required JSNumber iterations,
  });
}

@internal
extension type RsaHashedImportParams._(JSObject jsObject) {
  external factory RsaHashedImportParams({
    required JSString name,
    required JSString hash,
  });
}

@internal
extension type RsaHashedKeyGenParams._(JSObject jsObject) {
  external factory RsaHashedKeyGenParams({
    required JSString name,
    required JSNumber modulusLength,
    required JSUint8Array publicExponent,
    required JSString hash,
  });
}

@internal
extension type RsaPssParams._(JSObject jsObject) {
  external factory RsaPssParams({
    required JSString name,
    JSNumber? saltLength,
  });
}

@internal
extension type SignParams._(JSObject jsObject) {
  external factory SignParams({
    required JSString name,
  });
}

@internal
extension type VerifyParams._(JSObject jsObject) {
  external factory VerifyParams({
    required JSString name,
  });
}
