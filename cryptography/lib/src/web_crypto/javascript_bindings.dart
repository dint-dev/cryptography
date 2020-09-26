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

@JS()
library web_crypto_api;

import 'dart:typed_data';

import 'package:js/js.dart';
import 'package:meta/meta.dart';

@JS()
@anonymous
class AesCbcParams {
  external factory AesCbcParams({
    @required String name,
    @required ByteBuffer iv,
  });
}

@JS()
@anonymous
class AesCtrParams {
  external factory AesCtrParams({
    @required String name,
    @required ByteBuffer counter,
    @required int length,
  });
}

@JS()
@anonymous
class AesGcmParams {
  external factory AesGcmParams({
    @required String name,
    @required ByteBuffer iv,
    ByteBuffer additionalData,
    @required int tagLength,
  });
}

@JS()
@anonymous
class AesKeyGenParams {
  external factory AesKeyGenParams({
    @required String name,
    @required int length,
  });
}

@JS('CryptoKey')
class CryptoKey {
  external factory CryptoKey._();
  external dynamic get algorithm;
  external bool get extractable;
  external String get type;
  external List<String> get usages;
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
    @required String name,
    @required CryptoKey public,
  });
}

@JS()
@anonymous
class EcdhParams {
  external factory EcdhParams({
    @required String name,
    @required String namedCurve,
  });
}

@JS()
@anonymous
class EcdsaParams {
  external factory EcdsaParams({
    @required String name,
    @required String hash,
  });
}

@JS()
@anonymous
class EcKeyImportParams {
  external factory EcKeyImportParams({
    @required String name,
    @required String namedCurve,
  });
}

@JS()
@anonymous
class HkdfParams {
  external factory HkdfParams({
    @required String name,
    @required String hash,
    @required ByteBuffer salt,
    @required ByteBuffer info,
  });
}

@JS()
@anonymous
class HmacImportParams {
  external factory HmacImportParams({
    @required String name,
    @required String hash,
    int length,
  });
}

@JS()
@anonymous
class HmacKeyGenParams {
  external factory HmacKeyGenParams({
    @required String name,
    @required String hash,
    @required int length,
  });
}

@JS()
@anonymous
class Jwk {
  external factory Jwk({
    String crv,
    String n,
    String e,
    String d,
    String p,
    String q,
    String dp,
    String dq,
    String qi,
    bool ext,
    List<String> key_ops,
    @required String kty,
    String x,
    String y,
  });
  external String get crv;
  external String get d;
  external String get dp;
  external String get dq;
  external String get e;
  external bool get ext;
  external List<String> get key_ops;
  external String get kty;
  external String get n;
  external String get p;
  external String get q;
  external String get qi;
  external String get x;
  external String get y;
}

@JS()
@anonymous
class Pkdf2Params {
  external factory Pkdf2Params({
    @required String name,
    @required String hash,
    @required ByteBuffer salt,
    @required int iterations,
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
    @required String name,
    @required String hash,
  });
}

@JS()
@anonymous
class RsaHashedKeyGenParams {
  external factory RsaHashedKeyGenParams({
    @required String name,
    @required int modulusLength,
    @required dynamic publicExponent,
    @required String hash,
  });
}

@JS()
@anonymous
class RsaPssParams {
  external factory RsaPssParams({
    @required String name,
    int saltLength,
  });
}

@JS()
@anonymous
class SignParams {
  external factory SignParams({
    @required String name,
  });
}

@JS('crypto.subtle.decrypt')
external Promise<ByteBuffer> decrypt(
  dynamic algorithm,
  CryptoKey key,
  ByteBuffer data,
);

@JS('crypto.subtle.deriveBits')
external Promise deriveBits(
  dynamic algorithm,
  CryptoKey cryptoKey,
  int bits,
);

@JS('crypto.subtle.deriveKey')
external Promise deriveKey(
  dynamic algorithm,
  CryptoKey baseKey,
  dynamic derivedKeyAlgorithm,
  dynamic extractable,
  List<String> keyUsages,
);

@JS('crypto.subtle.digest')
external Promise<ByteBuffer> digest(
  String name,
  ByteBuffer data,
);

@JS('crypto.subtle.encrypt')
external Promise<ByteBuffer> encrypt(
  dynamic algorithm,
  CryptoKey key,
  ByteBuffer data,
);

@JS('crypto.subtle.exportKey')
external Promise<CryptoKey> exportKey(
  String format,
  CryptoKey key,
);

@JS('crypto.subtle.generateKey')
external Promise<dynamic> generateKey(
  Object algorithm,
  bool extractable,
  List<String> keyUsages,
);

@JS('crypto.subtle.importKey')
external Promise<CryptoKey> importKey(
  String format,
  dynamic keyData,
  dynamic algorithm,
  bool extractable,
  List<String> keyUsages,
);

@JS('crypto.subtle.sign')
external Promise<ByteBuffer> sign(
  dynamic algorithm,
  CryptoKey key,
  ByteBuffer data,
);

@JS('crypto.subtle.unwrap')
external Promise<bool> unwrap(
  String format,
  ByteBuffer wrappedKey,
  ByteBuffer data,
);

@JS('crypto.subtle.verify')
external Promise<bool> verify(
  dynamic algorithm,
  CryptoKey key,
  ByteBuffer signature,
  ByteBuffer data,
);

@JS('crypto.subtle.wrap')
external Promise<bool> wrap(
  String format,
  ByteBuffer wrappedKey,
  ByteBuffer data,
);

@JS()
@anonymous
class VerifyParams {
  external factory VerifyParams({
    @required String name,
  });
}
