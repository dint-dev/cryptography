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
external Crypto get crypto;

Subtle get subtle => crypto.subtle;

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
    @required ByteBuffer arrayBuffer,
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

@JS()
class Crypto {
  external factory Crypto._();
  external Subtle get subtle;
}

@JS()
class CryptoKey {
  external factory CryptoKey._();
  external dynamic get algorithm;
  external bool get extractable;
  external String get type;
  external List<String> get usages;
}

@JS()
class CryptoKeyPair {
  external factory CryptoKeyPair._();
  external CryptoKey get privateKey;
  external CryptoKey get publicKey;
}

@JS()
class Digest {
  external factory Digest._();
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
    String d,
    bool ext,
    List<String> key_ops,
    String kty,
    String x,
    String y,
  });
  external String get crv;
  external String get d;
  external bool get ext;
  external List<String> get key_ops;
  external String get kty;
  external String get x;
  external String get y;
}

@JS()
class KeyPair {
  external factory KeyPair._();
}

@JS()
class Promise<T> {
  external factory Promise._();
}

@JS()
class Signature {
  external factory Signature._();
}

@JS()
class Subtle {
  external factory Subtle._();

  external Promise<ByteBuffer> decrypt(
    dynamic algorithm,
    CryptoKey key,
    ByteBuffer data,
  );

  external Promise deriveBits(
    dynamic algorithm,
    CryptoKey cryptoKey,
    int bits,
  );

  external Promise deriveKey(
    dynamic algorithm,
    CryptoKey baseKey,
    dynamic derivedKeyAlgorithm,
    dynamic extractable,
    List<String> keyUsages,
  );

  external Promise<Digest> digest(
    String name,
    ByteBuffer data,
  );

  external Promise<ByteBuffer> encrypt(
    dynamic algorithm,
    CryptoKey key,
    ByteBuffer data,
  );

  external Promise<Signature> exportKey(
    String format,
    CryptoKey key,
  );

  external Promise<dynamic> generateKey(
    Object algorithm,
    bool extractable,
    List<String> keyUsages,
  );

  external Promise<Signature> importKey(
    String format,
    dynamic keyData,
    dynamic algorithm,
    bool extractable,
    List<String> keyUsages,
  );

  external Promise<Signature> sign(
    dynamic algorithm,
    CryptoKey key,
    ByteBuffer data,
  );

  external Promise<bool> unwrap(
    String format,
    ByteBuffer wrappedKey,
    ByteBuffer data,
  );

  external Promise<bool> verify(
    dynamic algorithm,
    CryptoKey key,
    ByteBuffer signature,
    ByteBuffer data,
  );

  external Promise<bool> wrap(
    String format,
    ByteBuffer wrappedKey,
    ByteBuffer data,
  );
}
