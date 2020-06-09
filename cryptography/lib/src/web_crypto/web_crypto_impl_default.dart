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

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:meta/meta.dart';

bool get isWebCryptoSupported => false;

Future<Uint8List> aesCbcDecrypt(
  List<int> input, {
  @required SecretKey secretKey,
  @required Nonce nonce,
}) {
  throw UnimplementedError();
}

Future<Uint8List> aesCbcEncrypt(
  List<int> input, {
  @required SecretKey secretKey,
  @required Nonce nonce,
}) {
  throw UnimplementedError();
}

Future<Uint8List> aesCtrDecrypt(
  List<int> input, {
  @required SecretKey secretKey,
  @required Nonce nonce,
}) {
  throw UnimplementedError();
}

Future<Uint8List> aesCtrEncrypt(
  List<int> input, {
  @required SecretKey secretKey,
  @required Nonce nonce,
}) {
  throw UnimplementedError();
}

Future<Uint8List> aesGcmDecrypt(
  List<int> input, {
  @required SecretKey secretKey,
  @required Nonce nonce,
  List<int> aad,
}) {
  throw UnimplementedError();
}

Future<Uint8List> aesGcmEncrypt(
  List<int> input, {
  @required SecretKey secretKey,
  @required Nonce nonce,
  List<int> aad,
}) {
  throw UnimplementedError();
}

Future<SecretKey> aesNewSecretKey({
  @required String name,
  @required int bits,
}) {
  throw UnimplementedError();
}

Future<KeyPair> ecdhNewKeyPair({@required String curve}) {
  throw UnimplementedError();
}

Future<SecretKey> ecdhSharedSecret({
  @required PrivateKey localPrivateKey,
  @required PublicKey remotePublicKey,
  @required String curve,
}) {
  throw UnimplementedError();
}

Future<KeyPair> ecdsaNewKeyPair({@required String curve}) {
  throw UnimplementedError();
}

Future<Signature> ecdsaSign(
  List<int> input,
  KeyPair keyPair, {
  @required String namedCurve,
  @required String hashName,
}) {
  throw UnimplementedError();
}

Future<bool> ecdsaVerify(
  List<int> input,
  Signature signature, {
  @required String namedCurve,
  @required String hashName,
}) {
  throw UnimplementedError();
}

Future<Hash> hash(List<int> bytes, String name) {
  throw UnimplementedError();
}

Future<List<int>> hkdf(
  List<int> bytes, {
  @required String hashName,
  @required List<int> salt,
  @required List<int> info,
  @required int bits,
}) {
  throw UnimplementedError();
}

Future<Mac> hmac(
  List<int> bytes, {
  @required SecretKey secretKey,
  @required String hashName,
}) {
  throw UnimplementedError();
}

Future<Uint8List> pbkdf2(
  List<int> input, {
  @required String hashName,
  @required int bits,
  @required int iterations,
  @required Nonce nonce,
}) {
  throw UnimplementedError();
}

@override
Future<KeyPair> rsaNewKeyPairForSigning({
  @required String name,
  @required int modulusLength,
  @required List<int> publicExponent,
  @required String hashName,
}) {
  throw UnimplementedError();
}

Future<Signature> rsaPssSign(
  List<int> input,
  KeyPair keyPair, {
  @required int saltLength,
  @required String hashName,
}) {
  throw UnimplementedError();
}

Future<bool> rsaPssVerify(
  List<int> input,
  Signature signature, {
  @required int saltLength,
  @required String hashName,
}) {
  throw UnimplementedError();
}

Future<Signature> rsaSsaPkcs1v15Sign(
  List<int> input,
  KeyPair keyPair, {
  @required String hashName,
}) {
  throw UnimplementedError();
}

Future<bool> rsaSsaPkcs1v15Verify(
  List<int> input,
  Signature signature, {
  @required String hashName,
}) {
  throw UnimplementedError();
}
