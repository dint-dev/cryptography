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

class WebRsaSsaPkcs1v15 extends WebRsaSignatureAlgorithm {
  @override
  String get name => 'rsaSsaPkcs1v15';

  @override
  String get webCryptoName => 'RSASSA-PKCS1-v1_5';

  WebRsaSsaPkcs1v15(HashAlgorithm hashAlgorithm) : super(hashAlgorithm);

  @override
  Future<Signature> sign(List<int> input, KeyPair keyPair) async {
    final byteBuffer = await js.promiseToFuture(web_crypto.subtle.sign(
      'RSASSA-PKCS1-v1_5',
      await _getCryptoKeyFromPrivateKey(keyPair.privateKey),
      _jsArrayBufferFrom(input),
    ));
    return Signature(
      Uint8List.view(byteBuffer),
      publicKey: keyPair.publicKey,
    );
  }

  @override
  Future<bool> verify(List<int> input, Signature signature) async {
    return js.promiseToFuture<bool>(web_crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5',
      await _getCryptoKeyFromPublicKey(signature.publicKey),
      _jsArrayBufferFrom(signature.bytes),
      _jsArrayBufferFrom(input),
    ));
  }
}
