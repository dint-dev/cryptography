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

class WebRsaPss extends WebRsaSignatureAlgorithm {
  WebRsaPss(HashAlgorithm hash)
      : assert(hash != null),
        super(hash);

  @override
  String get name => 'rsaPss';

  @override
  String get webCryptoName => 'RSA-PSS';

  @override
  Future<Signature> sign(List<int> input, KeyPair keyPair) async {
    final byteBuffer = await js.promiseToFuture(web_crypto.subtle.sign(
      web_crypto.RsaPssParams(
        name: 'RSA-PSS',
        saltLength: 32,
      ),
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
      web_crypto.RsaPssParams(
        name: 'RSA-PSS',
        saltLength: 32,
      ),
      await _getCryptoKeyFromPublicKey(signature.publicKey),
      _jsArrayBufferFrom(signature.bytes),
      _jsArrayBufferFrom(input),
    ));
  }
}
