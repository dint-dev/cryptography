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

const Cipher webAesCbc = _WebAesCbcCipher();

class _WebAesCbcCipher extends _WebAesCipher {
  const _WebAesCbcCipher();

  @override
  Cipher get dartImplementation => dart.dartAesCbc;

  @override
  String get webName => 'AES-CBC';

  @override
  Future<Uint8List> _decrypt(
    List<int> input, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    @required List<int> aad,
  }) async {
    final byteBuffer = await js.promiseToFuture<ByteBuffer>(
      web_crypto.subtle.decrypt(
        web_crypto.AesCbcParams(
          name: 'AES-CBC',
          iv: _jsArrayBufferFrom(nonce.bytes),
        ),
        await _getCryptoKey(secretKey, 'AES-CBC'),
        _jsArrayBufferFrom(input),
      ),
    );
    return Uint8List.view(byteBuffer);
  }

  @override
  Future<Uint8List> _encrypt(
    List<int> input, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    @required List<int> aad,
  }) async {
    final byteBuffer = await js.promiseToFuture<ByteBuffer>(
      web_crypto.subtle.encrypt(
        web_crypto.AesCbcParams(
          name: 'AES-CBC',
          iv: _jsArrayBufferFrom(nonce.bytes),
        ),
        await _getCryptoKey(secretKey, 'AES-CBC'),
        _jsArrayBufferFrom(input),
      ),
    );
    return Uint8List.view(byteBuffer);
  }
}
