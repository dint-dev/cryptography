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

class Pbkdf2Impl implements Pbkdf2 {
  @override
  final MacAlgorithm macAlgorithm;

  @override
  final int iterations;

  @override
  final int bits;

  const Pbkdf2Impl({
    @required this.macAlgorithm,
    @required this.iterations,
    @required this.bits,
  })  : assert(macAlgorithm != null),
        assert(iterations >= 1),
        assert(bits >= 64);

  @override
  Future<Uint8List> deriveBits(
    List<int> input, {
    @required Nonce nonce,
  }) async {
    ArgumentError.checkNotNull(nonce, 'nonce');
    ArgumentError.checkNotNull(bits, 'bits');
    ArgumentError.checkNotNull(iterations, 'iterations');
    final macAlgorithm = this.macAlgorithm;
    if (macAlgorithm is Hmac) {
      final webCryptoHashName = const <String, String>{
        'sha1': 'SHA-1',
        'sha256': 'SHA-256',
        'sha384': 'SHA-384',
        'sha512': 'SHA-512',
      }[macAlgorithm.hashAlgorithm.name];
      if (webCryptoHashName != null) {
        // importKey(...)
        final cryptoKey = await js.promiseToFuture<web_crypto.CryptoKey>(
          web_crypto.subtle.importKey(
            'raw',
            _jsArrayBufferFrom(input),
            'PBKDF2',
            false,
            ['deriveBits'],
          ),
        );

        // deriveBits(...)
        final byteBuffer = await js.promiseToFuture<ByteBuffer>(
          web_crypto.subtle.deriveBits(
            web_crypto.Pkdf2Params(
              name: 'PBKDF2',
              hash: webCryptoHashName,
              salt: _jsArrayBufferFrom(nonce.bytes),
              iterations: iterations,
            ),
            cryptoKey,
            bits,
          ),
        );

        return Uint8List.view(byteBuffer);
      }
    }

    return deriveBitsSync(
      input,
      nonce: nonce,
    );
  }

  @override
  Uint8List deriveBitsSync(
    List<int> input, {
    @required Nonce nonce,
  }) {
    return dart.Pbkdf2Impl(
      macAlgorithm: macAlgorithm,
      iterations: iterations,
      bits: bits,
    ).deriveBitsSync(
      input,
      nonce: nonce,
    );
  }
}
