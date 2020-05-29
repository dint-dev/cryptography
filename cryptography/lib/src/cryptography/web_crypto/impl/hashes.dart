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

const HashAlgorithm webSha1 = _WebHash(
  'SHA-1',
  dart.dartSha1,
);

const HashAlgorithm webSha256 = _WebHash(
  'SHA-256',
  dart.dartSha256,

  // According to our benchmarks,
  // Dart implementation is about 2x faster for very short hashes.
  minLengthForWebCrypto: 0,
);

const HashAlgorithm webSha384 = _WebHash(
  'SHA-384',
  dart.dartSha384,
);

const HashAlgorithm webSha512 = _WebHash(
  'SHA-512',
  dart.dartSha512,
);

class _WebHash extends HashAlgorithm {
  final String webName;
  final HashAlgorithm dartImplementation;
  final int minLengthForWebCrypto;

  const _WebHash(this.webName, this.dartImplementation,
      {this.minLengthForWebCrypto = 0})
      : assert(webName != null),
        assert(dartImplementation != null);

  @override
  int get blockLengthInBytes => dartImplementation.blockLengthInBytes;

  @override
  int get hashLengthInBytes => dartImplementation.hashLengthInBytes;

  @override
  String get name => dartImplementation.name;

  @override
  Future<SecretKey> newHashKey() async {
    final jsCryptoKey = await js
        .promiseToFuture<web_crypto.CryptoKey>(web_crypto.subtle.generateKey(
      web_crypto.HmacKeyGenParams(
        name: 'HMAC',
        hash: webName,
      ),
      true,
      ['sign', 'verify'],
    ));

    final jsRaw = await js.promiseToFuture<ByteBuffer>(
        web_crypto.subtle.exportKey('raw', jsCryptoKey));

    return SecretKey(jsRaw.asUint8List());
  }

  @override
  Future<Hash> hash(List<int> bytes) async {
    ArgumentError.checkNotNull(bytes);
    if (bytes.length < minLengthForWebCrypto) {
      return dartImplementation.hash(bytes);
    }
    final subtle = web_crypto.subtle;
    if (subtle == null) {
      // Very old browser.
      // All major browsers added support around 2013.
      return dartImplementation.hash(bytes);
    }
    final byteBuffer = await js.promiseToFuture<ByteBuffer>(
      subtle.digest(webName, _jsArrayBufferFrom(bytes)),
    );
    return Hash(Uint8List.view(byteBuffer));
  }

  @override
  Hash hashSync(List<int> data) {
    return dartImplementation.hashSync(data);
  }

  @override
  HashSink newSink() => dartImplementation.newSink();
}
