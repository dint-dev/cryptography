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

List<int> _base64UrlDecode(String s) {
  switch (s.length % 4) {
    case 1:
      return base64Url.decode(s + '===');
    case 2:
      return base64Url.decode(s + '==');
    case 3:
      return base64Url.decode(s + '=');
    default:
      return base64Url.decode(s);
  }
}

String _base64UrlEncode(List<int> data) {
  var s = base64Url.encode(data);
  // Remove trailing '=' characters
  var length = s.length;
  while (s.startsWith('=', length - 1)) {
    length--;
  }
  return s.substring(0, length);
}

ByteBuffer _jsArrayBufferFrom(List<int> data) {
  // Avoid copying if possible
  if (data is Uint8List &&
      data.offsetInBytes == 0 &&
      data.lengthInBytes == data.buffer.lengthInBytes) {
    return data.buffer;
  }
  // Copy
  return Uint8List.fromList(data).buffer;
}

Future<KeyPair> _newWebEcKeyPair(String curve) {
  // Generate key
  final promise = web_crypto.subtle.generateKey(
    web_crypto.EcdhParams(
      name: 'ECDH',
      namedCurve: curve,
    ),
    true,
    ['deriveBits'],
  );
  return js
      .promiseToFuture<web_crypto.CryptoKeyPair>(promise)
      .then((cryptoKeyPair) async {
    final privateKeyJs = await js.promiseToFuture<web_crypto.Jwk>(
      web_crypto.subtle.exportKey('jwk', cryptoKeyPair.privateKey),
    );

    // Get public key.
    final publicByteBuffer = await js.promiseToFuture<ByteBuffer>(
      web_crypto.subtle.exportKey('raw', cryptoKeyPair.publicKey),
    );
    final publicKeyBytes = Uint8List.view(publicByteBuffer);

    return KeyPair(
      privateKey: JwkPrivateKey(
        d: _base64UrlDecode(privateKeyJs.d),
        x: _base64UrlDecode(privateKeyJs.x),
        y: _base64UrlDecode(privateKeyJs.y),
      ),
      publicKey: PublicKey(publicKeyBytes),
    );
  });
}
