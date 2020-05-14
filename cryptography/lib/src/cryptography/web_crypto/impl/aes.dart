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

const Cipher webAesCtr = _WebAesCtrCipher();

const Cipher webAesGcm = _WebAesGcmCipher();

class _WebAesCbcCipher extends _WebAesCipher {
  const _WebAesCbcCipher();

  @override
  Cipher get dartImplementation => dart.dartAesCbc;

  @override
  Future<Uint8List> _decrypt(
    List<int> input, {
    @required SecretKey secretKey,
    @required Nonce nonce,
  }) async {
    final secretKeyBytes = secretKey.extractSync();
    final cryptoKey = await js.promiseToFuture<web_crypto.CryptoKey>(
      web_crypto.subtle.importKey(
        'raw',
        _jsArrayBufferFrom(secretKeyBytes),
        web_crypto.AesKeyGenParams(
          name: 'AES-CBC',
          length: 8 * secretKeyBytes.length,
        ),
        true,
        ['decrypt'],
      ),
    );
    final byteBuffer = await js.promiseToFuture<ByteBuffer>(
      web_crypto.subtle.decrypt(
        web_crypto.AesCbcParams(
          name: 'AES-CBC',
          iv: _jsArrayBufferFrom(nonce.bytes),
        ),
        cryptoKey,
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
  }) async {
    final secretKeyBytes = secretKey.extractSync();
    final cryptoKey = await js.promiseToFuture<web_crypto.CryptoKey>(
      web_crypto.subtle.importKey(
        'raw',
        _jsArrayBufferFrom(secretKeyBytes),
        web_crypto.AesKeyGenParams(
          name: 'AES-CBC',
          length: 8 * secretKeyBytes.length,
        ),
        true,
        ['encrypt'],
      ),
    );
    final byteBuffer = await js.promiseToFuture<ByteBuffer>(
      web_crypto.subtle.encrypt(
        web_crypto.AesCbcParams(
          name: 'AES-CBC',
          iv: _jsArrayBufferFrom(nonce.bytes),
        ),
        cryptoKey,
        _jsArrayBufferFrom(input),
      ),
    );
    return Uint8List.view(byteBuffer);
  }
}

abstract class _WebAesCipher extends Cipher {
  const _WebAesCipher();

  Cipher get dartImplementation;

  @override
  bool get isAuthenticated => dartImplementation.isAuthenticated;

  @override
  String get name => dartImplementation.name;

  @override
  int get nonceLength => dartImplementation.nonceLength;

  @override
  int get secretKeyLength => dartImplementation.secretKeyLength;

  @override
  Set<int> get secretKeyValidLengths =>
      dartImplementation.secretKeyValidLengths;

  @override
  Future<Uint8List> decrypt(
    List<int> input, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) async {
    _checkNonce(nonce);
    _checkAad(aad);
    _checkKeyStreamIndexZero(keyStreamIndex);
    return _decrypt(
      input,
      secretKey: secretKey,
      nonce: nonce,
    );
  }

  @override
  List<int> decryptSync(
    List<int> input, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) {
    return dartImplementation.decryptSync(
      input,
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
      keyStreamIndex: keyStreamIndex,
    );
  }

  @override
  Future<Uint8List> encrypt(
    List<int> input, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) async {
    _checkNonce(nonce);
    _checkAad(aad);
    _checkKeyStreamIndexZero(keyStreamIndex);
    return _encrypt(
      input,
      secretKey: secretKey,
      nonce: nonce,
    );
  }

  @override
  List<int> encryptSync(
    List<int> input, {
    @required SecretKey secretKey,
    @required Nonce nonce,
    List<int> aad,
    int keyStreamIndex = 0,
  }) {
    return dartImplementation.encryptSync(
      input,
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
      keyStreamIndex: keyStreamIndex,
    );
  }

  void _checkAad(List<int> aad) {
    if (aad != null) {
      throw ArgumentError.value(
        aad,
        'aad',
        'Must be null',
      );
    }
  }

  void _checkKeyStreamIndexZero(int keyStreamIndex) {
    if (keyStreamIndex != 0) {
      throw ArgumentError.value(
        keyStreamIndex,
        'keyStreamIndex',
        'Must be 0',
      );
    }
  }

  void _checkNonce(Nonce nonce) {
    if (nonce == null) {
      throw ArgumentError.notNull('nonce');
    }
    if (nonce.bytes.length < 8 || nonce.bytes.length > 16) {
      throw ArgumentError.value(
        nonce,
        'nonce',
        'Invalid nonce length: ${nonce.bytes} bytes',
      );
    }
  }

  Future<Uint8List> _decrypt(
    List<int> input, {
    @required SecretKey secretKey,
    @required Nonce nonce,
  });

  Future<Uint8List> _encrypt(
    List<int> input, {
    @required SecretKey secretKey,
    @required Nonce nonce,
  });
}

class _WebAesCtrCipher extends _WebAesCipher {
  const _WebAesCtrCipher();

  @override
  Cipher get dartImplementation => dart.dartAesCtr;

  @override
  Future<Uint8List> _decrypt(
    List<int> input, {
    @required SecretKey secretKey,
    @required Nonce nonce,
  }) async {
    final secretKeyBytes = secretKey.extractSync();
    final cryptoKey = await js.promiseToFuture<web_crypto.CryptoKey>(
      web_crypto.subtle.importKey(
        'raw',
        _jsArrayBufferFrom(secretKeyBytes),
        web_crypto.AesKeyGenParams(
          name: 'AES-CTR',
          length: 8 * secretKeyBytes.length,
        ),
        true,
        ['decrypt'],
      ),
    );
    var counterBytes = Uint8List(16);
    counterBytes.setAll(0, nonce.bytes);
    final byteBuffer = await js.promiseToFuture<ByteBuffer>(
      web_crypto.subtle.decrypt(
        web_crypto.AesCtrParams(
          name: 'AES-CTR',
          counter: counterBytes.buffer,
          length: 64,
        ),
        cryptoKey,
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
  }) async {
    final secretKeyBytes = secretKey.extractSync();
    final cryptoKey = await js.promiseToFuture<web_crypto.CryptoKey>(
      web_crypto.subtle.importKey(
        'raw',
        _jsArrayBufferFrom(secretKeyBytes),
        web_crypto.AesKeyGenParams(
          name: 'AES-CTR',
          length: 8 * secretKeyBytes.length,
        ),
        true,
        ['encrypt'],
      ),
    );
    var counterBytes = Uint8List(16);
    counterBytes.setAll(0, nonce.bytes);
    final byteBuffer = await js.promiseToFuture<ByteBuffer>(
      web_crypto.subtle.encrypt(
        web_crypto.AesCtrParams(
          name: 'AES-CTR',
          counter: counterBytes.buffer,
          length: 64,
        ),
        cryptoKey,
        _jsArrayBufferFrom(input),
      ),
    );
    return Uint8List.view(byteBuffer);
  }
}

class _WebAesGcmCipher extends _WebAesCipher {
  const _WebAesGcmCipher();

  @override
  Cipher get dartImplementation => dart.dartAesGcm;

  @override
  Future<Uint8List> _decrypt(
    List<int> input, {
    @required SecretKey secretKey,
    @required Nonce nonce,
  }) async {
    final secretKeyBytes = secretKey.extractSync();
    final cryptoKey = await js.promiseToFuture<web_crypto.CryptoKey>(
      web_crypto.subtle.importKey(
        'raw',
        _jsArrayBufferFrom(secretKeyBytes),
        web_crypto.AesKeyGenParams(
          name: 'AES-GCM',
          length: 8 * secretKeyBytes.length,
        ),
        true,
        ['decrypt'],
      ),
    );
    final byteBuffer = await js.promiseToFuture<ByteBuffer>(
      web_crypto.subtle.decrypt(
        web_crypto.AesGcmParams(
          name: 'AES-GCM',
          arrayBuffer: null,
          tagLength: 128,
          iv: _jsArrayBufferFrom(nonce.bytes),
        ),
        cryptoKey,
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
  }) async {
    final secretKeyBytes = secretKey.extractSync();
    final cryptoKey = await js.promiseToFuture<web_crypto.CryptoKey>(
      web_crypto.subtle.importKey(
        'raw',
        _jsArrayBufferFrom(secretKeyBytes),
        web_crypto.AesKeyGenParams(
          name: 'AES-GCM',
          length: 8 * secretKeyBytes.length,
        ),
        true,
        ['encrypt'],
      ),
    );
    final byteBuffer = await js.promiseToFuture<ByteBuffer>(
      web_crypto.subtle.encrypt(
        web_crypto.AesGcmParams(
          name: 'AES-GCM',
          arrayBuffer: null,
          tagLength: 128,
          iv: _jsArrayBufferFrom(nonce.bytes),
        ),
        cryptoKey,
        _jsArrayBufferFrom(input),
      ),
    );
    return Uint8List.view(byteBuffer);
  }
}
