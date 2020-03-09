// Copyright 2019 Gohilla Ltd (https://gohilla.com).
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

const _aesKeyGenerator = SecretKeyGenerator(
  validLengths: <int>{16, 24, 32},
  defaultLength: 32,
);

const _webCryptoUnavailableMessage =
    'Web Cryptograpy API is unavailable outside browser';

class WebAesCbcCipher extends Cipher {
  const WebAesCbcCipher();

  @override
  String get name => 'aesCbc';

  @override
  int get nonceLength => 16;

  @override
  SecretKeyGenerator get secretKeyGenerator => _aesKeyGenerator;

  @override
  Uint8List decryptSync(
    List<int> input, {
    @required SecretKey secretKey,
    int offset = 0,
    Nonce nonce,
  }) {
    throw UnsupportedError(_webCryptoUnavailableMessage);
  }

  @override
  Uint8List encryptSync(
    List<int> input, {
    @required SecretKey secretKey,
    int offset = 0,
    Nonce nonce,
  }) {
    throw UnsupportedError(_webCryptoUnavailableMessage);
  }
}

class WebAesCtrCipher extends Cipher {
  const WebAesCtrCipher();

  @override
  String get name => 'aesCtr';

  @override
  int get nonceLength => 16;

  @override
  SecretKeyGenerator get secretKeyGenerator => _aesKeyGenerator;

  @override
  Uint8List decryptSync(
    List<int> input, {
    @required SecretKey secretKey,
    int offset = 0,
    Nonce nonce,
  }) {
    throw UnsupportedError(_webCryptoUnavailableMessage);
  }

  @override
  Uint8List encryptSync(
    List<int> input, {
    @required SecretKey secretKey,
    int offset = 0,
    Nonce nonce,
  }) {
    throw UnsupportedError(_webCryptoUnavailableMessage);
  }
}

class WebAesGcmCipher extends Cipher {
  const WebAesGcmCipher();

  @override
  String get name => 'aesGcm';

  @override
  int get nonceLength => 16;

  @override
  SecretKeyGenerator get secretKeyGenerator => _aesKeyGenerator;

  @override
  Uint8List decryptSync(
    List<int> input, {
    @required SecretKey secretKey,
    int offset = 0,
    Nonce nonce,
  }) {
    throw UnsupportedError(_webCryptoUnavailableMessage);
  }

  @override
  Uint8List encryptSync(
    List<int> input, {
    @required SecretKey secretKey,
    int offset = 0,
    Nonce nonce,
  }) {
    throw UnsupportedError(_webCryptoUnavailableMessage);
  }
}

class WebEcdh extends KeyExchangeAlgorithm {
  @override
  final String name;
  final String webCryptoNamedCurve;
  @override
  final KeyPairGenerator keyPairGenerator;
  final KeyExchangeAlgorithm polyfill;

  const WebEcdh({
    @required this.name,
    @required this.webCryptoNamedCurve,
    @required this.keyPairGenerator,
    @required this.polyfill,
  });

  @override
  Future<SecretKey> sharedSecret(
      {PrivateKey localPrivateKey, PublicKey remotePublicKey}) {
    if (polyfill == null) {
      throw UnsupportedError('sharedSecretSync() is unsupported');
    }
    return polyfill.sharedSecret(
      localPrivateKey: localPrivateKey,
      remotePublicKey: remotePublicKey,
    );
  }

  @override
  SecretKey sharedSecretSync(
      {PrivateKey localPrivateKey, PublicKey remotePublicKey}) {
    if (polyfill == null) {
      throw UnsupportedError('sharedSecretSync() is unsupported');
    }
    return polyfill.sharedSecretSync(
      localPrivateKey: localPrivateKey,
      remotePublicKey: remotePublicKey,
    );
  }
}

class WebEcdsa extends SignatureAlgorithm {
  @override
  final String name;
  final String webCryptoNamedCurve;
  final String webCryptoHashName;
  @override
  final KeyPairGenerator keyPairGenerator;
  final SignatureAlgorithm polyfill;

  const WebEcdsa({
    @required this.name,
    @required this.webCryptoNamedCurve,
    @required this.webCryptoHashName,
    @required this.keyPairGenerator,
    @required this.polyfill,
  });

  @override
  Signature signSync(List<int> input, KeyPair keyPair) {
    if (polyfill == null) {
      throw UnsupportedError('sharedSecretSync() is unsupported');
    }
    return polyfill.signSync(input, keyPair);
  }

  @override
  bool verifySync(List<int> input, Signature signature) {
    if (polyfill == null) {
      throw UnsupportedError('sharedSecretSync() is unsupported');
    }
    return polyfill.verifySync(input, signature);
  }
}

class WebEcKeyPairGenerator extends KeyPairGenerator {
  @override
  final String name;
  final String webCryptoName;

  const WebEcKeyPairGenerator({
    @required this.name,
    @required this.webCryptoName,
  })  : assert(name != null),
        assert(webCryptoName != null);

  @override
  KeyPair generateSync() {
    throw UnsupportedError(_webCryptoUnavailableMessage);
  }
}

class WebHashAlgorithm extends HashAlgorithm {
  @override
  final String name;
  @override
  final int hashLengthInBytes;
  final String webCryptoName;

  final HashAlgorithm polyfill;

  const WebHashAlgorithm({
    @required this.name,
    @required this.hashLengthInBytes,
    @required this.webCryptoName,
    @required this.polyfill,
  }) : assert(webCryptoName != null);

  @override
  HashSink newSink() {
    if (polyfill == null) {
      throw UnsupportedError(_webCryptoUnavailableMessage);
    }
    return polyfill.newSink();
  }
}

class WebSignatureAlgorithm extends SignatureAlgorithm {
  @override
  final String name;
  final String webCryptoName;
  @override
  final KeyPairGenerator keyPairGenerator;
  final SignatureAlgorithm polyfill;

  const WebSignatureAlgorithm({
    @required this.name,
    @required this.webCryptoName,
    @required this.keyPairGenerator,
    @required this.polyfill,
  })  : assert(name != null),
        assert(webCryptoName != null);

  @override
  Future<Signature> sign(List<int> input, KeyPair keyPair) {
    if (polyfill == null) {
      throw UnsupportedError(_webCryptoUnavailableMessage);
    }
    return polyfill.sign(input, keyPair);
  }

  @override
  Signature signSync(List<int> input, KeyPair keyPair) {
    if (polyfill == null) {
      throw UnsupportedError(_webCryptoUnavailableMessage);
    }
    return polyfill.signSync(input, keyPair);
  }

  @override
  Future<bool> verify(List<int> input, Signature signature) {
    if (polyfill == null) {
      throw UnsupportedError(_webCryptoUnavailableMessage);
    }
    return polyfill.verify(input, signature);
  }

  @override
  bool verifySync(List<int> input, Signature signature) {
    if (polyfill == null) {
      throw UnsupportedError(_webCryptoUnavailableMessage);
    }
    return polyfill.verifySync(input, signature);
  }
}
