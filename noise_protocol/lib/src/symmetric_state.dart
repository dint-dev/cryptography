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

part of noise_protocol;

/// _SymmetricState_ in the [specification](https://noiseprotocol.org/noise.html).
@visibleForTesting
class SymmetricState {
  final NoiseProtocol protocol;
  final CipherState cipherState;

  /// The Noise specification uses identifier _ck_ for this.
  List<int>? _chainingKey;

  /// The Noise specification uses identifier _h_ for this.
  Hash? _hash;

  SymmetricState({required this.protocol})
      : cipherState = CipherState(cipher: protocol.cipher);

  /// Chaining key. The Noise specification uses identifier _ck_ for this.
  List<int>? get chainingKey => _chainingKey;

  /// Current hash. The Noise specification uses identifier _h_ for this.
  Hash? get hash => _hash;

  /// See the [specification](https://noiseprotocol.org/noise.html).
  Future<List<int>> decryptAndHash(List<int> cipherText) async {
    final clearText = await cipherState.decrypt(
      cipherText,
    );
    await mixHash(cipherText);
    return clearText;
  }

  /// See the [specification](https://noiseprotocol.org/noise.html).
  Future<List<int>> encryptAndHash(List<int> clearText) async {
    final cipherText = await cipherState.encrypt(
      clearText,
    );
    await mixHash(cipherText);
    return cipherText;
  }

  /// See the [specification](https://noiseprotocol.org/noise.html).
  Future<void> initializeSymmetric() async {
    final hashAlgorithm = protocol.hashAlgorithm.implementation;
    final buffer = protocol.toString().codeUnits.toList();
    while (buffer.length < hashAlgorithm.hashLengthInBytes) {
      buffer.add(0);
    }
    _hash = await hashAlgorithm.hash(buffer);
    _chainingKey = (await hashAlgorithm.hash(buffer)).bytes;
    cipherState.initialize(null);
  }

  /// See the [specification](https://noiseprotocol.org/noise.html).
  Future<void> mixHash(List<int> data) async {
    final sink = protocol.hashAlgorithm.implementation.newHashSink();
    sink.add(_hash!.bytes);
    sink.add(data);
    sink.close();
    _hash = await sink.hash();
  }

  /// See the [specification](https://noiseprotocol.org/noise.html).
  Future<void> mixKey(List<int> key) async {
    final hashAlgorithm = protocol.hashAlgorithm.implementation;
    final hashLength = hashAlgorithm.hashLengthInBytes;
    final hkdf = Hkdf(
      hmac: Hmac(hashAlgorithm),
      outputLength: 2 * hashAlgorithm.hashLengthInBytes,
    );
    final hkdfOutput = await hkdf.deriveKey(
      secretKey: SecretKey(_chainingKey!),
      nonce: key,
    );
    final temp = await hkdfOutput.extractBytes();
    _chainingKey = temp.sublist(0, 32);
    cipherState.initialize(
      SecretKeyData(temp.sublist(hashLength, hashLength + 32)),
    );
  }

  /// See the [specification](https://noiseprotocol.org/noise.html).
  Future<void> mixKeyAndHash(SecretKey secretKey) async {
    final hashAlgorithm = protocol.hashAlgorithm.implementation;
    final hashLength = hashAlgorithm.hashLengthInBytes;
    final hkdf = Hkdf(
      hmac: Hmac(hashAlgorithm),
      outputLength: 3 * hashAlgorithm.hashLengthInBytes,
    );
    final hkdfOutput = await hkdf.deriveKey(
      secretKey: SecretKey(_chainingKey!),
      nonce: const <int>[],
    );
    final temp = await hkdfOutput.extractBytes();

    // First segment is truncated to 32 bytes
    _chainingKey = temp.sublist(0, 32);

    // Second segment is hashLength long
    await mixHash(
      temp.sublist(hashLength, 2 * hashLength),
    );

    // Third segment is truncated to 32 bytes
    await mixHash(
      temp.sublist(2 * hashLength, 2 * hashLength + 32),
    );
  }

  /// See the [specification](https://noiseprotocol.org/noise.html).
  Future<HandshakeResult> split({bool isInitiator = false}) async {
    final hashAlgorithm = protocol.hashAlgorithm.implementation;
    final hashLength = hashAlgorithm.hashLengthInBytes;
    assert(hashLength >= 32);
    final hkdf = Hkdf(
      hmac: Hmac(hashAlgorithm),
      outputLength: 2 * hashAlgorithm.hashLengthInBytes,
    );
    final hkdfOutput = await hkdf.deriveKey(
      secretKey: SecretKey(_chainingKey!),
      nonce: const <int>[],
    );
    final temp = await hkdfOutput.extractBytes();
    final temp0 = temp.sublist(0, 32);
    final temp1 = temp.sublist(hashLength, hashLength + 32);
    final encrypter = CipherState(
      cipher: protocol.cipher,
    );
    final decrypter = CipherState(
      cipher: protocol.cipher,
    );
    encrypter.initialize(SecretKeyData(isInitiator ? temp0 : temp1));
    decrypter.initialize(SecretKeyData(isInitiator ? temp1 : temp0));
    return HandshakeResult(
      encryptingState: decrypter,
      decryptingState: encrypter,
    );
  }
}
