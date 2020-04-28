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

/// Cipher.
///
/// Possible values are:
///   * [NoiseCipher.aesGcm] (AES-GCM)
///   * [NoiseCipher.chachaPoly] (ChaCha20-Poly1305-AEAD)
///
class NoiseCipher {
  /// AES-GCM
  static const NoiseCipher aesGcm = NoiseCipher._(
    'AESGCM',
    cryptography.aesGcm,
  );

  /// ChaCha20-Poly1305-AEAD
  static const NoiseCipher chachaPoly = NoiseCipher._(
    'ChaChaPoly',
    cryptography.chacha20Poly1305Aead,
  );

  /// Name of the algorithm.
  final String name;

  /// Implementation.
  final Cipher implementation;

  const NoiseCipher._(this.name, this.implementation);

  /// Generates a nonce from a counter value.
  Nonce nonce(int counter) {
    // 4 bytes of zeroes + 8 byte LITTLE endian encoding of the counter.
    // We can't use setUint64() because it's unsupported in browsers.
    final byteData = ByteData(12);
    byteData.setUint32(4, counter ~/ (uint32mask + 1), Endian.little);
    byteData.setUint32(8, uint32mask & counter, Endian.little);
    return Nonce(Uint8List.view(byteData.buffer));
  }
}

/// Hash algorithm.
///
/// Possible values are:
///   * [NoiseHashAlgorithm.blake2s] (BLAKE2s)
///   * [NoiseHashAlgorithm.sha256] (SHA2-256)
///
class NoiseHashAlgorithm {
  /// BLAKE2s
  static const NoiseHashAlgorithm blake2s = NoiseHashAlgorithm._(
    'BLAKE2s',
    cryptography.blake2s,
  );

  /// SHA2-256
  static const NoiseHashAlgorithm sha256 = NoiseHashAlgorithm._(
    'SHA256',
    cryptography.sha256,
  );

  /// Name of the algorithm.
  final String name;

  /// Implementation.
  final HashAlgorithm implementation;

  const NoiseHashAlgorithm._(this.name, this.implementation);
}

/// Key exchange algorithm.
///
/// Possible values are:
///   * [NoiseKeyExchangeAlgorithm.x25519]
///
class NoiseKeyExchangeAlgorithm {
  /// X25519
  static const NoiseKeyExchangeAlgorithm x25519 = NoiseKeyExchangeAlgorithm._(
    'X25519',
    cryptography.x25519,
  );

  /// Name of the algorithm.
  final String name;

  /// Implementation.
  final KeyExchangeAlgorithm implementation;

  const NoiseKeyExchangeAlgorithm._(this.name, this.implementation);
}

/// Defines [handshakePattern], [keyExchangeAlgorithm], [cipher], and
/// [hashAlgorithm].
///
/// Example:
/// ```
/// const protocol = NoiseProtocol(
///   handshakePattern: HandshakePattern.xx,
///   keyExchangeAlgorithm: NoiseKeyExchangeAlgorithm.x25519,
///   cipher: NoiseCipher.chachaPoly,
///   hashAlgorithm: NoiseHashAlgorithm.blake2s,
/// );
/// ```
class NoiseProtocol {
  /// Handshake pattern.
  final HandshakePattern handshakePattern;

  /// Key exchange algorithm.
  final NoiseKeyExchangeAlgorithm keyExchangeAlgorithm;

  /// Hash algorithm.
  final NoiseHashAlgorithm hashAlgorithm;

  /// Cipher.
  final NoiseCipher cipher;

  const NoiseProtocol({
    @required this.handshakePattern,
    @required this.keyExchangeAlgorithm,
    @required this.hashAlgorithm,
    @required this.cipher,
  })  : assert(handshakePattern != null),
        assert(keyExchangeAlgorithm != null),
        assert(hashAlgorithm != null),
        assert(cipher != null);

  /// Returns public key length.
  int get publicKeyLength =>
      keyExchangeAlgorithm.implementation.publicKeyLength;

  /// Returns Noise protocol string.
  @override
  String toString() {
    final sb = StringBuffer();
    sb.write('Noise_');
    sb.write(handshakePattern.name);
    sb.write('_');
    sb.write(keyExchangeAlgorithm.name);
    sb.write('_');
    sb.write(cipher.name);
    sb.write('_');
    sb.write(hashAlgorithm.name);
    return sb.toString();
  }
}
