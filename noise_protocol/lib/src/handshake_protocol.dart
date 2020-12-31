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
///   * [NoiseCipher.chachaPoly] (Chacha20-Poly1305-AEAD)
///
class NoiseCipher {
  /// AES-GCM
  static final NoiseCipher aesGcm = NoiseCipher._(
    'AESGCM',
    AesGcm.with256bits(),
  );

  /// Chacha20-Poly1305-AEAD
  static final NoiseCipher chachaPoly = NoiseCipher._(
    'ChachaPoly',
    Chacha20.poly1305Aead(),
  );

  /// Name of the algorithm.
  final String name;

  /// Implementation.
  final StreamingCipher implementation;

  const NoiseCipher._(this.name, this.implementation);

  /// Generates a nonce from a counter value.
  List<int> nonce(int counter) {
    // 4 bytes of zeroes + 8 byte LITTLE endian encoding of the counter.
    // We can't use setUint64() because it's unsupported in browsers.
    final byteData = ByteData(12);
    byteData.setUint32(4, counter ~/ (uint32mask + 1), Endian.little);
    byteData.setUint32(8, uint32mask & counter, Endian.little);
    return Uint8List.view(byteData.buffer);
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
  static final NoiseHashAlgorithm blake2s = NoiseHashAlgorithm._(
    'BLAKE2s',
    Blake2s(),
  );

  /// SHA2-256
  static final NoiseHashAlgorithm sha256 = NoiseHashAlgorithm._(
    'SHA256',
    Sha256(),
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
  static final NoiseKeyExchangeAlgorithm x25519 = NoiseKeyExchangeAlgorithm._(
    'X25519',
    X25519(),
  );

  /// Name of the algorithm.
  final String name;

  /// Implementation.
  final KeyExchangeAlgorithm implementation;

  const NoiseKeyExchangeAlgorithm._(this.name, this.implementation);
}

/// Defines [handshakePattern], [noiseKeyExchangeAlgorithm], [cipher], and
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
  final NoiseHandshakePattern handshakePattern;

  /// Key exchange algorithm.
  final NoiseKeyExchangeAlgorithm noiseKeyExchangeAlgorithm;

  /// Hash algorithm.
  final NoiseHashAlgorithm hashAlgorithm;

  /// Cipher.
  final NoiseCipher cipher;

  const NoiseProtocol({
    required this.handshakePattern,
    required this.noiseKeyExchangeAlgorithm,
    required this.hashAlgorithm,
    required this.cipher,
  });

  /// Returns public key length.
  int get publicKeyLength =>
      noiseKeyExchangeAlgorithm.implementation.keyPairType.publicKeyLength;

  /// Returns Noise protocol string.
  @override
  String toString() {
    final sb = StringBuffer();
    sb.write('Noise_');
    sb.write(handshakePattern.name);
    sb.write('_');
    sb.write(noiseKeyExchangeAlgorithm.name);
    sb.write('_');
    sb.write(cipher.name);
    sb.write('_');
    sb.write(hashAlgorithm.name);
    return sb.toString();
  }
}
