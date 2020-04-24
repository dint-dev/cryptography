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

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/utils.dart';
import 'package:meta/meta.dart';

/// _X25519_ ([RFC 7748](https://tools.ietf.org/html/rfc7748)) key exchange
/// algorithm (ECDH with Curve25519).
///
/// An example:
/// ```dart
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   // Let's generate two keypairs.
///   final localKeyPair = await x25519.newKeyPair();
///   final remoteKeyPair = await x5519.newKeyPair();
///
///   // We can now calculate a shared secret
///   var sharedSecret = await x25519.sharedSecret(
///     localPrivateKey: localKeyPair.privateKey,
///     remotePublicKey: remoteKeyPair.publicKey,
///   );
/// }
///```
const KeyExchangeAlgorithm x25519 = _X25519();

class _X25519 extends KeyExchangeAlgorithm {
  /// Constant [9, 0, ..., 0] is used when calculating shared secret.
  static final Uint8List _constant9 = () {
    final result = Uint8List(32);
    result[0] = 9;
    return result;
  }();

  /// Constant [0xdb41, 1, 0, ..., 0].
  static final Int32List _constant121665 = () {
    final result = Int32List(16);
    result[0] = 0xdb41;
    result[1] = 1;
    return result;
  }();

  const _X25519();

  @override
  String get name => 'x25519';

  @override
  int get publicKeyLength => 32;

  @override
  KeyPair newKeyPairFromSeedSync(PrivateKey seed) {
    ArgumentError.checkNotNull(seed, 'privateKey');
    final seedBytes = Uint8List.fromList(seed.extractSync());
    if (seedBytes.length != 32) {
      throw ArgumentError(
        'Seed has invalid length: ${seedBytes.length}',
      );
    }

    // Create a secret key
    _X25519.replaceSeedWithSecretKey(seedBytes);
    final privateKey = PrivateKey(seedBytes);

    // Calculate public key
    final publicKeyBytes = Uint8List(32);
    _X25519._calculate(publicKeyBytes, seedBytes, _X25519._constant9);

    // Return a keypair
    final publicKey = PublicKey(publicKeyBytes);
    return KeyPair(privateKey: privateKey, publicKey: publicKey);
  }

  @override
  KeyPair newKeyPairSync() {
    return newKeyPairFromSeedSync(
      PrivateKey.randomBytes(32),
    );
  }

  @override
  SecretKey sharedSecretSync({
    @required PrivateKey localPrivateKey,
    @required PublicKey remotePublicKey,
  }) {
    final secretKeyUint8List = Uint8List.fromList(
      localPrivateKey.extractSync(),
    );
    replaceSeedWithSecretKey(secretKeyUint8List);
    final result = Uint8List(32);
    _calculate(
      result,
      secretKeyUint8List,
      Uint8List.fromList(remotePublicKey.bytes),
    );
    return SecretKey(result);
  }

  /// Modifies certain bits of seed so that the result is a valid secret key.
  static void replaceSeedWithSecretKey(List<int> seed) {
    // First 3 bits must be 0
    seed[0] &= 0xf8;

    // Bit 254 must be 1
    seed[31] |= 0x40;

    // Bit 255 must be 0
    seed[31] &= 0x7f;
  }

  static void _calculate(
    Uint8List result,
    Uint8List secretKey,
    Uint8List publicKey,
  ) {
    // Unpack public key into the internal Int32List
    final unpackedPublicKey = Int32List(16);
    _unpack256(unpackedPublicKey, publicKey);

    // Clear the last bit
    unpackedPublicKey[15] &= 0x7FFF;

    // Allocate temporary arrays
    final a = Int32List(16),
        b = Int32List(16),
        c = Int32List(16),
        d = Int32List(16),
        e = Int32List(16),
        f = Int32List(16);

    // Initialize 'b'
    for (var i = 0; i < 16; i++) {
      b[i] = unpackedPublicKey[i];
    }

    // Initialize 'a' and 'd'
    a[0] = 1;
    d[0] = 1;

    // For each bit in 'secretKey'
    for (var i = 254; i >= 0; i--) {
      // Get the bit
      final isSwap = 1 & (secretKey[i >> 3] >> (7 & i));

      // if isSwap == 1:
      //   swap(a, b)
      //   swap(c, d)
      _conditionalSwap(a, b, isSwap);
      _conditionalSwap(c, d, isSwap);

      // e = a + c
      // a = a + c
      // c = b + d
      // b = b - d
      for (var i = 0; i < 16; i++) {
        final ai = a[i];
        final bi = b[i];
        final ci = c[i];
        final di = d[i];
        e[i] = ai + ci;
        a[i] = ai - ci;
        c[i] = bi + di;
        b[i] = bi - di;
      }

      // d = e^2
      // f = a^2
      // a = c * a
      // c = b * e
      multiply256(d, e, e);
      multiply256(f, a, a);
      multiply256(a, c, a);
      multiply256(c, b, e);

      // e = a + c
      // a = a - c
      // c = d - f
      for (var i = 0; i < 16; i++) {
        final ai = a[i];
        final ci = c[i];
        e[i] = ai + ci;
        a[i] = ai - ci;
        c[i] = d[i] - f[i];
      }

      // b = a^2
      multiply256(b, a, a);

      // a = c * _constant121665
      multiply256(a, c, _constant121665);

      // a += d
      for (var i = 0; i < 16; i++) {
        a[i] += d[i];
      }

      // c = c * a
      // a = d * f
      // d = b * unpacked
      // b = e^2
      multiply256(c, c, a);
      multiply256(a, d, f);
      multiply256(d, b, unpackedPublicKey);
      multiply256(b, e, e);

      // if bit == 1:
      //   swap(a, b)
      //   swap(c, d)
      _conditionalSwap(a, b, isSwap);
      _conditionalSwap(c, d, isSwap);
    }

    // Copy 'c' to 'd'
    for (var i = 0; i < 16; i++) {
      d[i] = c[i];
    }

    // 254 times
    for (var i = 253; i >= 0; i--) {
      // c = c^2
      multiply256(c, c, c);

      if (i != 2 && i != 4) {
        // c = c * d
        multiply256(c, c, d);
      }
    }

    // a = a * c
    multiply256(a, a, c);

    // 3 times
    for (var i = 0; i < 3; i++) {
      var x = 1;
      for (var i = 0; i < 16; i++) {
        final v = 0xFFFF + a[i] + x;
        x = v ~/ 0x10000;
        a[i] = v - 0x10000 * x;
      }
      a[0] += 38 * (x - 1);
    }

    // 2 times
    for (var i = 0; i < 2; i++) {
      // The first element
      var previous = a[0] - 0xFFED;
      b[0] = 0xFFFF & previous;

      // Subsequent elements
      for (var j = 1; j < 15; j++) {
        final current = a[j] - 0xFFFF - (1 & (previous >> 16));
        b[j] = 0xFFFF & current;
        previous = current;
      }

      // The last element
      b[15] = a[15] - 0x7FFF - (1 & (previous >> 16));

      // if isSwap == 1:
      //   swap(a, m)
      final isSwap = 1 - (1 & (b[15] >> 16));
      _conditionalSwap(a, b, isSwap);
    }

    // Pack the internal Int32List into result bytes
    _pack256(result, a);
  }

  // Constant-time conditional swap.
  //
  // If b is 0, the function does nothing.
  // If b is 1, elements of the arrays will be swapped.
  static void _conditionalSwap(Int32List p, Int32List q, int b) {
    final c = ~(b - 1);
    for (var i = 0; i < 16; i++) {
      final t = c & (p[i] ^ q[i]);
      p[i] ^= t;
      q[i] ^= t;
    }
  }

  static void _pack256(Uint8List result, Int32List unpacked) {
    final byteData = ByteData.view(result.buffer, result.offsetInBytes, 32);
    for (var i = 0; i < 16; i++) {
      byteData.setUint16(2 * i, unpacked[i], Endian.little);
    }
  }

  static void _unpack256(Int32List result, Uint8List packed) {
    final byteData = ByteData.view(packed.buffer, packed.offsetInBytes, 32);
    for (var i = 0; i < 16; i++) {
      result[i] = byteData.getUint16(2 * i, Endian.little);
    }
  }
}
