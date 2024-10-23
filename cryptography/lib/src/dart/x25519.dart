// Copyright 2019-2020 Gohilla.
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

import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:cryptography_plus/dart.dart';

import 'ed25519_impl.dart';
import 'x25519_impl.dart';

/// [X25519] implemented in pure Dart.
///
/// For more information about the algorithm and examples, see documentation
/// for the class [X25519].
class DartX25519 extends X25519 with DartKeyExchangeAlgorithmMixin {
  static final Uint8List _constant9 = () {
    final result = Uint8List(32);
    result[0] = 9;
    return result;
  }();

  // Constant 9.
  static final Int32List _constant121665 = () {
    final result = Int32List(16);
    result[0] = 0xdb41;
    result[1] = 1;
    return result;
  }();

  // Constant 121665 (0x1db41).
  const DartX25519({Random? random}) : super.constructor(random: random);

  @override
  KeyPairType get keyPairType => KeyPairType.x25519;

  @override
  Future<SimpleKeyPair> newKeyPairFromSeed(List<int> seed) async {
    final modifiedBytes = DartX25519.modifiedPrivateKeyBytes(seed);
    return SimpleKeyPairData(
      modifiedBytes,
      publicKey: DartX25519._publicKey(modifiedBytes),
      type: KeyPairType.x25519,
    );
  }

  @override
  SecretKey sharedSecretSync({
    required KeyPairData keyPairData,
    required PublicKey remotePublicKey,
  }) {
    if (keyPairData is! SimpleKeyPairData ||
        !KeyPairType.x25519.isValidKeyPairData(keyPairData)) {
      throw ArgumentError.value(
        keyPairData,
        'keyPairData',
      );
    }
    if (remotePublicKey is! SimplePublicKey ||
        !KeyPairType.x25519.isValidPublicKey(remotePublicKey)) {
      throw ArgumentError.value(
        remotePublicKey,
        'remotePublicKey',
      );
    }
    final privateKeyBytes = modifiedPrivateKeyBytes(keyPairData.bytes);
    final result = Uint8List(32);
    _calculate(
      result,
      privateKeyBytes,
      Uint8List.fromList(remotePublicKey.bytes),
    );
    return SecretKey(result);
  }

  /// Modifies certain bits of seed so that the result is a valid secret key.
  static Uint8List modifiedPrivateKeyBytes(List<int> seed) {
    if (seed.length != 32) {
      throw ArgumentError('Seed must be 32 bytes');
    }
    final result = Uint8List.fromList(seed);
    // First 3 bits must be 0
    result[0] &= 0xf8;

    // Bit 254 must be 1
    result[31] |= 0x40;

    // Bit 255 must be 0
    result[31] &= 0x7f;
    return result;
  }

  static void _calculate(
    Uint8List result,
    Uint8List secretKey,
    Uint8List publicKey,
  ) {
    // Unpack public key into the internal Int32List
    final unpackedPublicKey = (Register25519()..setBytes(publicKey)).data;

    // Clear the last bit
    unpackedPublicKey[15] &= 0x7FFF;

    // Allocate arrays
    final a = Int32List(16);
    final b = Int32List(16);
    final c = Int32List(16);
    final d = Int32List(16);
    final e = Int32List(16);
    final f = Int32List(16);

    // See RFC 7748:
    // "Elliptic Curves for Security"
    // https://tools.ietf.org/html/rfc7748
    //
    // Initialize variables.
    //
    // `secretKey` = RFC parameter `k`
    // `unpackedPublicKey` = RFC parameter `u`
    // `a` = RFC assignment `x_2 = 1`
    // `b` = RFC assignment `z_3 = u`
    // `c` = RFC assignment `z_2 = 0`
    // `d` = RFC assignment `z_3 = 1`
    a[0] = 1;
    d[0] = 1;
    for (var i = 0; i < 16; i++) {
      b[i] = unpackedPublicKey[i];
    }

    // For bits 255..0
    for (var t = 254; t >= 0; t--) {
      // Get the secret key bit
      final ki = 1 & (secretKey[t >> 3] >> (7 & t));

      // Two conditional swaps.
      //
      // In the RFC:
      //   `a` is `x_2`
      //   `b` is `x_3`
      //   `c` is `z_2`
      //   `d` is `z_3`
      _conditionalSwap(a, b, ki);
      _conditionalSwap(c, d, ki);

      // Perform +/- operation.
      // We don't need to handle carry bits. Later multiplication will take
      // care of values that have become more than 16 bits.
      for (var i = 0; i < 16; i++) {
        final ai = a[i];
        final bi = b[i];
        final ci = c[i];
        final di = d[i];

        // `e` = RFC assignment `A = x_2 + z_2`
        e[i] = ai + ci;

        // `a` = RFC assignment `B = x_2 - z_2`
        a[i] = ai - ci;

        // `c` = RFC assignment `C = x_3 + z_3`
        c[i] = bi + di;

        // `d` = RFC assignment `D = x_3 - z_3`
        b[i] = bi - di;
      }

      // d = RFC assignment `AA = A^2`
      mod38Mul(d, e, e);

      // f = RFC assignment `BB = B^2`
      mod38Mul(f, a, a);

      // a = RFC assignment `DA = D * A`
      mod38Mul(a, c, a);

      // b = RFC assignment `CB = C * B`
      mod38Mul(c, b, e);

      // In the RFC:
      // x_3 = (DA + CB)^2
      // z_3 = x_1 * (DA - CB)^2
      for (var i = 0; i < 16; i++) {
        final ai = a[i];
        final ci = c[i];
        e[i] = ai + ci;
        a[i] = ai - ci;
        c[i] = d[i] - f[i];
      }

      // b = RFC expression `(DA - CB)^2`
      //
      // Argument `a` = RFC expression `(DA - CB)`
      mod38Mul(b, a, a);

      // a = RFC expression `a24 * E`
      //
      // Argument `c` = RFC expression `E`
      mod38Mul(a, _constant121665, c);

      // a = RFC expression `(AA + a24 * E)`
      //
      // Argument `a` = RFC expression `a24 * E`
      // Argument `d` = RFC expression `AA`
      for (var i = 0; i < 16; i++) {
        a[i] += d[i];
      }

      // c = RFC assignment `z_2 = E * (AA + a24 * E)`
      //
      // Argument `a` = RFC expression `(AA + a24 * E)`
      // Argument `c` = RFC expression `E`
      mod38Mul(c, a, c);

      // a = RFC assignment `x_2 = AA * BB`
      //
      // Argument `d` = RFC expression `AA`
      // Argument `f` = RFC expression `BB`
      mod38Mul(a, d, f);

      // d = RFC assignment `z_3 = x_1 * (DA - CB)^2`
      mod38Mul(d, unpackedPublicKey, b);

      // Remaining calculations.
      //
      // See:
      // "High-speed Curve25519 on 8-bit, 16-bit, and 32-bit microcontrollers"
      // https://link.springer.com/article/10.1007/s10623-015-0087-1
      mod38Mul(b, e, e);
      _conditionalSwap(a, b, ki);
      _conditionalSwap(c, d, ki);
    }

    // Remaining calculations.
    //
    // See:
    // "High-speed Curve25519 on 8-bit, 16-bit, and 32-bit microcontrollers"
    // https://link.springer.com/article/10.1007/s10623-015-0087-1

    // d = c
    for (var i = 0; i < 16; i++) {
      d[i] = c[i];
    }

    for (var i = 253; i >= 0; i--) {
      mod38Mul(c, c, c);
      if (i != 2 && i != 4) {
        mod38Mul(c, c, d);
      }
    }
    mod38Mul(a, a, c);
    for (var i = 0; i < 3; i++) {
      var x = 1;
      for (var i = 0; i < 16; i++) {
        final v = 0xFFFF + a[i] + x;
        x = v ~/ 0x10000;
        a[i] = v - 0x10000 * x;
      }
      a[0] += 38 * (x - 1);
    }
    for (var i = 0; i < 2; i++) {
      var previous = a[0] - 0xFFED;
      b[0] = 0xFFFF & previous;
      for (var j = 1; j < 15; j++) {
        final current = a[j] - 0xFFFF - (1 & (previous >> 16));
        b[j] = 0xFFFF & current;
        previous = current;
      }
      b[15] = a[15] - 0x7FFF - (1 & (previous >> 16));
      final isSwap = 1 - (1 & (b[15] >> 16));
      _conditionalSwap(a, b, isSwap);
    }

    // Pack the internal Int32List into result bytes
    Register25519(a).toBytes(result);
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

  static SimplePublicKey _publicKey(List<int> seed) {
    final privateKeyBytes = DartX25519.modifiedPrivateKeyBytes(seed);
    final publicKeyBytes = Uint8List(32);

    // The private key should already be fixed, but it's good to ensure it.

    // Calculate public key.
    _calculate(
      publicKeyBytes,
      privateKeyBytes,
      DartX25519._constant9,
    );
    return SimplePublicKey(
      publicKeyBytes,
      type: KeyPairType.x25519,
    );
  }
}
