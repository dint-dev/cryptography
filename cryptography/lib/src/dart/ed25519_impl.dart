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

import 'dart:typed_data';

import '../_internal/big_int.dart';
import 'x25519_impl.dart';

final _mask16 = BigInt.from(0xFFFF);

/// An ED25519 point.
class Ed25519Point {
  /// ED25519 base point.
  static final base = () {
    final y = Register25519()
      ..parse(
        '46316835694926478169428394003475163141307993866256225615783033603165251855960',
      );
    final x = Register25519()
      ..parse(
        '15112221349535400772501151409588531511454012693041857206046113283949847762202',
      );
    final xy = Register25519()..mul(x, y);
    return Ed25519Point(x, y, Register25519.one, xy);
  }();

  final Register25519 x;
  final Register25519 y;
  final Register25519 z;
  final Register25519 w;

  Ed25519Point(this.x, this.y, this.z, this.w);

  Ed25519Point.zero()
      : this(
          Register25519(),
          Register25519(),
          Register25519(),
          Register25519(),
        );

  bool equals(Ed25519Point other) {
    final v0 = Register25519();
    final v1 = Register25519();

    // v0 = x * other.z
    v0.mul(x, other.z);

    // v1 = z * other.x
    v1.mul(z, other.x);

    // p.x * q.z - p.z * q.x
    v0.sub(v0, v1);

    if (!v0.isZero) {
      return false;
    }

    // v0 = p.y * q.z
    v0.mul(x, other.z);

    // v1 = p.z * q.y
    v1.mul(z, other.x);

    // p.y * q.z - p.z * q.y
    v0.sub(v0, v1);

    return v0.isZero;
  }
}

// A register that uses modulo `2^255 - 19` arithmetic.
//
// The 256-bit integer is stored as a little-endian _16 x uint16_.
class Register25519 {
  /// Constant `0`.
  static final Register25519 zero = Register25519()..data[0] = 0;

  /// Constant `1`.
  static final Register25519 one = Register25519()..data[0] = 1;

  /// Constant `2`.
  static final Register25519 two = Register25519()..data[0] = 2;

  /// Constant `2^(P - 1) >> 2`
  static final Z = Register25519()
    ..parse(
      '19681161376707505956807079304988542015446066515923890162744021073123829784752',
    );

  /// Constant D.
  static final D = Register25519()
    ..parse(
      '37095705934669439343138083508754565189542113879843219016388785533085940283555',
    );

  /// Constant `(2^255 - 19 + 3) ~/ 8`
  // ignore: non_constant_identifier_names
  static final PPlus3Slash8BigInt = Register25519()
    ..data[0] = 0xFFFE
    ..data.fillRange(1, 15, 0xFFFF)
    ..data[15] = 0x0FFF;

  /// Constant `2^255 - 19`
  static final Register25519 P = Register25519()
    ..data[0] = 0xFFED
    ..data.fillRange(1, 15, 0xFFFF)
    ..data[15] = 0x7FFF;

  /// Constant `2^255 - 19 - 2`
  // ignore: non_constant_identifier_names
  static final Register25519 PMinusTwo = Register25519()
    ..data.setAll(0, P.data)
    ..data[0] -= 2;

  /// Constant `2^255 - 19`
  // ignore: non_constant_identifier_names
  static final _P = BigInt.two.pow(255) - BigInt.from(19);

  /// A 256-bit integer stored as 16 _uint16_ values, in little-endian.
  final Int32List data;

  Register25519([Int32List? data]) : data = data ?? Int32List(16);

  factory Register25519.from(Register25519 r) {
    return Register25519(Int32List.fromList(r.data));
  }

  /// Tells whether the value is zero.
  bool get isZero => data.every((element) => element == 0);

  /// Replaces the value with `(a + b) mod (2^255 - 19)`.
  void add(Register25519 a, Register25519 b) {
    final ad = a.data;
    final bd = b.data;
    final cd = data;
    var last = 0;
    for (var i = 0; i < 16; i++) {
      final ai = ad[i];
      final bi = bd[i];
      last = ai + bi + (last ~/ 0x10000);
      cd[i] = 0xFFFF & last;
    }
    cd[15] += (last ~/ 0x10000) * 0x10000;
    _mod19();
  }

  /// Tells whether the value is greater than or equal to the other value.
  bool isGreaterOrEqual(Register25519 other) {
    final a = data;
    final b = other.data;
    for (var i = 15; i >= 0; i--) {
      final ai = a[i];
      final bi = b[i];
      if (ai < bi) {
        return false;
      }
      if (ai > bi) {
        return true;
      }
    }
    return true;
  }

  /// Replaces the value with `(a * b) mod (2^255 - 19)`.
  void mul(Register25519 a, Register25519 b) {
    mod38Mul(data, a.data, b.data);
    _mod19();
  }

  void parse(String s) {
    setBigInt(BigInt.parse(s));
  }

  /// Replaces the value with `a^b mod (2^255 - 19)`.
  void pow(Register25519 base, Register25519 exponent) {
    // TODO: Improve performance by eliminating use of BigInt here.
    setBigInt(base.toBigInt().modPow(exponent.toBigInt(), _P));

    // For some reason the below doesn't work with very large exponents:
//    if (exponent.isZero) {
//      data.setAll(0, one.data);
//      return;
//    }
//    final result = Register25519.from(one);
//    final tmp = Register25519.from(base);
//    exponent = Register25519.from(exponent);
//    for (var i = 0; i < 256; i++) {
//      final b = 0x1 & (exponent.data[i ~/ 16] >> (i % 16));
//      if (b == 1) {
//        result.mul(result, tmp);
//      }
//      tmp.mul(tmp, tmp);
//    }
//    assert(
//      result.toBigInt() ==
//          base.toBigInt().modPow(exponent.toBigInt(), _PBigInt),
//    );
//    data.setAll(0, result.data);
  }

  /// Replaces the value with `a`.
  void set(Register25519 a) {
    data.setAll(0, a.data);
  }

  /// Replaces the value with the [BigInt].
  void setBigInt(BigInt bigInt) {
    final result = data;
    if (bigInt.isNegative) {
      throw ArgumentError('Negative');
    }
    for (var i = 0; i < 16; i++) {
      result[i] = (_mask16 & bigInt).toInt();
      bigInt >>= 16;
    }
    assert(bigInt == BigInt.zero);
  }

  /// Replaces the value with the bytes.
  void setBytes(Uint8List packed) {
    assert(packed.length == 32, 'length=${packed.length}');
    final byteData = ByteData.view(packed.buffer, packed.offsetInBytes, 32);
    final result = data;
    for (var i = 0; i < 16; i++) {
      result[i] = byteData.getUint16(2 * i, Endian.little);
    }
  }

  /// Replaces the value with `(a - b) mod (2^255 - 19)`
  void sub(Register25519 a, Register25519 b) {
    final ad = a.data;
    final bd = b.data;
    final cd = data;
    final pd = P.data;
    var last = 0;
    for (var i = 0; i < 16; i++) {
      // We add 2*P[i] so the result will always be positive.
      last = pd[i] + pd[i] + ad[i] - bd[i] + (last >> 16);
      assert(last >= 0);
      assert(last < 0x100000000);
      cd[i] = 0xFFFF & last;
    }
    cd[15] |= (last >> 16) << 16;
    _mod19();
  }

  /// Returns the value as [BigInt].
  BigInt toBigInt() {
    final list = data;
    var result = BigInt.zero;
    for (var i = 0; i < 16; i++) {
      final v = list[i];
      if (v < 0) {
        throw StateError(
          'Invalid integer: $list',
        );
      }
      if (v >= 0x10000) {
        throw StateError(
          'Invalid integer: $list',
        );
      }
      result |= (BigInt.from(v) << (i * 16));
    }
    return result;
  }

  /// Returns the value as bytes.
  Uint8List toBytes([Uint8List? result]) {
    final data = this.data;
    result ??= Uint8List(32);
    final byteData = ByteData.view(result.buffer, result.offsetInBytes, 32);
    for (var i = 0; i < 16; i++) {
      byteData.setUint16(2 * i, 0xFFFF & data[i], Endian.little);
    }
    return result;
  }

  @override
  String toString() => '0x${toBigInt().toRadixString(16)}';

  void _mod19() {
    while (isGreaterOrEqual(P)) {
      final a = data;
      var previous = a[0] - 0xFFED;
      a[0] = 0xFFFF & previous;
      for (var i = 1; i < 15; i++) {
        final current = a[i] - 0xFFFF - (1 & (previous >> 16));
        a[i] = 0xFFFF & current;
        previous = current;
      }
      a[15] = a[15] - 0x7FFF - (1 & (previous >> 16));
    }
  }
}

/// A register that uses modulo `2^252 + 27742317777372353535851937790883648493`
/// arithmetic.
class RegisterL {
  /// Constant `2^252 + 27742317777372353535851937790883648493`.
  static final constantL = BigInt.parse(
    '7237005577332262213973186563042994240857116359379907606001950938285454250989',
  );

  BigInt? _value;

  void add(RegisterL a, RegisterL b) {
    _value = (a.toBigInt()! + b.toBigInt()!) % constantL;
  }

  void mul(RegisterL a, RegisterL b) {
    _value = (a.toBigInt()! * b.toBigInt()!) % constantL;
  }

  void readBigInt(BigInt value) {
    _value = value;
  }

  void readBytes(List<int> bytes) {
    _value = bigIntFromBytes(bytes) % constantL;
  }

  BigInt? toBigInt() => _value;

  Uint8List toBytes() {
    return bigIntToBytes(_value, Uint8List(32));
  }

  Register25519 toRegister25519() {
    return Register25519()..setBigInt(toBigInt()!);
  }

  @override
  String toString() => '0x${toBigInt()!.toRadixString(16)}';
}
