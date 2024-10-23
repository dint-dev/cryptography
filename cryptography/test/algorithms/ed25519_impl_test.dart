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

import 'package:cryptography_plus/src/dart/ed25519_impl.dart';
import 'package:test/test.dart';

void main() {
  // ---------------------------------------------------------------------------
  //
  // IMPORTANT:
  //
  // We've migrated most of the tests to 'cryptography_test'.
  // This file is only for tests that are specific to the 'cryptography'
  // package.
  //
  // ---------------------------------------------------------------------------
  group('Register25519', () {
    final modulo = BigInt.two.pow(255) - BigInt.from(19);

    test('P', () {
      expect(
        Register25519.P.toBigInt().toRadixString(16),
        (BigInt.two.pow(255) - BigInt.from(19)).toRadixString(16),
      );
    });

    test('PMinusTwo', () {
      expect(
        Register25519.PMinusTwo.toBigInt().toRadixString(16),
        (BigInt.two.pow(255) - BigInt.from(21)).toRadixString(16),
      );
    });

    test('PPlus3Slash8BigInt', () {
      expect(
        Register25519.PPlus3Slash8BigInt.toBigInt().toRadixString(16),
        ((BigInt.two.pow(255) - BigInt.from(16)) >> 3).toRadixString(16),
      );
    });

    test('toBigInt', () {
      final register = Register25519();
      register.data[0] = 2;
      expect(register.toBigInt(), BigInt.from(0x2));

      register.data[0] = 0;
      register.data[1] = 3;
      expect(register.toBigInt(), BigInt.from(0x30000));

      register.data[0] = 0;
      register.data[1] = 0;
      register.data[15] = 0x8000;
      expect(register.toBigInt(), BigInt.one << 255);
    });

    test('setBigInt', () {
      final register = Register25519();
      register.setBigInt(BigInt.from(0x2));
      expect(register.data[0], 2);
      expect(register.data[1], 0);
      expect(register.data[14], 0);
      expect(register.data[15], 0);

      register.setBigInt(BigInt.from(0x30000));
      expect(register.data[0], 0);
      expect(register.data[1], 3);
      expect(register.data[14], 0);
      expect(register.data[15], 0);

      register.setBigInt(BigInt.one << 255);
      expect(register.data[0], 0);
      expect(register.data[1], 0);
      expect(register.data[14], 0);
      expect(register.data[15], 0x8000);
    });

    test('add', () {
      final values = [
        BigInt.zero,
        BigInt.one,
        BigInt.two,
        BigInt.from(18),
        BigInt.from(19),
        BigInt.from(20),
        BigInt.from(0xFFFF),
        BigInt.from(0x10000),
        BigInt.parse('0123456789abcdef0123456789abcdef', radix: 16),
        BigInt.two.pow(252) - BigInt.one,
        BigInt.two.pow(253),
        BigInt.two.pow(255) - BigInt.from(25),
        BigInt.two.pow(255) - BigInt.from(24),
        BigInt.two.pow(255) - BigInt.from(23),
        BigInt.two.pow(255) - BigInt.from(22),
        BigInt.two.pow(255) - BigInt.from(21),
        BigInt.two.pow(255) - BigInt.from(20),
      ];
      for (var a in values) {
        for (var b in values) {
          final ar = Register25519()..setBigInt(a);
          final br = Register25519()..setBigInt(b);
          final cr = Register25519();
          cr.add(ar, br);
          final c = cr.toBigInt();
          expect(
            c.toRadixString(16),
            ((a + b) % modulo).toRadixString(16),
            reason: 'a=$ar\nb=$br\nc=$cr',
          );
        }
      }

      for (var a in values) {
        final ar = Register25519()..setBigInt(a);
        ar.add(ar, ar);
        expect(
          ar.toBigInt().toRadixString(16),
          ((a + a) % modulo).toRadixString(16),
          reason: 'a=$ar',
        );
      }
    });

    test('mul', () {
      final values = [
        BigInt.zero,
        BigInt.one,
        BigInt.two,
        BigInt.from(18),
        BigInt.from(19),
        BigInt.from(20),
        BigInt.from(0xFFFF),
        BigInt.from(0x10000),
        BigInt.parse('0123456789abcdef0123456789abcdef', radix: 16),
        BigInt.two.pow(252) - BigInt.one,
        BigInt.two.pow(253),
        BigInt.two.pow(255) - BigInt.from(25),
        BigInt.two.pow(255) - BigInt.from(24),
        BigInt.two.pow(255) - BigInt.from(23),
        BigInt.two.pow(255) - BigInt.from(22),
        BigInt.two.pow(255) - BigInt.from(21),
        BigInt.two.pow(255) - BigInt.from(20),
      ];
      for (var a in values) {
        for (var b in values) {
          final ar = Register25519()..setBigInt(a);
          final br = Register25519()..setBigInt(b);
          final cr = Register25519();
          cr.mul(ar, br);
          final c = cr.toBigInt();
          expect(
            c.toRadixString(16),
            ((a * b) % modulo).toRadixString(16),
            reason: 'a=$ar\nb=$br\nc=$cr',
          );
        }
      }

      for (var a in values) {
        final ar = Register25519()..setBigInt(a);
        for (var i = 0; i < 1000; i++) {
          ar.mul(ar, ar);
          a = (a * a) % modulo;
          expect(
            ar.toBigInt().toRadixString(16),
            a.toRadixString(16),
          );
        }
      }
    });

    test('pow', () {
      final values = [
        BigInt.zero,
        BigInt.one,
        BigInt.two,
        BigInt.from(18),
        BigInt.from(19),
        BigInt.from(20),
        BigInt.from(0xFFFF),
        BigInt.from(0x10000),
        BigInt.parse('0123456789abcdef0123456789abcdef', radix: 16),
        BigInt.two.pow(252) - BigInt.one,
        BigInt.two.pow(253),
        BigInt.two.pow(255) - BigInt.from(25),
        BigInt.two.pow(255) - BigInt.from(24),
        BigInt.two.pow(255) - BigInt.from(23),
        BigInt.two.pow(255) - BigInt.from(22),
        BigInt.two.pow(255) - BigInt.from(21),
        BigInt.two.pow(255) - BigInt.from(20),
      ];
      for (var a in values) {
        for (var b in values) {
          final ar = Register25519()..setBigInt(a);
          final br = Register25519()..setBigInt(b);
          final cr = Register25519();

          cr.pow(ar, br);
          final c = cr.toBigInt();
          expect(
            c.toRadixString(16),
            a.modPow(b, modulo).toRadixString(16),
            reason: 'a=$ar\nb=$br\nc=$cr',
          );
        }
      }
    });

    test('sub', () {
      final values = [
        BigInt.zero,
        BigInt.one,
        BigInt.two,
        BigInt.from(18),
        BigInt.from(19),
        BigInt.from(20),
        BigInt.from(0xFFFF),
        BigInt.from(0x10000),
        BigInt.parse('0123456789abcdef0123456789abcdef', radix: 16),
        BigInt.two.pow(252) - BigInt.one,
        BigInt.two.pow(253),
        BigInt.two.pow(255) - BigInt.from(25),
        BigInt.two.pow(255) - BigInt.from(24),
        BigInt.two.pow(255) - BigInt.from(23),
        BigInt.two.pow(255) - BigInt.from(22),
        BigInt.two.pow(255) - BigInt.from(21),
        BigInt.two.pow(255) - BigInt.from(20),
      ];
      for (var a in values) {
        for (var b in values) {
          final ar = Register25519()..setBigInt(a);
          final br = Register25519()..setBigInt(b);
          final cr = Register25519();
          cr.sub(ar, br);
          final c = cr.toBigInt();
          expect(
            c,
            (a - b) % modulo,
            reason: 'a=$ar\nb=$br\nc=$cr',
          );
        }
      }

      for (var a in values) {
        final ar = Register25519()..setBigInt(a);
        ar.sub(ar, ar);
        expect(
          ar.toBigInt().toRadixString(16),
          BigInt.zero.toRadixString(16),
          reason: 'a=$ar',
        );
      }
    });
  });

  group('RegisterL', () {
    final modulo = RegisterL.constantL;

    test('add', () {
      final values = [
        BigInt.zero,
        BigInt.one,
        BigInt.two,
        BigInt.from(18),
        BigInt.from(19),
        BigInt.from(20),
        BigInt.from(0xFFFF),
        BigInt.from(0x10000),
        BigInt.parse('0123456789abcdef0123456789abcdef', radix: 16),
        BigInt.two.pow(252) - BigInt.one,
        BigInt.two.pow(253),
        BigInt.two.pow(255) - BigInt.from(25),
        BigInt.two.pow(255) - BigInt.from(24),
        BigInt.two.pow(255) - BigInt.from(23),
        BigInt.two.pow(255) - BigInt.from(22),
        BigInt.two.pow(255) - BigInt.from(21),
        BigInt.two.pow(255) - BigInt.from(20),
      ];
      for (var a in values) {
        for (var b in values) {
          final ar = RegisterL()..readBigInt(a);
          final br = RegisterL()..readBigInt(b);
          final cr = RegisterL();
          cr.add(ar, br);
          final c = cr.toBigInt()!;
          expect(
            c.toRadixString(16),
            ((a + b) % modulo).toRadixString(16),
            reason: 'a=$ar\nb=$br\nc=$cr',
          );
        }
      }

      for (var a in values) {
        final ar = RegisterL()..readBigInt(a);
        ar.mul(ar, ar);
        expect(
          ar.toBigInt()!.toRadixString(16),
          ((a * a) % modulo).toRadixString(16),
          reason: 'a=$ar',
        );
      }
    });

    test('mul', () {
      final values = [
        BigInt.zero,
        BigInt.one,
        BigInt.two,
        BigInt.from(18),
        BigInt.from(19),
        BigInt.from(20),
        BigInt.from(0xFFFF),
        BigInt.from(0x10000),
        BigInt.parse('0123456789abcdef0123456789abcdef', radix: 16),
        BigInt.two.pow(252) - BigInt.one,
        BigInt.two.pow(253),
        BigInt.two.pow(255) - BigInt.from(25),
        BigInt.two.pow(255) - BigInt.from(24),
        BigInt.two.pow(255) - BigInt.from(23),
        BigInt.two.pow(255) - BigInt.from(22),
        BigInt.two.pow(255) - BigInt.from(21),
        BigInt.two.pow(255) - BigInt.from(20),
      ];
      for (var a in values) {
        for (var b in values) {
          final ar = RegisterL()..readBigInt(a);
          final br = RegisterL()..readBigInt(b);
          final cr = RegisterL();
          cr.mul(ar, br);
          final c = cr.toBigInt()!;
          expect(
            c.toRadixString(16),
            ((a * b) % modulo).toRadixString(16),
            reason: 'a=$ar\nb=$br\nc=$cr',
          );
        }
      }

      for (var a in values) {
        final ar = RegisterL()..readBigInt(a);
        ar.mul(ar, ar);
        expect(
          ar.toBigInt()!.toRadixString(16),
          ((a * a) % modulo).toRadixString(16),
          reason: 'a=$ar',
        );
      }
    });
  });
}
