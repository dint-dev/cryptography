import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:test/test.dart';

void main() {
  group("SecretKey:", () {
    test("SecretKey.randomBytes()", () {
      final a = SecretKey.randomBytes(32);
      final b = SecretKey.randomBytes(32);
      expect(a.hashCode, isNot(b.hashCode));
      expect(a, isNot(b));
    });

    test("increment(): [..., 0,0,2] --> [...0,0,3]", () {
      var bytes = Uint8List(12);
      bytes[11] = 2;
      bytes = SecretKey(bytes).increment().bytes;
      expect(bytes[11], equals(3));
      expect(bytes[10], equals(0));
      expect(bytes[9], equals(0));
    });

    test("increment(): [..., 0,2,255] --> [...0,3,0]", () {
      var bytes = Uint8List(12);
      bytes[11] = 255;
      bytes[10] = 2;
      bytes = SecretKey(bytes).increment().bytes;
      expect(bytes[11], equals(0));
      expect(bytes[10], equals(3));
      expect(bytes[9], equals(0));
    });

    test("increment(): [..., 2,255,255] --> [...3,0,0]", () {
      var bytes = Uint8List(12);
      bytes[11] = 255;
      bytes[10] = 255;
      bytes[9] = 2;
      bytes = SecretKey(bytes).increment().bytes;
      expect(bytes[11], equals(0));
      expect(bytes[10], equals(0));
      expect(bytes[9], equals(3));
    });

    test("== (same bytes)", () {
      final a = SecretKey(Uint8List.fromList([3, 1, 4]));
      final b = SecretKey(Uint8List.fromList([3, 1, 4]));
      expect(a.hashCode, b.hashCode);
      expect(a, b);
    });

    test("== (different bytes)", () {
      final a = SecretKey(Uint8List.fromList([3, 3, 4]));
      final b = SecretKey(Uint8List.fromList([3, 1, 4]));
      expect(a.hashCode, isNot(b.hashCode));
      expect(a, isNot(b));
      expect(b, isNot(a));
    });

    test("== (different lengths)", () {
      final a = SecretKey(Uint8List.fromList([3, 1]));
      final b = SecretKey(Uint8List.fromList([3, 1, 4]));
      expect(a.hashCode, isNot(b.hashCode));
      expect(a, isNot(b));
      expect(b, isNot(a));
    });

    test("toString() does not contain bytes", () {
      final a = SecretKey(Uint8List(3));
      expect(a, isNot(contains("0")));
    });
  });
}
