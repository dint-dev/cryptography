import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:test/test.dart';

void main() {
  group("Signature:", () {
    test("== (same bytes)", () {
      final a = Signature(Uint8List.fromList([3, 1, 4]));
      final b = Signature(Uint8List.fromList([3, 1, 4]));
      expect(a.hashCode, b.hashCode);
      expect(a, b);
    });

    test("== (different bytes)", () {
      final a = Signature(Uint8List.fromList([3, 3, 4]));
      final b = Signature(Uint8List.fromList([3, 1, 4]));
      expect(a.hashCode, isNot(b.hashCode));
      expect(a, isNot(b));
      expect(b, isNot(a));
    });

    test("== (different lengths)", () {
      final a = Signature(Uint8List.fromList([3, 1]));
      final b = Signature(Uint8List.fromList([3, 1, 4]));
      expect(a.hashCode, isNot(b.hashCode));
      expect(a, isNot(b));
      expect(b, isNot(a));
    });

    test("toString() does not contain bytes", () {
      final a = Signature(Uint8List(3));
      expect(a, isNot(contains("0")));
    });
  });
}
