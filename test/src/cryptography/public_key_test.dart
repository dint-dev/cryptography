import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:test/test.dart';

void main() {
  group("PublicKey:", () {
    test("== (same bytes)", () {
      final a = PublicKey(Uint8List.fromList([3, 1, 4]));
      final b = PublicKey(Uint8List.fromList([3, 1, 4]));
      expect(a.hashCode, b.hashCode);
      expect(a, b);
    });

    test("== (different bytes)", () {
      final a = PublicKey(Uint8List.fromList([3, 3, 4]));
      final b = PublicKey(Uint8List.fromList([3, 1, 4]));
      expect(a.hashCode, isNot(b.hashCode));
      expect(a, isNot(b));
      expect(b, isNot(a));
    });

    test("== (different lengths)", () {
      final a = PublicKey(Uint8List.fromList([3, 1]));
      final b = PublicKey(Uint8List.fromList([3, 1, 4]));
      expect(a.hashCode, isNot(b.hashCode));
      expect(a, isNot(b));
      expect(b, isNot(a));
    });

    test("toHex()", () {
      final a = PublicKey(Uint8List.fromList([18, 19, 20]));
      expect(a.toHex(), "121314");
    });

    test("toString()", () {
      final a = PublicKey(Uint8List.fromList([18, 19, 20]));
      expect(a.toString(), "PublicKey.parseHex('121314')");
    });
  });
}
