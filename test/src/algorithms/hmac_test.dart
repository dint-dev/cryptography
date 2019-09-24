import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/src/math/hex.dart';
import 'package:test/test.dart';

void main() {
  test("hmac", () {
    final hmac = Hmac(sha256);
    final input = utf8.encode("text");
    final secretKey = SecretKey(utf8.encode("secret"));
    expect(
      hexFromBytes(hmac.calculateMac(input, secretKey).bytes),
      "6a 79 3f da 3e 70 b f6 6a 4f 27 e5 31 5b 7 83 b5 ca 14 42 a4 a1 8c 16 c5 77 d5 14 d3 3 2 e6",
    );
  });
}
