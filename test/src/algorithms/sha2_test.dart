import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/math.dart';
import 'package:test/test.dart';

void main() {
  test("sha224", () {
    expect(
      hexFromBytes(sha224.hash(utf8.encode("")).bytes),
      "d1 4a 2 8c 2a 3a 2b c9 47 61 2 bb 28 82 34 c4 15 a2 b0 1f 82 8e a6 2a c5 b3 e4 2f",
    );
  });
  test("sha256", () {
    expect(
      hexFromBytes(sha256.hash(utf8.encode("")).bytes),
      "e3 b0 c4 42 98 fc 1c 14 9a fb f4 c8 99 6f b9 24 27 ae 41 e4 64 9b 93 4c a4 95 99 1b 78 52 b8 55",
    );
  });
  test("sha384", () {
    expect(
      hexFromBytes(sha384.hash(utf8.encode("")).bytes),
      "38 b0 60 a7 51 ac 96 38 4c d9 32 7e b1 b1 e3 6a 21 fd b7 11 14 be 7 43 4c c c7 bf 63 f6 e1 da 27 4e de bf e7 6f 65 fb d5 1a d2 f1 48 98 b9 5b",
    );
  });
  test("sha512", () {
    expect(
      hexFromBytes(sha512.hash(utf8.encode("")).bytes),
      "cf 83 e1 35 7e ef b8 bd f1 54 28 50 d6 6d 80 7 d6 20 e4 5 b 57 15 dc 83 f4 a9 21 d3 6c e9 ce 47 d0 d1 3c 5d 85 f2 b0 ff 83 18 d2 87 7e ec 2f 63 b9 31 bd 47 41 7a 81 a5 38 32 7a f9 27 da 3e",
    );
  });
}
