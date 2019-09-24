// Copyright 2019 Gohilla (opensource@gohilla.com).
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
import 'package:cryptography/math.dart';
import 'package:test/test.dart';

void main() {
  group("Chacha20:", () {
    test("newSecretKey(): two results are not equal", () {
      final key = chacha20.newSecretKey();
      expect(key.bytes, hasLength(32));
      expect(key, isNot(chacha20.newSecretKey()));
    });

    test("newNonce(): two results are not equal", () {
      final nonce = chacha20.newNonce();
      expect(nonce.bytes, hasLength(12));
      expect(nonce, isNot(chacha20.newNonce()));
    });

    group("newState(...):", () {
      test("throws ArgumentError when 'secretKey' is null", () {
        expect(() {
          chacha20.newState(null, nonce: chacha20.newNonce());
        }, throwsA(const TypeMatcher<ArgumentError>()));
      });

      test("throws ArgumentError when 'secretKey' has a wrong length", () {
        expect(() {
          chacha20.newState(
            SecretKey(List<int>(31)),
            nonce: chacha20.newNonce(),
          );
        }, throwsA(const TypeMatcher<ArgumentError>()));
      });

      test("throws ArgumentError when 'nonce' has a wrong length", () {
        expect(() {
          chacha20.newState(
            chacha20.newSecretKey(),
            nonce: SecretKey(Uint8List(13)),
          );
        }, throwsA(const TypeMatcher<ArgumentError>()));
      });
    });
  });

  group("Chacha20State:", () {
    test("keyStreamIndex: can be mutated", () {
      final state = chacha20.newState(
        chacha20.newSecretKey(),
        nonce: chacha20.newNonce(),
      );
      expect(state.keyStreamIndex, equals(0));

      state.keyStreamIndex = 1;
      expect(state.keyStreamIndex, equals(1));
    });

    test("keyStreamIndex: is automatically incremented", () {
      final state = chacha20.newState(
        chacha20.newSecretKey(),
        nonce: chacha20.newNonce(),
      );
      expect(state.keyStreamIndex, equals(0));

      // 0 --> 0
      state.convert([]);
      expect(state.keyStreamIndex, equals(0));

      // 0 --> 3
      state.convert([1, 2, 3]);
      expect(state.keyStreamIndex, equals(3));

      // 3 --> 63
      state.convert(List.filled(60, 0));
      expect(state.keyStreamIndex, equals(63));

      // 63 -> 64
      state.convert([1]);
      expect(state.keyStreamIndex, equals(64));
    });

    test("convert(...): throws StateError after close()", () {
      final state = chacha20.newState(
        chacha20.newSecretKey(),
        nonce: chacha20.newNonce(),
      );
      state.close();
      expect(
        () => state.convert(<int>[]),
        throwsStateError,
      );
    });

    test("convert(...): all input lengths 0...1000 behave consistently", () {
      final state = chacha20.newState(
        chacha20.newSecretKey(),
        nonce: chacha20.newNonce(),
      );

      // Clear text is a sequence of 'a' letters
      final clearText = Uint8List(1000);
      final charCodeForA = "a".codeUnitAt(0);
      clearText.fillRange(0, clearText.length, charCodeForA);

      for (var n = 0; n < 1000; n++) {
        final clearTextSection =
            Uint8List.view(clearText.buffer, clearText.offsetInBytes, n);
        // Encrypt
        state.keyStreamIndex = 0;
        final encrypted = state.convert(clearTextSection);

        // Decrypt
        state.keyStreamIndex = 0;
        final decrypted = state.convert(encrypted);
        expect(decrypted.length, equals(n));

        // Test that the decrypted matches clear text.
        expect(
          decrypted,
          clearTextSection,
        );
      }
    });

    test(
        "convert(...): various 'keyStreamIndex' values and input lengths behave consistently",
        () async {
      final state = chacha20.newState(
        chacha20.newSecretKey(),
        nonce: chacha20.newNonce(),
      );
      final input = List.filled(130, "a".codeUnitAt(0));
      final expectedOutput = state.convert(input);

      for (var skip in const [0, 1, 63, 64, 65, 127, 128, 129]) {
        for (var take in [
          0,
          1,
          63,
          64,
          65,
          127,
          128,
          129,
          input.length - skip
        ]) {
          // If 'take' is too large
          if (take > input.length - skip) {
            // Go to next case
            continue;
          }

          // Take slice of input bytes and encrypted bytes
          final inputSlice = input.skip(skip).take(take).toList();
          final expectedOutputSlice =
              expectedOutput.skip(skip).take(take).toList();

          // Test converting the slice
          state.keyStreamIndex = skip;
          expect(
            state.convert(inputSlice),
            orderedEquals(expectedOutputSlice),
          );

          expect(
            state.keyStreamIndex,
            equals(skip + take),
          );

          // Test converting the remaining bytes
          expect(
            state.convert(input.skip(skip + take).toList()),
            orderedEquals(expectedOutput.skip(skip + take).toList()),
          );
          expect(state.keyStreamIndex, equals(130));
        }
      }
    });

    group("RFC 7539: encryption example", () {
      /// -----------------------------------
      /// These constants are from RFC 7539:
      /// https://tools.ietf.org/html/rfc7539
      /// -----------------------------------

      final cleartext =
          "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
              .runes
              .toList();

      final key = SecretKey(hexToBytes(
        "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f",
      ));

      final nonce = SecretKey(hexToBytes(
        "00:00:00:00:00:00:00:4a:00:00:00:00",
      ));

      final initialKeyStreamIndex = 64;

      final expectedKeyStream = hexToBytes("""
        22:4f:51:f3:40:1b:d9:e1:2f:de:27:6f:b8:63:1d:ed:8c:13:1f:82:3d:2c:06
        e2:7e:4f:ca:ec:9e:f3:cf:78:8a:3b:0a:a3:72:60:0a:92:b5:79:74:cd:ed:2b
        93:34:79:4c:ba:40:c6:3e:34:cd:ea:21:2c:4c:f0:7d:41:b7:69:a6:74:9f:3f
        63:0f:41:22:ca:fe:28:ec:4d:c4:7e:26:d4:34:6d:70:b9:8c:73:f3:e9:c5:3a
        c4:0c:59:45:39:8b:6e:da:1a:83:2c:89:c1:67:ea:cd:90:1d:7e:2b:f3:63              
      """);

      final expectedEncrypted = hexToBytes("""
        6e 2e 35 9a 25 68 f9 80 41 ba 07 28 dd 0d 69 81
        e9 7e 7a ec 1d 43 60 c2 0a 27 af cc fd 9f ae 0b
        f9 1b 65 c5 52 47 33 ab 8f 59 3d ab cd 62 b3 57
        16 39 d6 24 e6 51 52 ab 8f 53 0c 35 9f 08 61 d8
        07 ca 0d bf 50 0d 6a 61 56 a3 8e 08 8a 22 b6 5e
        52 bc 51 4d 16 cc f8 06 81 8c e9 1a b7 79 37 36
        5a f9 0b bf 74 a3 5b e6 b4 0b 8e ed f2 78 5e 42
        87 4d                   
      """);

      /// ------------------------------
      /// End of constants from RFC 7539
      /// ------------------------------

      KeyStreamCipherState state;
      setUp(() {
        state = chacha20.newState(
          key,
          nonce: nonce,
          keyStreamIndex: initialKeyStreamIndex,
        );
      });

      test("keystream", () {
        final keyStream = Uint8List(cleartext.length);
        state.fillWithKeyStream(keyStream, 0);
        expect(
            hexFromBytes(keyStream), equals(hexFromBytes(expectedKeyStream)));
      });

      test("convert", () {
        final encrypted = state.convert(cleartext);
        expect(
            hexFromBytes(encrypted), equals(hexFromBytes(expectedEncrypted)));
      });

      test("convert encrypted to cleartext", () {
        final decrypted = state.convert(expectedEncrypted);
        expect(hexFromBytes(decrypted), equals(hexFromBytes(cleartext)));
      });

      test("convert in multiple parts", () {
        // Span 0:0
        var encrypted = state.convert(cleartext.sublist(0, 0));
        expect(hexFromBytes(encrypted),
            equals(hexFromBytes(expectedEncrypted.sublist(0, 0))));

        // Span 0:1
        encrypted = state.convert(cleartext.sublist(0, 1));
        expect(hexFromBytes(encrypted),
            equals(hexFromBytes(expectedEncrypted.sublist(0, 1))));

        // Span 1:3
        encrypted = state.convert(cleartext.sublist(1, 3));
        expect(hexFromBytes(encrypted),
            equals(hexFromBytes(expectedEncrypted.sublist(1, 3))));

        // Span 3:end
        encrypted = state.convert(cleartext.sublist(3));
        expect(hexFromBytes(encrypted),
            equals(hexFromBytes(expectedEncrypted.sublist(3))));
      });

      test("fillWithConverted throws ArgumentError if length is negative", () {
        final buffer = Uint8List(65);
        expect(
          () => state.fillWithConverted(buffer, 0, cleartext, 0, length: -1),
          throwsA(const TypeMatcher<ArgumentError>()),
        );
      });

      test("fillWithConverted throws ArgumentError if length is too large", () {
        final buffer = Uint8List(1);
        expect(
          () => state.fillWithConverted(buffer, 0, cleartext, 0, length: 2),
          throwsA(const TypeMatcher<ArgumentError>()),
        );
      });

      test("fillWithConverted in multiple parts", () {
        final buffer = Uint8List(65);
        var filledLength = 0;

        // Fill buffer with encrypted 1..3
        state.keyStreamIndex = initialKeyStreamIndex;

        for (var n in [2, 0, 3]) {
          // Fill
          state.fillWithConverted(
            buffer,
            filledLength,
            cleartext,
            filledLength,
            length: n,
          );
          filledLength += n;

          // Check
          expect(
            hexFromBytes(buffer.sublist(0, filledLength)),
            equals(hexFromBytes(expectedEncrypted.sublist(0, filledLength))),
          );

          // Zeroes after it
          expect(
            buffer.sublist(filledLength).every((item) => item == 0),
            isTrue,
          );
        }
      });

      test("fillWithConverted when buffer is smaller than cleartext", () {
        final buffer = Uint8List(5);
        final bufferStart = 4;
        const clearTextStart = 2;

        // Fill buffer with encrypted 1..3
        state.keyStreamIndex = initialKeyStreamIndex + clearTextStart;
        state.fillWithConverted(buffer, bufferStart, cleartext, clearTextStart);

        // 0:4 is zeroes
        expect(
            buffer.sublist(0, bufferStart).every((item) => item == 0), isTrue);

        // 4:N is converted
        expect(
          hexFromBytes(buffer.sublist(bufferStart)),
          equals(hexFromBytes(expectedEncrypted.sublist(
              clearTextStart, clearTextStart + buffer.length - bufferStart))),
        );
      });

      test("fillWithConverted when buffer is larger than cleartext", () {
        final buffer = Uint8List(512);
        final bufferStart = 4;
        const clearTextStart = 2;

        state.keyStreamIndex = initialKeyStreamIndex + clearTextStart;
        state.fillWithConverted(buffer, bufferStart, cleartext, clearTextStart);

        // 0:4 is zeroes
        expect(
            buffer.sublist(0, bufferStart).every((item) => item == 0), isTrue);

        // 4:N is converted
        final bufferFilledEnd =
            bufferStart + expectedEncrypted.length - clearTextStart;
        expect(
          hexFromBytes(buffer.sublist(bufferStart, bufferFilledEnd)),
          equals(hexFromBytes(expectedEncrypted.sublist(clearTextStart))),
        );

        // N: is zeroes
        expect(
            buffer.sublist(bufferFilledEnd).every((item) => item == 0), isTrue);
      });
    });
  });
}
