import 'package:cryptography_flutter/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  final clearText = List<int>.filled(10000, 1);

  group('aesGcm:', () {
    TestWidgetsFlutterBinding.ensureInitialized();

    const algo = aesGcm;
    SecretKey secretKey;
    Nonce nonce;
    List<int> cipherText;

    setUp(() {
      secretKey = algo.newSecretKeySync();
      nonce = algo.newNonce();
      cipherText = algo.encryptSync(
        clearText,
        secretKey: secretKey,
        nonce: nonce,
      );
    });

    test('encrypt', () async {
      final actual = await algo.encrypt(
        clearText,
        secretKey: secretKey,
        nonce: nonce,
      );
      expect(actual, orderedEquals(cipherText));
    });

    test('decrypt', () async {
      final actual = await algo.decrypt(
        cipherText,
        secretKey: secretKey,
        nonce: nonce,
      );
      expect(actual, orderedEquals(clearText));
    });
  });

  group('chacha20Poly1305Aead:', () {
    const algo = chacha20Poly1305Aead;
    SecretKey secretKey;
    Nonce nonce;
    List<int> cipherText;

    setUp(() {
      secretKey = algo.newSecretKeySync();
      nonce = algo.newNonce();
      cipherText = algo.encryptSync(
        clearText,
        secretKey: secretKey,
        nonce: nonce,
      );
    });

    test('encrypt', () async {
      final actual = await algo.encrypt(
        clearText,
        secretKey: secretKey,
        nonce: nonce,
      );
      expect(actual, orderedEquals(cipherText));
    });

    test('decrypt', () async {
      final actual = await algo.decrypt(
        cipherText,
        secretKey: secretKey,
        nonce: nonce,
      );
      expect(actual, orderedEquals(clearText));
    });
  });
}
