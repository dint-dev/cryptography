import 'package:cryptography/cryptography.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:kms/kms.dart';
import 'package:kms_flutter/kms_flutter.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  Kms kms;
  setUp(() {
    WidgetsFlutterBinding.ensureInitialized();
    kms = flutterKms();
  });

  tearDown(() async {
    await for (var document in kms.documentsAsStream()) {
      await document.delete();
    }
  });

  test('flutterKms() returns BrowserKms in browser', () {
    expect(kms, isA<BrowserKms>());
  }, testOn: 'chrome');

  test('flutterKms() returns PluginKms in Android and iOS', () {
    expect(kms, isA<PluginKms>());
  }, testOn: 'android || ios');

  test('collection.createKeyPair(keyExchangeType: ...)', () async {
    final document = await kms.collection('example').createKeyPair(
        keyExchangeType: KeyExchangeType.x25519, signatureType: null);
    expect(
      document.documentId,
      hasLength(32),
    );

    final sharedSecret = await document.sharedSecret(
      remotePublicKey: x25519.newKeyPairSync().publicKey,
    );
    expect(sharedSecret, isNotNull);

    await document.delete();
  });

  test('collection.createKeyPair(signatureType: ...)', () async {
    final document = await kms.collection('example').createKeyPair(
        keyExchangeType: null, signatureType: SignatureType.ed25519);
    expect(
      document.documentId,
      hasLength(32),
    );

    final signature = await document.sign([1, 3, 4]);
    expect(signature, isNotNull);

    await document.delete();
  });

  test('collection.createSecretKey(...)', () async {
    final document = await kms
        .collection('example')
        .createSecretKey(cipherType: CipherType.chacha20Poly1305Aead);
    expect(
      document.documentId,
      hasLength(32),
    );

    final nonce = Nonce.randomBytes(12);
    final encrypted = await document.encrypt(
      [1, 3, 4],
      nonce: nonce,
    );
    expect(encrypted, hasLength(greaterThan(3)));

    final decrypted = await document.decrypt(
      encrypted,
      nonce: nonce,
    );
    expect(decrypted, [1, 2, 3]);

    await document.delete();
  });
}
