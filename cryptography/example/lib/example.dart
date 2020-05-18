import 'package:cryptography/cryptography.dart';

Future<void> main() async {
  // Generate a random 256-bit secret key
  final secretKey = await chacha20.newSecretKey();

  // Generate a random 96-bit nonce.
  final nonce = chacha20.newNonce();

  // Encrypt
  final plainText = [1, 2, 3];
  final cipherText = await chacha20Poly1305Aead.encrypt(
    plainText,
    secretKey: secretKey,
    nonce: nonce,
  );

  print('Bytes: ${chacha20Poly1305Aead.getDataInCipherText(cipherText)}');
  print('MAC: ${chacha20Poly1305Aead.getMacInCipherText(cipherText)}');
}
