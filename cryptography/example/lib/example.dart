import 'package:cryptography/cryptography.dart';

Future<void> main() async {
  // Generate a random 256-bit secret key
  final secretKey = await chacha20.newSecretKey();

  // Generate a random 96-bit nonce.
  final nonce = chacha20.newNonce();

  // Encrypt
  final result = await chacha20Poly1305Aead.encrypt(
    [1, 2, 3],
    secretKey: secretKey,
    nonce: nonce,
  );
  print('Bytes: ${result.cipherText}');
  print('MAC: ${result.mac}');
}
