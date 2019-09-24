import 'package:cryptography/cryptography.dart';

void main() {
  // Generate a random 256-bit secret key
  final secretKey = chacha20.newSecretKey();

  // Generate a random 96-bit nonce.
  final nonce = chacha20.newNonce();

  // Encrypt
  final result = chacha20.encrypt(
    [1, 2, 3],
    secretKey,
    nonce: nonce,
  );
  print(result);
}
