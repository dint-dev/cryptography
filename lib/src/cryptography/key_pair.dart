import 'package:cryptography/cryptography.dart';

/// A pair of keys ([SecretKey] and a [PublicKey]).
class KeyPair {
  final SecretKey secretKey;
  final PublicKey publicKey;

  @override
  KeyPair(this.secretKey, this.publicKey) {
    ArgumentError.checkNotNull(secretKey, "secretKey");
    ArgumentError.checkNotNull(publicKey, "publicKey");
  }

  @override
  int get hashCode => publicKey.hashCode;

  @override
  operator ==(other) =>
      other is KeyPair &&
      publicKey == other.publicKey &&
      secretKey == other.secretKey;

  @override
  String toString() => "KeyPair(..., $publicKey)";
}
