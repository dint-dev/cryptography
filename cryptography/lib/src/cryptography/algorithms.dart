import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/dart.dart';
import 'package:cryptography/helpers.dart';
import 'package:meta/meta.dart';

/// _AES-CBC_ (cipher block chaining mode) [Cipher].
///
/// ## Available implementation
///   * In browsers, [BrowserAesCbc] is used by default.
///   * Otherwise [DartAesCbc] is used by default.
///   * The package [cryptography_flutter](https://pub.dev/packages/cryptography_flutter)
///     supports native implementations available in Android and iOS.
///
/// ## About the algorithm
///   * Three possible key lengths:
///     * 128 bits: [AesCbc.with128bits]
///     * 192 bits: [AesCbc.with192bits]
///     * 256 bits: [AesCbc.with256bits]
///   * Nonce is always 16 bytes. If you want to use a nonce with a different
///     length (e.g. 12 bytes), you need to add zero bytes before/after your
///     nonce.
///   * You must choose some [macAlgorithm]. If you are sure that you don't need
///     one, use [MacAlgorithm.empty].
///
/// ## Example
/// ```dart
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   final message = <int>[1,2,3];
///
///   // AES-CBC with 128 bit keys and HMAC-SHA256 authentication.
///   final algorithm = AesCbc.with128bits(
///     macAlgorithm: Hmac.sha256(),
///   );
///   final secretKey = await algorithm.newSecretKey();
///   final nonce = algorithm.newNonce();
///
///   // Encrypt
///   final secretBox = await algorithm.encrypt(
///     message,
///     secretKey: secretKey,
///   );
///   print('Nonce: ${secretBox.nonce}')
///   print('Ciphertext: ${secretBox.cipherText}')
///   print('MAC: ${secretBox.mac.bytes}')
///
///   // Decrypt
///   final clearText = await algorithm.encrypt(
///     secretBox,
///     secretKey: secretKey,
///   );
///   print('Cleartext: $clearText');
/// }
/// ```
abstract class AesCbc extends Cipher {
  /// Constructor for classes that extend this class.
  @protected
  const AesCbc.constructor();

  factory AesCbc.with128bits({required MacAlgorithm macAlgorithm}) {
    return AesCbc._(
      macAlgorithm: macAlgorithm,
      secretKeyLength: 16,
    );
  }

  factory AesCbc.with192bits({required MacAlgorithm macAlgorithm}) {
    return AesCbc._(
      macAlgorithm: macAlgorithm,
      secretKeyLength: 24,
    );
  }

  factory AesCbc.with256bits({required MacAlgorithm macAlgorithm}) {
    return AesCbc._(
      macAlgorithm: macAlgorithm,
      secretKeyLength: 32,
    );
  }

  factory AesCbc._({
    required MacAlgorithm macAlgorithm,
    required int secretKeyLength,
  }) {
    return Cryptography.instance.aesCbc(
      macAlgorithm: macAlgorithm,
      secretKeyLength: secretKeyLength,
    );
  }

  @override
  int get hashCode =>
      (AesCbc).hashCode ^ secretKeyLength.hashCode ^ macAlgorithm.hashCode;

  @override
  int get nonceLength => 16;

  @override
  bool operator ==(other) =>
      other is AesCbc &&
      secretKeyLength == other.secretKeyLength &&
      macAlgorithm == other.macAlgorithm;

  @override
  String toString() {
    return 'AesCbc.with${secretKeyLength * 8}bits(macAlgorithm: $macAlgorithm)';
  }
}

/// _AES-CTR_ (counter mode) [Cipher].
///
/// ## Available implementation
///   * In browsers, [BrowserAesCtr] is used by default.
///   * Otherwise [DartAesCtr] is used by default.
///   * The package [cryptography_flutter](https://pub.dev/packages/cryptography_flutter)
///     supports native implementations available in Android and iOS.
///
/// ## About the algorithm
///   * Three possible key lengths:
///     * 128 bits: [AesCtr.with128bits]
///     * 192 bits: [AesCtr.with192bits]
///     * 256 bits: [AesCtr.with256bits]
///   * Nonce length is 12 bytes by default. That means 4 bytes is used for
///     block counter.
///       * Because block is 16 bytes, maximum message size is 32 GB with a
///         single nonce.
///       * You can choose another nonce length in the constructor if you need
///         to.
///   * You must choose some [macAlgorithm]. If you are sure that you don't need
///     one, use [MacAlgorithm.empty].
///
/// ## Example
/// ```dart
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   final message = <int>[1,2,3];
///
///   // AES-CTR with 128 bit keys and HMAC-SHA256 authentication.
///   final algorithm = AesCtr.with128bits(
///     macAlgorithm: Hmac.sha256(),
///   );
///   final secretKey = await algorithm.newSecretKey();
///   final nonce = algorithm.newNonce();
///
///   // Encrypt
///   final secretBox = await algorithm.encrypt(
///     message,
///     secretKey: secretKey,
///   );
///   print('Nonce: ${secretBox.nonce}')
///   print('Ciphertext: ${secretBox.cipherText}')
///   print('MAC: ${secretBox.mac.bytes}')
///
///   // Decrypt
///   final clearText = await algorithm.encrypt(
///     secretBox,
///     secretKey: secretKey,
///   );
///   print('Cleartext: $clearText');
/// }
/// ```
abstract class AesCtr extends StreamingCipher {
  /// Constructor for classes that extend this class.
  @protected
  const AesCtr.constructor();

  factory AesCtr.with128bits({
    required MacAlgorithm macAlgorithm,
  }) {
    return AesCtr._(
      macAlgorithm: macAlgorithm,
      secretKeyLength: 16,
    );
  }

  factory AesCtr.with192bits({
    required MacAlgorithm macAlgorithm,
  }) {
    return AesCtr._(
      macAlgorithm: macAlgorithm,
      secretKeyLength: 24,
    );
  }

  factory AesCtr.with256bits({
    required MacAlgorithm macAlgorithm,
  }) {
    return AesCtr._(
      macAlgorithm: macAlgorithm,
      secretKeyLength: 32,
    );
  }

  factory AesCtr._({
    required MacAlgorithm macAlgorithm,
    required int secretKeyLength,
  }) {
    return Cryptography.instance.aesCtr(
      macAlgorithm: macAlgorithm,
      secretKeyLength: secretKeyLength,
    );
  }

  /// Number of bits occupied by the counter.
  int get counterBits;

  @override
  int get hashCode =>
      (AesCtr).hashCode ^ secretKeyLength.hashCode ^ macAlgorithm.hashCode;

  @override
  int get nonceLength => 16;

  @override
  bool operator ==(other) =>
      other is AesCtr &&
      secretKeyLength == other.secretKeyLength &&
      macAlgorithm == other.macAlgorithm;

  @override
  String toString() {
    return 'AesCtr.with${secretKeyLength * 8}bits(macAlgorithm: $macAlgorithm)';
  }
}

/// _AES-GCM_ (Galois/Counter Mode) [Cipher].
///
/// ## Available implementation
///   * In browsers, [BrowserAesGcm] is used by default.
///   * Otherwise [DartAesGcm] is used by default.
///   * The package [cryptography_flutter](https://pub.dev/packages/cryptography_flutter)
///     supports AES-GCM operating system APIs available in Android and iOS.
///     __We recommend you use "package:cryptography_flutter" for the best
///     performance and easier cryptographic compliance.__
///
/// ## About the algorithm
///   * Three possible key lengths:
///     * 128 bits: [AesGcm.with128bits]
///     * 192 bits: [AesGcm.with192bits]
///     * 256 bits: [AesGcm.with256bits]
///   * AES-GCM takes a 128-bit "nonce" block as a parameter. It is split into
///     a random part and block counter. In our implementation, the random part
///     is 96 bits by default, which means the block counter is 32 bits. When
///     block counter is 32 bits, the maximum size of a message is _block_size *
///     2^32 = 32 GB_. If you need longer messages, use a smaller nonce.
///   * AES-GCM standard specifies a MAC algorithm ("GCM"). The output is a
///     128-bit [Mac].
///
/// ## Example
/// ```dart
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   final message = <int>[1,2,3];
///
///   final algorithm = AesGcm.with128bits();
///   final secretKey = await algorithm.newSecretKey();
///   final nonce = algorithm.newNonce();
///
///   // Encrypt
///   final secretBox = await algorithm.encrypt(
///     message,
///     secretKey: secretKey,
///     nonce: nonce,
///   );
///   print('Nonce: ${secretBox.nonce}')
///   print('Ciphertext: ${secretBox.cipherText}')
///   print('MAC: ${secretBox.mac.bytes}')
///
///   // Decrypt
///   final clearText = await algorithm.encrypt(
///     secretBox,
///     secretKey: secretKey,
///   );
///   print('Cleartext: $clearText');
/// }
/// ```
abstract class AesGcm extends StreamingCipher {
  /// MAC algorithm used by _AES-GCM_.
  static const MacAlgorithm aesGcmMac = DartGcm();

  /// Constructor for classes that extend this class.
  @protected
  const AesGcm.constructor();

  factory AesGcm.with128bits({
    int nonceLength = 12,
  }) {
    return AesGcm._(
      secretKeyLength: 16,
      nonceLength: nonceLength,
    );
  }

  factory AesGcm.with192bits({
    int nonceLength = 12,
  }) {
    return AesGcm._(
      secretKeyLength: 24,
      nonceLength: nonceLength,
    );
  }

  factory AesGcm.with256bits({
    int nonceLength = 12,
  }) {
    return AesGcm._(
      secretKeyLength: 32,
      nonceLength: nonceLength,
    );
  }

  factory AesGcm._({
    int secretKeyLength = 32,
    int nonceLength = 12,
  }) {
    return Cryptography.instance.aesGcm(
      secretKeyLength: secretKeyLength,
      nonceLength: nonceLength,
    );
  }

  @override
  int get hashCode => (AesGcm).hashCode;

  @override
  MacAlgorithm get macAlgorithm => AesGcm.aesGcmMac;

  @override
  int get nonceLength;

  @override
  bool operator ==(other) =>
      other is AesGcm &&
      secretKeyLength == other.secretKeyLength &&
      nonceLength == other.nonceLength;

  @override
  String toString() {
    return 'AesGcm.with${secretKeyLength * 8}bits(nonceLength: $nonceLength)';
  }
}

/// _Argon2id_ ([draft-irtf-cfrg-argon2-03](https://tools.ietf.org/html/draft-irtf-cfrg-argon2-03))
/// password hashing function.
///
/// _Argon2_ is known for winning _Password Hashing Competition_ 2015. The
/// algorithm can provide much better security than older algorithms such as
/// [Pbkdf2].
///
/// ## Example
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   final algorithm = Argon2id(
///     parallelism: 3,
///     memorySize: 10000000,
///     iterations: 3,
///     hashLength: 32,
///   );
///
///   final newSecretKey = await algorithm.deriveKey(
///     secretKey: SecretKey([1,2,3]),
///     nonce: [4,5,6],
///   );
///   final newSecretKeyBytes = await newSecretKey.extractBytes();
///
///   print('hashed password: $newSecretKeyBytes');
/// }
/// ```
///
/// ## In need of synchronous APIs?
///
/// If you need to perform operations synchronously, use [DartArgon2id] in
/// _package:cryptography/dart.dart_.
///
abstract class Argon2id extends KdfAlgorithm {
  factory Argon2id({
    required int parallelism,
    required int memorySize,
    required int iterations,
    required int hashLength,
  }) {
    return Cryptography.instance.argon2id(
      parallelism: parallelism,
      memorySize: memorySize,
      iterations: iterations,
      hashLength: hashLength,
    );
  }

  const Argon2id.constructor();

  @override
  int get hashCode => parallelism ^ memorySize ^ iterations ^ hashLength;

  /// Hash length.
  int get hashLength;

  /// Number of iterations.
  int get iterations;

  /// Minimum number of bytes attacker needs to store in memory for each
  /// attempt.
  int get memorySize;

  /// Maximum number of processors attacker can use concurrently for each
  /// attempt.
  int get parallelism;

  /// Argon2id algorithm version number.
  @nonVirtual
  int get version => 0x13;

  @override
  bool operator ==(other) =>
      other is Argon2id &&
      parallelism == other.parallelism &&
      memorySize == other.memorySize &&
      iterations == other.iterations &&
      hashLength == other.hashLength;

  /// Calculates output of Argon2id algorithm.
  ///
  /// Parameter `secretKey` is the hashed password, which can have any length.
  ///
  /// Parameter `nonce` is the password salt, which can have any length.
  ///
  /// Parameters `k` and `ad` are optional additional parameters specified by
  /// Argon2. They are usually left empty.
  @override
  Future<SecretKey> deriveKey({
    required SecretKey secretKey,
    required List<int> nonce,
    List<int> k = const <int>[],
    List<int> ad = const <int>[],
  });

  @override
  String toString() => 'Argon2id(\n'
      '  parallelism: $parallelism,\n'
      '  memorySize: $memorySize,\n'
      '  iterations: $iterations,\n'
      '  hashLength: $hashLength,\n'
      ')';
}

/// _BLAKE2B_ ([RFC 7693](https://tools.ietf.org/html/rfc7693)) [HashAlgorithm].
///
/// ## Asynchronous usage
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   final algorithm = Blake2b();
///   final message = <int>[1,2,3];
///   final hash = await algorithm.hash(message);
///   print('Hash: ${hash.bytes}');
/// }
/// ```
///
/// If you need synchronous computations, use [DartBlake2b].
///
/// ## Streaming usage
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// void main() async {
///   final algorithm = Blake2b();
///
///   // Create a sink
///   final sink = algorithm.newSink();
///
///   // Add any number of chunks
///   sink.add(<int>[1,2,3]);
///   sink.add(<int>[4,5]);
///
///   // Calculate the hash
///   sink.close();
///   final hash = await sink.hash();
///
///   print('Hash: ${hash.bytes}');
/// }
/// ```
///
/// ## In need of synchronous APIs?
///
/// If you need to perform operations synchronously, use [DartBlake2b] in
/// _package:cryptography/dart.dart_.
///
abstract class Blake2b extends HashAlgorithm {
  factory Blake2b() {
    return Cryptography.instance.blake2b();
  }

  /// Constructor for classes that extend this class.
  @protected
  const Blake2b.constructor();

  @override
  int get blockLengthInBytes => 64;

  @override
  int get hashCode => (Blake2b).hashCode;

  @override
  int get hashLengthInBytes => 64;

  @override
  bool operator ==(other) => other is Blake2b;
}

/// _BLAKE2S_ ([RFC 7693](https://tools.ietf.org/html/rfc7693)) [HashAlgorithm].
///
/// ## Asynchronous usage
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   final algorithm = Blake2s();
///   final message = <int>[1,2,3];
///   final hash = await algorithm.hash(message);
///   print('Hash: ${hash.bytes}');
/// }
/// ```
///
/// If you need synchronous computations, use [DartBlake2s].
///
/// ## Streaming usage
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// void main() async {
///   final algorithm = Blake2s();
///
///   // Create a sink
///   final sink = algorithm.newSink();
///
///   // Add any number of chunks
///   sink.add(<int>[1,2,3]);
///   sink.add(<int>[4,5]);
///
///   // Calculate the hash
///   sink.close();
///   final hash = await sink.hash();
///
///   print('Hash: ${hash.bytes}');
/// }
/// ```
///
/// ## In need of synchronous APIs?
///
/// If you need to perform operations synchronously, use [DartBlake2s] in
/// _package:cryptography/dart.dart_.
///
abstract class Blake2s extends HashAlgorithm {
  factory Blake2s() {
    return Cryptography.instance.blake2s();
  }

  /// Constructor for classes that extend this class.
  @protected
  const Blake2s.constructor();

  @override
  int get blockLengthInBytes => 32;

  @override
  int get hashCode => (Blake2s).hashCode;

  @override
  int get hashLengthInBytes => 32;

  @override
  bool operator ==(other) => other is Blake2s;
}

/// _ChaCha20_ ([RFC 7539](https://tools.ietf.org/html/rfc7539))
/// [StreamingCipher].
///
/// We recommend you to use [Chacha20.poly1305Aead()],
/// which does message authentication with a standard AEAD construction for
/// _ChaCha20_.
///
/// ## About the algorithm
///   * [secretKeyLength] is 32 bytes.
///   * [nonceLength] is 12 bytes.\
///
/// ## Example
/// ```dart
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   final message = <int>[1,2,3];
///
///   final algorithm = Chacha20(macAlgorithm: Hmac.sha256());
///   final secretKey = await algorithm.newSecretKey();
///
///   // Encrypt
///   final secretBox = await algorithm.encrypt(
///     message,
///     secretKey: secretKey,
///   );
///   print('Nonce: ${secretBox.nonce}')
///   print('Ciphertext: ${secretBox.cipherText}')
///   print('MAC: ${secretBox.mac.bytes}')
///
///   // Decrypt
///   final clearText = await algorithm.decrypt(
///     secretBox,
///     secretKey: secretKey,
///   );
///   print('Cleartext: $clearText');
/// }
/// ```
///
/// ## In need of synchronous APIs?
///
/// If you need to perform operations synchronously, use [DartChacha20] in
/// _package:cryptography/dart.dart_.
///
abstract class Chacha20 extends StreamingCipher {
  factory Chacha20({required MacAlgorithm macAlgorithm}) {
    return Cryptography.instance.chacha20(macAlgorithm: macAlgorithm);
  }

  /// Constructor for classes that extend this class.
  @protected
  const Chacha20.constructor();

  /// _AEAD_CHACHA20_POLY1305_ ([https://tools.ietf.org/html/rfc7539](RFC 7539))
  /// [Cipher].
  ///
  /// The returned cipher has-builtin [macAlgorithm] that calculates a 128-bit
  /// MAC. AAD (Associated Authenticated Data) is supported by [encrypt()] and
  /// [decrypt()].
  ///
  /// ## About the algorithm
  ///   * [secretKeyLength] is 32 bytes.
  ///   * [nonceLength] is 12 bytes.\
  factory Chacha20.poly1305Aead() {
    return Cryptography.instance.chacha20Poly1305Aead();
  }

  @override
  int get hashCode => (Chacha20).hashCode ^ macAlgorithm.hashCode;

  @override
  int get nonceLength => 12;

  @override
  int get secretKeyLength => 32;

  @override
  bool operator ==(other) =>
      other is Chacha20 && macAlgorithm == other.macAlgorithm;

  @override
  String toString() {
    if (macAlgorithm is DartChacha20Poly1305AeadMacAlgorithm) {
      return 'Chacha20.poly1305Aead()';
    }
    return 'Chacha20(macAlgorithm: $macAlgorithm)';
  }
}

/// ECDH with P-256 / P-384 / P-521 elliptic curve.
///
/// Private keys can be instances of [EcSecretKey] or implementation-specific
/// subclasses of [SecretKey].
///
/// ## Example
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   // In this example, we use P-256 curve.
///   final algorithm = Ecdh.p256();
///
///   // Alice generates a key pair for herself.
///   final aliceSecretKey = await algorithm.newSecretKey();
///   final alicePublicKey = await algorithm.publicKey(aliceSecretKey);
///
///   // Bob generates a key pair for himself.
///   final bobSecretKey = await algorithm.newSecretKey();
///   final bobPublicKey = await algorithm.publicKey(bobSecretKey);
///
///   // Each party calculates shared secret.
///   // Parties get the same symmetric key as a result.
///   final keyForAlice = await algorithm.sharedSecretKey(
///     localSecretKey: alicePublicKey,
///     remotePublicKey: bobPublicKey,
///   );
///   final keyForBob = await algorithm.sharedSecretKey(
///     localSecretKey: bobSecretKey,
///     remotePublicKey: alicePublicKey,
///   );
/// }
/// ```
abstract class Ecdh extends KeyExchangeAlgorithm {
  /// Constructor for classes that extend this class.
  @protected
  const Ecdh.constructor();

  /// ECDH using _P-256_ (secp256r1 / prime256v1) elliptic curve.
  ///
  /// For usage, see [Ecdh] class documentation.
  factory Ecdh.p256({required int length}) {
    return Cryptography.instance.ecdhP256(length: length);
  }

  /// ECDH using _P-384_ (secp384r1 / prime384v1) elliptic curve.
  ///
  /// For usage, see [Ecdh] class documentation.
  factory Ecdh.p384({required int length}) {
    return Cryptography.instance.ecdhP384(length: length);
  }

  /// ECDH using _P-521_ (secp521r1 / prime521v1) elliptic curve.
  ///
  /// For usage, see [Ecdh] class documentation.
  factory Ecdh.p521({required int length}) {
    return Cryptography.instance.ecdhP521(length: length);
  }

  @override
  Future<EcKeyPair> newKeyPair() {
    final seed = Uint8List(keyPairType.privateKeyLength);
    fillBytesWithSecureRandom(seed);
    return newKeyPairFromSeed(seed);
  }

  @override
  Future<EcKeyPair> newKeyPairFromSeed(List<int> seed);

  @override
  String toString() => 'Ecdh.p${keyPairType.ellipticBits}()';
}

/// ECDSA with P-256 / P-384 / P-521 elliptic curve.
///
/// For more information about ECDSA, read
/// [RFC 6090](https://www.ietf.org/rfc/rfc6090.txt)
/// ("Fundamental Elliptic Curve Cryptography Algorithms").
///
/// Secret keys can be instances of [EcSecretKey] or implementation-specific
/// subclasses of [SecretKey].
///
/// ## Example
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   // In this example, we use ECDSA-P256-SHA256
///   final algorithm = Ecdsa.p256(Sha256());
///
///   // Generate a random key pair
///   final secretKey = await algorithm.newSecretKey();
///   final publicKey = await algorithm.publicKey(secretKey);
///
///   // Sign a message
///   final message = <int>[1,2,3];
///   final signature = await algorithm.sign(
///     [1,2,3],
///     secretKey: secretKey,
///   );
///
///   // Anyone can verify the signature
///   final isVerified = await algorithm.verify(
///     message: message,
///     signature: signature,
///   );
/// }
/// ```
abstract class Ecdsa extends SignatureAlgorithm {
  /// Constructor for classes that extend this class.
  @protected
  const Ecdsa.constructor();

  /// ECDSA using _P-256_ (secp256r1 / prime256v1) elliptic curve.
  ///
  /// For usage, see [Ecdsa] class documentation.
  factory Ecdsa.p256(HashAlgorithm hashAlgorithm) {
    return Cryptography.instance.ecdsaP256(hashAlgorithm);
  }

  /// ECDSA using _P-384_ (secp384r1 / prime384v1) elliptic curve.
  ///
  /// For usage, see [Ecdsa] class documentation.
  factory Ecdsa.p384(HashAlgorithm hashAlgorithm) {
    return Cryptography.instance.ecdsaP384(hashAlgorithm);
  }

  /// ECDSA using _P-521_ (secp521r1 / prime521v1) elliptic curve.
  ///
  /// For usage, see [Ecdsa] class documentation.
  factory Ecdsa.p521(HashAlgorithm hashAlgorithm) {
    return Cryptography.instance.ecdsaP521(hashAlgorithm);
  }

  /// Used hash algorithm.
  ///
  /// We recommend [Sha256], [Sha384], or [Sha512].
  HashAlgorithm get hashAlgorithm;

  @override
  Future<EcKeyPair> newKeyPair() {
    final seed = Uint8List(keyPairType.privateKeyLength);
    fillBytesWithSecureRandom(seed);
    return newKeyPairFromSeed(seed);
  }

  @override
  Future<EcKeyPair> newKeyPairFromSeed(List<int> seed);

  @override
  String toString() => 'Ecdsa.p${keyPairType.ellipticBits}($hashAlgorithm)';
}

/// _Ed25519_ ([RFC 8032](https://tools.ietf.org/html/rfc8032)) signature
/// algorithm.
///
/// ## Things to know
///   * Private key is any 32-byte sequence.
///   * Public key is 32 bytes.
///
/// ## Example
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   final algorithm = Ed25519();
///
///   // Generate a key pair
///   final keyPair = await algorithm.newKeyPair();
///
///   // Sign a message
///   final message = <int>[1,2,3];
///   final signature = await algorithm.sign(
///     message,
///     keyPair,
///   );
///   print('Signature bytes: ${signature.bytes}');
///   print('Public key: ${signature.publicKey.bytes}');
///
///   // Anyone can verify the signature
///   final isSignatureCorrect = await algorithm.verify(
///     message,
///     signature: signature,
///   );
/// }
/// ```
///
/// ## In need of synchronous APIs?
///
/// If you need to perform operations synchronously, use [DartEd25519] in
/// _package:cryptography/dart.dart_.
///
abstract class Ed25519 extends SignatureAlgorithm {
  factory Ed25519() {
    return Cryptography.instance.ed25519();
  }

  /// Constructor for classes that extend this class.
  @protected
  const Ed25519.constructor();

  @override
  Future<SimpleKeyPair> newKeyPair() {
    final seed = Uint8List(keyPairType.privateKeyLength);
    fillBytesWithSecureRandom(seed);
    return newKeyPairFromSeed(seed);
  }

  @override
  Future<SimpleKeyPair> newKeyPairFromSeed(List<int> seed);

  @override
  String toString() => 'Ed25519()';
}

/// _Hchacha20_ ([draft-irtf-cfrg-xchacha](https://tools.ietf.org/html/draft-arciszewski-xchacha-03))
/// key derivation algorithm.
///
/// Hchacha20 produces a 256-bit secret key from 256-bit secret key and 96-bit
/// nonce. The algorithm is used by [Xchacha20].
///
abstract class Hchacha20 {
  factory Hchacha20() {
    return Cryptography.instance.hchacha20();
  }

  const Hchacha20.constructor();

  @override
  int get hashCode => (Hchacha20).hashCode;

  @override
  bool operator ==(other) => other is Hchacha20;

  Future<SecretKey> deriveKey({
    required SecretKey secretKey,
    required List<int> nonce,
  });

  @override
  String toString() => 'Hchacha20()';
}

/// _HKDF_ ([RFC 5869](https://tools.ietf.org/html/rfc5869))
/// key derivation algorithm.
///
/// ## Example
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// void main() async {
///   final algorithm = Hkdf(
///     hmac: Hmac(Sha256()),
///     outputLength: 32,
///   );
///   final secretKey = SecretKey([1,2,3]);
///   final nonce = [4,5,6];
///   final output = await algorithm.deriveKey(
///     secretKey: secretKey,
///     nonce: nonce,
///   );
/// }
/// ```
abstract class Hkdf extends KdfAlgorithm {
  factory Hkdf({required Hmac hmac, required int outputLength}) {
    return Cryptography.instance.hkdf(
      hmac: hmac,
      outputLength: outputLength,
    );
  }

  /// Constructor for classes that extend this class.
  @protected
  const Hkdf.constructor();

  @override
  int get hashCode => 11 * hmac.hashCode ^ outputLength;

  Hmac get hmac;

  int get outputLength;

  @override
  bool operator ==(other) =>
      other is Hkdf && hmac == other.hmac && outputLength == other.outputLength;

  @override
  Future<SecretKey> deriveKey({
    required SecretKey secretKey,
    List<int> nonce = const <int>[],
    List<int> info = const <int>[],
  });

  @override
  String toString() => 'Hkdf($hmac)';
}

/// _HMAC_ [MacAlgorithm].
///
/// You should use:
///   * [Hmac.sha1()] for _HMAC-SHA1_.
///   * [Hmac.sha256()] for _HMAC-SHA256_.
///   * [Hmac.sha512()] for _HMAC-SHA512_.
///   * For other combinations, give hash algorithm in the constructor
///     (example: `Hmac(Blake2s())`).
///
/// If you need synchronous computations, use [DartHmac].
///
/// ## Example
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// void main() async {
///   final message = [1,2,3];
///   final secretKey = SecretKey([4,5,6]);
///
///   // In our example, we calculate HMAC-SHA256
///   final hmac = Hmac.sha256();
///   final mac = await hmac.calculateMac(
///     message,
///     secretKey: secretKey,
///   );
/// }
/// ```
abstract class Hmac extends MacAlgorithm {
  factory Hmac(HashAlgorithm hashAlgorithm) {
    return Cryptography.instance.hmac(hashAlgorithm);
  }

  /// Constructor for classes that extend this class.
  @protected
  const Hmac.constructor();

  factory Hmac.sha256() {
    return Hmac(Sha256());
  }

  factory Hmac.sha512() {
    return Hmac(Sha512());
  }

  HashAlgorithm get hashAlgorithm;

  @override
  int get hashCode => (Hmac).hashCode ^ hashAlgorithm.hashCode;

  @override
  int get macLength => hashAlgorithm.hashLengthInBytes;

  @override
  bool operator ==(other) =>
      other is Hmac && hashAlgorithm == other.hashAlgorithm;

  @override
  String toString() {
    final hashAlgorithm = this.hashAlgorithm;
    if (hashAlgorithm is Sha256) {
      return 'Hmac.sha256()';
    }
    if (hashAlgorithm is Sha512) {
      return 'Hmac.sha512()';
    }
    return 'Hmac($hashAlgorithm)';
  }
}

/// _PBKDF2_ password hashing algorithm implemented in pure Dart.
///
/// ## About the algorithm
///   * `macAlgorithm` can be any [MacAlgorithm] (such as [Hmac.sha256()]).
///   * `iterations` should be at least 100 000 for reasonable security in
///     password hashing. The higher the better.
///   * `bits` should be at least 128 for reasonable security in password hashing.
///   * PBKDF2 is a popular choice for password hashing, but much better
///     algorithms exists (such as [Argon2id]).
///
/// ## Example
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   final pbkdf2 = Pbkdf2(
///     macAlgorithm: Hmac.sha256(),
///     iterations: 100000,
///     bits: 128,
///   );
///
///   // Password we want to hash
///   final secretKey = SecretKey([1,2,3]);
///
///   // A random salt
///   final nonce = [4,5,6];
///
///   // Calculate a hash that can be stored in the database
///   final newSecretKey = await pbkdf2.deriveKey(
///     secretKey: secretKey,
///     nonce: nonce,
///   );
///   final newSecretKeyBytes = await newSecretKey.extractBytes();
///   print('Result: $newSecretKeyBytes');
/// }
/// ```
abstract class Pbkdf2 extends KdfAlgorithm {
  factory Pbkdf2({
    required MacAlgorithm macAlgorithm,
    required int iterations,
    required int bits,
  }) {
    return Cryptography.instance.pbkdf2(
      macAlgorithm: macAlgorithm,
      iterations: iterations,
      bits: bits,
    );
  }

  /// Constructor for classes that extend this class.
  @protected
  const Pbkdf2.constructor();

  int get bits;

  @override
  int get hashCode => macAlgorithm.hashCode ^ iterations ^ bits;

  int get iterations;

  MacAlgorithm get macAlgorithm;

  @override
  bool operator ==(other) =>
      other is Pbkdf2 &&
      iterations == other.iterations &&
      bits == other.bits &&
      macAlgorithm == other.macAlgorithm;

  @override
  Future<SecretKey> deriveKey({
    required SecretKey secretKey,
    required List<int> nonce,
  });

  @override
  String toString() =>
      'Pbkdf2(macAlgorithm: $macAlgorithm, iterations: $iterations, bits: $bits)';
}

/// _Poly1305_ ([RFC 7539](https://tools.ietf.org/html/rfc7539)) [MacAlgorithm].
///
/// ## About the algorithm
///   * DO NOT use the same (key, nonce) tuple twice.
///   * DO NOT use the algorithm for key derivation.
abstract class Poly1305 extends MacAlgorithm {
  factory Poly1305() {
    return Cryptography.instance.poly1305();
  }

  /// Constructor for classes that extend this class.
  @protected
  const Poly1305.constructor();

  @override
  int get hashCode => (Poly1305).hashCode;

  @override
  int get macLength => 16;

  @override
  bool operator ==(other) => other is Poly1305;
}

/// _RSA-PSS_ [SignatureAlgorithm].
///
/// Secret keys can be instances of [RsaKeyPairData].
/// Some implementations may support other subclasses [SecretKey].
/// For example, _Web Cryptography API_ supports opaque non-exportable keys.
///
/// Public keys should be instances of [RsaPublicKey].
///
/// ## Example
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   final algorithm = RsaPss(
///     hashAlgorithm: Sha256(),
///   );
///
///   // Generate a key pair
///   final keyPair = await algorithm.newKeyPair();
///
///   // Sign a message
///   final message = <int>[1,2,3];
///   final signature = await algorithm.sign(
///     message,
///     keyPair: keyPair,
///   );
///   print('Signature bytes: ${signature.bytes}');
///   print('Public key: ${signature.publicKey.bytes}');
///
///   // Anyone can verify the signature
///   final isSignatureCorrect = await algorithm.verify(
///     message,
///     signature: signature,
///   );
/// }
/// ```
abstract class RsaPss extends SignatureAlgorithm {
  static const int defaultNonceLengthInBytes = 16;
  static const int defaultModulusLength = 4096;
  static const List<int> defaultPublicExponent = <int>[0x01, 0x00, 0x01];

  factory RsaPss(
    HashAlgorithm hashAlgorithm, {
    int nonceLengthInBytes = defaultNonceLengthInBytes,
  }) {
    return Cryptography.instance.rsaPss(
      hashAlgorithm,
      nonceLengthInBytes: nonceLengthInBytes,
    );
  }

  /// Constructor for classes that extend this class.
  @protected
  const RsaPss.constructor();

  HashAlgorithm get hashAlgorithm;

  @override
  int get hashCode => (RsaSsaPkcs1v15).hashCode ^ hashAlgorithm.hashCode;

  @override
  KeyPairType<KeyPairData, PublicKey> get keyPairType => KeyPairType.rsa;

  @override
  bool operator ==(other) =>
      other is RsaPss && hashAlgorithm == other.hashAlgorithm;

  @override
  Future<RsaKeyPair> newKeyPair({
    int modulusLength = defaultModulusLength,
    List<int> publicExponent = defaultPublicExponent,
  });

  @override
  String toString() => 'RsaPss(hashAlgorithm: $hashAlgorithm)';
}

/// _RSA-SSA-PKCS1v15_ [SignatureAlgorithm].
///
/// Secret keys can be instances of [RsaKeyPairData].
/// Some implementations may support other subclasses [SecretKey].
/// For example, _Web Cryptography API_ supports opaque non-exportable keys.
///
/// Public keys should be instances of [RsaPublicKey].
///
/// ## Example
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   final algorithm = RsaSsaPkcs1v15(
///     hashAlgorithm: Sha256(),
///   );
///
///   // Generate a key pair
///   final keyPair = await algorithm.newKeyPair();
///
///   // Sign a message
///   final message = <int>[1,2,3];
///   final signature = await algorithm.sign(
///     message,
///     keyPair: keyPair,
///   );
///   print('Signature bytes: ${signature.bytes}');
///   print('Public key: ${signature.publicKey.bytes}');
///
///   // Anyone can verify the signature
///   final isSignatureCorrect = await algorithm.verify(
///     message,
///     signature: signature,
///   );
/// }
/// ```
abstract class RsaSsaPkcs1v15 extends SignatureAlgorithm {
  static const int defaultModulusLength = 4096;
  static const List<int> defaultPublicExponent = RsaPss.defaultPublicExponent;

  factory RsaSsaPkcs1v15(HashAlgorithm hashAlgorithm) {
    return Cryptography.instance.rsaSsaPkcs1v15(hashAlgorithm);
  }

  /// Constructor for classes that extend this class.
  @protected
  const RsaSsaPkcs1v15.constructor();

  HashAlgorithm get hashAlgorithm;

  @override
  int get hashCode => (RsaSsaPkcs1v15).hashCode ^ hashAlgorithm.hashCode;

  @override
  KeyPairType<KeyPairData, PublicKey> get keyPairType => KeyPairType.rsa;

  @override
  bool operator ==(other) =>
      other is RsaSsaPkcs1v15 && hashAlgorithm == other.hashAlgorithm;

  @override
  Future<RsaKeyPair> newKeyPair({
    int modulusLength = RsaSsaPkcs1v15.defaultModulusLength,
    List<int> publicExponent = RsaSsaPkcs1v15.defaultPublicExponent,
  });

  @override
  String toString() => 'RsaSsaPkcs1v15(hashAlgorithm: $hashAlgorithm)';
}

/// _SHA-1_ [HashAlgorithm].
///
/// ## Asynchronous usage (recommended)
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   final message = <int>[1,2,3];
///   final algorithm = Sha1();
///   final hash = await algorithm.hash(message);
///   print('Hash: ${hash.bytes}');
/// }
/// ```
///
/// If you need synchronous computations, use [DartSha1].
///
/// ## Streaming usage
/// This enables you to handle very large inputs without keeping everything in
/// memory:
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// void main() async {
///   // Create a sink
///   final algorithm = Sha1();
///   final sink = algorithm.newSink();
///
///   // Add any number of chunks
///   sink.add(<int>[1,2,3]);
///   sink.add(<int>[4,5]);
///
///   // Calculate the hash
///   sink.close();
///   final hash = await sink.hash();
///   print('Hash: ${hash.bytes}');
/// }
/// ```
///
/// ## In need of synchronous APIs?
///
/// If you need to perform operations synchronously, use [DartSha1] in
/// _package:cryptography/dart.dart_.
///
abstract class Sha1 extends HashAlgorithm {
  factory Sha1() => Cryptography.instance.sha1();

  /// Constructor for classes that extend this class.
  @protected
  const Sha1.constructor();

  @override
  int get blockLengthInBytes => 64;

  @override
  int get hashCode => (Sha1).hashCode;

  @override
  int get hashLengthInBytes => 20;

  @override
  bool operator ==(other) => other is Sha1;

  @override
  String toString() => 'Sha1()';
}

/// _SHA-224_ (SHA2-224) [HashAlgorithm].
///
/// ## Asynchronous usage (recommended)
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   final message = <int>[1,2,3];
///   final algorithm = Sha224();
///   final hash = await algorithm.hash(message);
///   print('Hash: ${hash.bytes}');
/// }
/// ```
///
/// If you need synchronous computations, use [DartSha224].
///
/// ## Streaming usage
/// This enables you to handle very large inputs without keeping everything in
/// memory:
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// void main() async {
///   // Create a sink
///   final algorithm = Sha224();
///   final sink = algorithm.newSink();
///
///   // Add any number of chunks
///   sink.add(<int>[1,2,3]);
///   sink.add(<int>[4,5]);
///
///   // Calculate the hash
///   sink.close();
///   final hash = await sink.hash();
///   print('Hash: ${hash.bytes}');
/// }
/// ```
///
/// ## In need of synchronous APIs?
///
/// If you need to perform operations synchronously, use [DartSha224] in
/// _package:cryptography/dart.dart_.
///
abstract class Sha224 extends HashAlgorithm {
  factory Sha224() => Cryptography.instance.sha224();

  /// Constructor for classes that extend this class.
  @protected
  const Sha224.constructor();

  @override
  int get blockLengthInBytes => 64;

  @override
  int get hashCode => (Sha224).hashCode;

  @override
  int get hashLengthInBytes => 28;

  @override
  bool operator ==(other) => other is Sha224;

  @override
  String toString() => 'Sha224()';
}

/// _SHA-256_ (SHA2-256) [HashAlgorithm].
///
/// ## Asynchronous usage (recommended)
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   final message = <int>[1,2,3];
///   final algorithm = Sha256();
///   final hash = await algorithm.hash(message);
///   print('Hash: ${hash.bytes}');
/// }
/// ```
///
/// If you need synchronous computations, use [DartSha256].
///
/// ## Streaming usage
/// This enables you to handle very large inputs without keeping everything in
/// memory:
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// void main() async {
///   // Create a sink
///   final algorithm = Sha256();
///   final sink = algorithm.newSink();
///
///   // Add any number of chunks
///   sink.add(<int>[1,2,3]);
///   sink.add(<int>[4,5]);
///
///   // Calculate the hash
///   sink.close();
///   final hash = await sink.hash();
///   print('Hash: ${hash.bytes}');
/// }
/// ```
///
/// ## In need of synchronous APIs?
///
/// If you need to perform operations synchronously, use [DartSha256] in
/// _package:cryptography/dart.dart_.
///
abstract class Sha256 extends HashAlgorithm {
  factory Sha256() => Cryptography.instance.sha256();

  /// Constructor for classes that extend this class.
  @protected
  const Sha256.constructor();

  @override
  int get blockLengthInBytes => 64;

  @override
  int get hashCode => (Sha256).hashCode;

  @override
  int get hashLengthInBytes => 32;

  @override
  bool operator ==(other) => other is Sha256;

  @override
  String toString() => 'Sha256()';
}

/// _SHA-384_ (SHA2-384) [HashAlgorithm].
///
/// ## Asynchronous usage (recommended)
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   final message = <int>[1,2,3];
///   final algorithm = Sha384();
///   final hash = await algorithm.hash(message);
///   print('Hash: ${hash.bytes}');
/// }
/// ```
///
/// If you need synchronous computations, use [DartSha384].
///
/// ## Streaming usage
/// This enables you to handle very large inputs without keeping everything in
/// memory:
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// void main() async {
///   // Create a sink
///   final algorithm = Sha384();
///   final sink = algorithm.newSink();
///
///   // Add any number of chunks
///   sink.add(<int>[1,2,3]);
///   sink.add(<int>[4,5]);
///
///   // Calculate the hash
///   sink.close();
///   final hash = await sink.hash();
///   print('Hash: ${hash.bytes}');
/// }
/// ```
///
/// ## In need of synchronous APIs?
///
/// If you need to perform operations synchronously, use [DartSha384] in
/// _package:cryptography/dart.dart_.
///
abstract class Sha384 extends HashAlgorithm {
  factory Sha384() => Cryptography.instance.sha384();

  /// Constructor for classes that extend this class.
  @protected
  const Sha384.constructor();

  @override
  int get blockLengthInBytes => 128;

  @override
  int get hashCode => (Sha384).hashCode;

  @override
  int get hashLengthInBytes => 48;

  @override
  bool operator ==(other) => other is Sha384;

  @override
  String toString() => 'Sha384()';
}

/// _SHA-512_ (SHA2-512) [HashAlgorithm].
///
/// ## Asynchronous usage (recommended)
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   final message = <int>[1,2,3];
///   final algorithm = Sha512();
///   final hash = await algorithm.hash(message);
///   print('Hash: ${hash.bytes}');
/// }
/// ```
///
/// If you need synchronous computations, use [DartSha512].
///
/// ## Streaming usage
/// This enables you to handle very large inputs without keeping everything in
/// memory:
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// void main() async {
///   // Create a sink
///   final algorithm = Sha512();
///   final sink = algorithm.newSink();
///
///   // Add any number of chunks
///   sink.add(<int>[1,2,3]);
///   sink.add(<int>[4,5]);
///
///   // Calculate the hash
///   sink.close();
///   final hash = await sink.hash();
///   print('Hash: ${hash.bytes}');
/// }
/// ```
///
/// ## In need of synchronous APIs?
///
/// If you need to perform operations synchronously, use [DartSha512] in
/// _package:cryptography/dart.dart_.
///
abstract class Sha512 extends HashAlgorithm {
  factory Sha512() => Cryptography.instance.sha512();

  /// Constructor for classes that extend this class.
  @protected
  const Sha512.constructor();

  @override
  int get blockLengthInBytes => 128;

  @override
  int get hashCode => (Sha512).hashCode;

  @override
  int get hashLengthInBytes => 64;

  @override
  bool operator ==(other) => other is Sha512;

  @override
  String toString() => 'Sha512()';
}

/// Superclass of streaming ciphers such as [AesGcm] and [Chacha20] that allow
/// encrypter/decrypter to choose offset in the keystream.
abstract class StreamingCipher extends Cipher {
  const StreamingCipher();

  /// Decrypts a ciphertext.
  ///
  /// Parameter [keyStreamIndex] allows you to choose offset in the keystream.
  ///
  /// For other arguments, see [Cipher.decrypt].
  @override
  Future<List<int>> decrypt(
    SecretBox secretBox, {
    required SecretKey secretKey,
    List<int> aad = const <int>[],
    int keyStreamIndex = 0,
  });

  /// Encrypts a cleartext.
  ///
  /// Parameter [keyStreamIndex] allows you to choose offset in the keystream.
  ///
  /// For other arguments, see [Cipher.encrypt].
  @override
  Future<SecretBox> encrypt(
    List<int> message, {
    required SecretKey secretKey,
    List<int>? nonce,
    List<int> aad = const <int>[],
    int keyStreamIndex = 0,
  });
}

/// _X25519_ ([RFC 7748](https://tools.ietf.org/html/rfc7748))
/// [KeyExchangeAlgorithm].
///
/// X25519 is an elliptic curve Diffie-Hellman key exchange algorithm that uses
/// Curve25519.
///
/// ## Things to know
///   * Private key is any 32-byte sequence.
///   * Public key is 32 bytes.
///
/// ## Example
/// ```dart
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   final algorithm = Cryptography.instance.x25519();
///
///   // Let's generate two keypairs.
///   final keyPair = await algorithm.newKeyPair();
///   final remoteKeyPair = await algorithm.newKeyPair();
///   final remotePublicKey = await remoteKeyPair.extractPublicKey();
///
///   // We can now calculate the shared secret key
///   final sharedSecretKey = await algorithm.sharedSecretKey(
///     keyPair: keyPair,
///     remotePublicKey: remotePublicKey,
///   );
/// }
/// ```
///
/// ## In need of synchronous APIs?
///
/// If you need to perform operations synchronously, use [DartX25519] in
/// _package:cryptography/dart.dart_.
///
abstract class X25519 extends KeyExchangeAlgorithm {
  factory X25519() {
    return Cryptography.instance.x25519();
  }

  /// Constructor for classes that extend this class.
  @protected
  const X25519.constructor();

  @override
  Future<SimpleKeyPair> newKeyPair() {
    final seed = Uint8List(keyPairType.privateKeyLength);
    fillBytesWithSecureRandom(seed);
    return newKeyPairFromSeed(seed);
  }

  @override
  Future<SimpleKeyPair> newKeyPairFromSeed(List<int> seed);

  @override
  String toString() => 'X25519()';
}

/// _Xchacha20_ ([draft-irtf-cfrg-xchacha](https://tools.ietf.org/html/draft-arciszewski-xchacha-03)).
/// cipher.
///
/// The only difference between _Xchacha20_ and [Chacha20] is that _Xchacha20_
/// uses 192-bit nonces whereas _Chacha20_ uses 96-bit nonces.
///
/// ## Things to know
///   * [SecretKey] must be 32 bytes.
///   * [Nonce] must be 24 bytes.
///   * `keyStreamIndex` enables choosing index in the key  stream.
///   * It's dangerous to use the same (key, nonce) combination twice.
///   * It's dangerous to use the cipher without authentication.
///
/// ## Example
///
/// See [chacha20].
///
/// ## In need of synchronous APIs?
///
/// If you need to perform operations synchronously, use [DartXchacha20] in
/// _package:cryptography/dart.dart_.
///
abstract class Xchacha20 extends StreamingCipher {
  factory Xchacha20({required MacAlgorithm macAlgorithm}) {
    return Cryptography.instance.xchacha20(macAlgorithm: macAlgorithm);
  }

  /// Constructor for classes that extend this class.
  @protected
  const Xchacha20.constructor();

  /// _XAEAD_CHACHA20_POLY1305_ ([draft-irtf-cfrg-xchacha](https://tools.ietf.org/html/draft-arciszewski-xchacha-03)) cipher.
  ///
  /// [SecretBox.mac] contains a 128-bit MAC.
  /// AAD (Associated Authenticated Data) is supported.
  factory Xchacha20.poly1305Aead() {
    return Cryptography.instance.xchacha20Poly1305Aead();
  }

  @override
  int get hashCode => (Xchacha20).hashCode ^ macAlgorithm.hashCode;

  @override
  int get nonceLength => 24;

  @override
  int get secretKeyLength => 32;

  @override
  bool operator ==(other) =>
      other is Xchacha20 && macAlgorithm == other.macAlgorithm;
}
