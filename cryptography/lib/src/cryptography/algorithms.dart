import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography_plus/cryptography_plus.dart';
import 'package:cryptography_plus/dart.dart';
import 'package:cryptography_plus/helpers.dart';
import 'package:meta/meta.dart';

/// _AES-CBC_ (cipher block chaining mode) [Cipher].
///
/// In browsers, the default implementation will use
/// [Web Cryptography API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API).
/// On other platforms, [DartAesCbc] will be used.
///
/// If you use Flutter, you can enable
/// [cryptography_flutter](https://pub.dev/packages/cryptography_flutter_plus).
/// It can improve performance in many cases.
///
/// ## Things to know
///   * Three possible key lengths:
///     * 128 bits: [AesCbc.with128bits]
///     * 192 bits: [AesCbc.with192bits]
///     * 256 bits: [AesCbc.with256bits]
///   * Nonce is always 16 bytes. If you want to use a nonce with a different
///     length (e.g. 12 bytes), you need to add zero bytes before/after your
///     nonce.
///   * You must choose some [macAlgorithm]. If you are sure that you don't need
///     one, use [MacAlgorithm.empty].
///   * The standard supports any padding, but this uses PKCS7 padding by
///     default (for compatibility with Web Cryptography API).
///
/// ## Example
/// ```dart
/// import 'package:cryptography_plus/cryptography_plus.dart';
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
  /// Number of bytes in a block.
  static const blockLengthInBytes = 16;

  /// Constructor for classes that extend this class.
  const AesCbc.constructor({
    Random? random,
  }) : super(random: random);

  /// Constructs 128-bit AES-CBC.
  factory AesCbc.with128bits({
    required MacAlgorithm macAlgorithm,
    PaddingAlgorithm paddingAlgorithm = PaddingAlgorithm.pkcs7,
  }) {
    return AesCbc._(
      macAlgorithm: macAlgorithm,
      paddingAlgorithm: paddingAlgorithm,
      secretKeyLength: 16,
    );
  }

  /// Constructs 192-bit AES-CBC.
  factory AesCbc.with192bits({
    required MacAlgorithm macAlgorithm,
    PaddingAlgorithm paddingAlgorithm = PaddingAlgorithm.pkcs7,
  }) {
    return AesCbc._(
      macAlgorithm: macAlgorithm,
      paddingAlgorithm: paddingAlgorithm,
      secretKeyLength: 24,
    );
  }

  /// Constructs 256-bit AES-CBC.
  factory AesCbc.with256bits({
    required MacAlgorithm macAlgorithm,
    PaddingAlgorithm paddingAlgorithm = PaddingAlgorithm.pkcs7,
  }) {
    return AesCbc._(
      macAlgorithm: macAlgorithm,
      paddingAlgorithm: paddingAlgorithm,
      secretKeyLength: 32,
    );
  }

  factory AesCbc._({
    required MacAlgorithm macAlgorithm,
    required int secretKeyLength,
    required PaddingAlgorithm paddingAlgorithm,
  }) {
    return Cryptography.instance.aesCbc(
      macAlgorithm: macAlgorithm,
      paddingAlgorithm: paddingAlgorithm,
      secretKeyLength: secretKeyLength,
    );
  }

  @override
  int get hashCode => Object.hash(AesCbc, secretKeyLength, macAlgorithm);

  @override
  int get nonceLength => 16;

  /// [PaddingAlgorithm] used by AES-CBC.
  PaddingAlgorithm get paddingAlgorithm;

  @override
  bool operator ==(other) =>
      other is AesCbc &&
      secretKeyLength == other.secretKeyLength &&
      macAlgorithm == other.macAlgorithm &&
      paddingAlgorithm == other.paddingAlgorithm;

  @override
  int cipherTextLength(int clearTextLength) {
    return (clearTextLength + (blockLengthInBytes - 1)) ~/ blockLengthInBytes;
  }

  @override
  String toString() {
    if (identical(paddingAlgorithm, PaddingAlgorithm.pkcs7)) {
      return '$runtimeType.with${secretKeyLength * 8}bits(macAlgorithm: $macAlgorithm)';
    }
    return '$runtimeType.with${secretKeyLength * 8}bits(macAlgorithm: $macAlgorithm, paddingAlgorithm: $paddingAlgorithm)';
  }

  @override
  DartAesCbc toSync() {
    return DartAesCbc(
      macAlgorithm: macAlgorithm,
      secretKeyLength: secretKeyLength,
      paddingAlgorithm: paddingAlgorithm,
      random: random,
    );
  }
}

/// _AES-CTR_ (counter mode) [Cipher].
///
/// In browsers, the default implementation will use
/// [Web Cryptography API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API).
/// On other platforms, [DartAesCtr] will be used.
///
/// If you use Flutter, you can enable
/// [cryptography_flutter](https://pub.dev/packages/cryptography_flutter_plus).
/// It can improve performance in many cases.
///
/// ## Things to know
///   * Three possible key lengths:
///     * 128 bits: [AesCtr.with128bits]
///     * 192 bits: [AesCtr.with192bits]
///     * 256 bits: [AesCtr.with256bits]
///   * Nonce length is 12 bytes by default, which implies 4 bytes for the block
///     counter. Because block is 16 bytes, the maximum message size is 32 GB
///     with a single nonce. You can choose another nonce length in the
///     constructor if you need to support larger messages.
///   * You must choose some [macAlgorithm]. If you are sure that you don't need
///     one, use [MacAlgorithm.empty].
///
/// ## Example
/// ```dart
/// import 'package:cryptography_plus/cryptography_plus.dart';
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
  /// Default value for [counterBits].
  static const int defaultCounterBits = 64;

  /// Constructor for classes that extend this class.
  const AesCtr.constructor({Random? random}) : super(random: random);

  /// Constructs 128-bit AES-CTR.
  factory AesCtr.with128bits({
    required MacAlgorithm macAlgorithm,
  }) {
    return AesCtr._(
      macAlgorithm: macAlgorithm,
      secretKeyLength: 16,
    );
  }

  /// Constructs 192-bit AES-CTR.
  factory AesCtr.with192bits({
    required MacAlgorithm macAlgorithm,
  }) {
    return AesCtr._(
      macAlgorithm: macAlgorithm,
      secretKeyLength: 24,
    );
  }

  /// Constructs 256-bit AES-CTR.
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
  int get hashCode => Object.hash(AesCtr, secretKeyLength, macAlgorithm);

  @override
  int get nonceLength => 16;

  @override
  bool operator ==(other) =>
      other is AesCtr &&
      secretKeyLength == other.secretKeyLength &&
      macAlgorithm == other.macAlgorithm;

  @override
  void checkParameters({
    int? length,
    required SecretKey secretKey,
    required int nonceLength,
    int aadLength = 0,
    int keyStreamIndex = 0,
  }) {
    // Allow nonce length to be anything.
    // TODO: Should we require 12 bytes?
    if (nonceLength != this.nonceLength) {
      nonceLength = this.nonceLength;
    }
    super.checkParameters(
      length: length,
      secretKey: secretKey,
      nonceLength: nonceLength,
      aadLength: aadLength,
      keyStreamIndex: keyStreamIndex,
    );
  }

  @override
  String toString() {
    return '$runtimeType.with${secretKeyLength * 8}bits(macAlgorithm: $macAlgorithm, counterBits: $counterBits)';
  }

  @override
  DartAesCtr toSync() {
    return DartAesCtr(
      macAlgorithm: macAlgorithm,
      secretKeyLength: secretKeyLength,
      random: random,
    );
  }
}

/// _AES-GCM_ (Galois/Counter Mode) [Cipher].
///
/// In browsers, the default implementation will use
/// [Web Cryptography API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API).
/// On other platforms, [DartAesGcm] will be used.
///
/// If you use Flutter, you can enable
/// [cryptography_flutter](https://pub.dev/packages/cryptography_flutter_plus).
/// It can improve performance in many cases.
///
/// ## Things to know
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
/// import 'package:cryptography_plus/cryptography_plus.dart';
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
abstract class AesGcm extends Cipher {
  /// MAC algorithm used by _AES-GCM_.
  static const MacAlgorithm aesGcmMac = DartGcm();

  static const int defaultNonceLength = 12;

  /// Constructor for classes that extend this class.
  const AesGcm.constructor({Random? random}) : super(random: random);

  factory AesGcm.with128bits({
    int nonceLength = AesGcm.defaultNonceLength,
  }) {
    return AesGcm._(
      secretKeyLength: 16,
      nonceLength: nonceLength,
    );
  }

  factory AesGcm.with192bits({
    int nonceLength = AesGcm.defaultNonceLength,
  }) {
    return AesGcm._(
      secretKeyLength: 24,
      nonceLength: nonceLength,
    );
  }

  factory AesGcm.with256bits({
    int nonceLength = AesGcm.defaultNonceLength,
  }) {
    return AesGcm._(
      secretKeyLength: 32,
      nonceLength: nonceLength,
    );
  }

  factory AesGcm._({
    required int secretKeyLength,
    required int nonceLength,
  }) {
    return Cryptography.instance.aesGcm(
      secretKeyLength: secretKeyLength,
      nonceLength: nonceLength,
    );
  }

  @override
  int get hashCode => Object.hash(AesGcm, secretKeyLength, nonceLength);

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
    if (nonceLength == AesGcm.defaultNonceLength) {
      return '$runtimeType.with${secretKeyLength * 8}bits()';
    }
    return '$runtimeType.with${secretKeyLength * 8}bits(nonceLength: $nonceLength)';
  }

  @override
  DartAesGcm toSync() {
    return DartAesGcm(
      secretKeyLength: secretKeyLength,
      nonceLength: nonceLength,
      random: random,
    );
  }
}

/// _Argon2id_ ([RFC 9106](https://datatracker.ietf.org/doc/rfc9106/))
/// memory-hard password hashing function.
///
/// _Argon2_ is known for winning _Password Hashing Competition_ 2015. OWASP
/// [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
/// describes it as first choice for password hashing.
///
/// The default implementation is [DartArgon2id], our pure Dart implementation.
///
/// ## Things to know
///   * You need to choose:
///     * [memory]
///       * Number of 1kB blocks of memory needed to compute the hash.
///       * Higher is better for security. You should experiment what is good
///         for your system. We recommend to start from 1000 (= 1 MB) and go
///         as high as you can.
///     * [parallelism]
///       * Maximum number of parallel computations.
///       * You should choose a small number such as 1 or 4.
///     * [iterations]
///       * Number of iterations. Higher is better for security, but usually
///         you should use value `1` because it makes more sense (from security
///         point of view) to raise [memory] parameter instead.
///     * [hashLength]
///       * The value should be at least 16 bytes. More than 32 bytes is
///         unnecessary from security point of view.
///   * OWASP [suggests](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
///     the following parameter values:
///       * memory = 19 MiB of memory
///       * parallelism = 1
///       * iterations = 2
///
/// ## Example
/// ```
/// import 'package:cryptography_plus/cryptography_plus.dart';
///
/// Future<void> main() async {
///   final algorithm = Argon2id(
///     parallelism: 4,
///     memory: 10000, // 10 000 x 1kB block = 10 MB
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
/// _package:cryptography_plus/dart.dart_.
///
abstract class Argon2id extends KdfAlgorithm {
  factory Argon2id({
    required int parallelism,
    required int memory,
    required int iterations,
    required int hashLength,
  }) {
    return Cryptography.instance.argon2id(
      parallelism: parallelism,
      memory: memory,
      iterations: iterations,
      hashLength: hashLength,
    );
  }

  /// Constructor subclasses.
  const Argon2id.constructor();

  @override
  int get hashCode => parallelism ^ memory ^ iterations ^ hashLength;

  /// Hash length.
  int get hashLength;

  /// Number of iterations.
  int get iterations;

  /// Minimum number of 1 kB blocks needed to compute the hash.
  int get memory;

  /// Maximum number of processors attacker can use concurrently for each
  /// attempt.
  int get parallelism;

  /// Argon2id algorithm version number.
  @nonVirtual
  int get version => 19;

  @override
  bool operator ==(other) =>
      other is Argon2id &&
      parallelism == other.parallelism &&
      memory == other.memory &&
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
    List<int> optionalSecret = const <int>[],
    List<int> associatedData = const <int>[],
  });

  @override
  String toString() => '$runtimeType(\n'
      '  parallelism: $parallelism,\n'
      '  memory: $memory,\n'
      '  iterations: $iterations,\n'
      '  hashLength: $hashLength,\n'
      ')';
}

/// _BLAKE2B_ ([RFC 7693](https://tools.ietf.org/html/rfc7693)), which can be
/// used both as [HashAlgorithm] and [MacAlgorithm].
///
/// By default, [DartBlake2b] will be used.
///
/// ## Things to know
///   * The default [hashLengthInBytes] / [macLength] is 64 bytes. You can
///     choose a shorter hash length when you call the constructor. You should
///     NOT truncate the hash yourself.
///   * The algorithm was designed to be used directly as [MacAlgorithm] (no
///     [Hmac] needed). Maximum secret key size is 64 bytes.
///   * Blake2 hash/MAC function family includes also [Blake2s].
///
/// ## Example: Hashing a byte list
/// ```
/// import 'package:cryptography_plus/cryptography_plus.dart';
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
/// ## Example: Hashing a sequence of chunks
/// ```
/// import 'package:cryptography_plus/cryptography_plus.dart';
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
abstract class Blake2b extends HashAlgorithm implements MacAlgorithm {
  /// Default value of [hashLengthInBytes] and [macLength].
  static const int defaultHashLengthInBytes = 64;

  factory Blake2b({
    int hashLengthInBytes = defaultHashLengthInBytes,
  }) {
    if (hashLengthInBytes < 1 || hashLengthInBytes > defaultHashLengthInBytes) {
      throw ArgumentError.value(hashLengthInBytes);
    }
    return Cryptography.instance.blake2b(
      hashLengthInBytes: hashLengthInBytes,
    );
  }

  /// Constructor for subclasses.
  const Blake2b.constructor({
    this.hashLengthInBytes = defaultHashLengthInBytes,
  })  : assert(hashLengthInBytes > 0),
        assert(hashLengthInBytes <= defaultHashLengthInBytes);

  /// Enables you to replace [hashLengthInBytes].
  ///
  /// Subclasses should replace this with their own implementation.
  Blake2b replace({int? hashLength}) {
    hashLength ??= hashLengthInBytes;
    if (hashLength == hashLengthInBytes) {
      return this;
    }
    return Blake2b(
      hashLengthInBytes: hashLength,
    );
  }

  @override
  void checkParameters({
    int? length,
    required SecretKey secretKey,
    required int nonceLength,
    required int aadLength,
    required int keyStreamIndex,
  }) {}

  @override
  int get keyStreamUsed => 0;

  @override
  int get macLength => hashLengthInBytes;

  @override
  bool get supportsAad => false;

  @override
  bool get supportsKeyStreamIndex => false;

  @override
  int get blockLengthInBytes => 64;

  @override
  int get hashCode => (Blake2b).hashCode;

  @override
  final int hashLengthInBytes;

  @override
  bool operator ==(other) => other is Blake2b;

  @override
  DartBlake2b toSync() => DartBlake2b(
        hashLengthInBytes: hashLengthInBytes,
      );

  @override
  String toString() {
    if (hashLengthInBytes == defaultHashLengthInBytes) {
      return 'Blake2b()';
    }
    return 'Blake2b(hashLengthInBytes: $hashLengthInBytes)';
  }
}

/// _BLAKE2S_ ([RFC 7693](https://tools.ietf.org/html/rfc7693)), which can be
/// used both as [HashAlgorithm] and [MacAlgorithm].
///
/// By default, [DartBlake2s] will be used.
///
/// ## Things to know
///   * The default [hashLengthInBytes] / [macLength] is 32 bytes. You can
///     choose a shorter hash length when you call the constructor. You should
///     NOT truncate the hash yourself.
///   * The algorithm was designed to be used directly as [MacAlgorithm] (no
///     [Hmac] needed). Maximum secret key size is 32 bytes.
///   * Blake2 hash/MAC function family includes also [Blake2b].
///
/// ## Example: Hashing a byte list
/// ```dart
/// import 'package:cryptography_plus/cryptography_plus.dart';
///
/// Future<void> main() async {
///   final algorithm = Blake2s();
///   final message = <int>[1,2,3];
///   final hash = await algorithm.hash(message);
///   print('Hash: ${hash.bytes}');
/// }
/// ```
///
/// ## Example: Hashing a sequence of chunks
/// ```dart
/// import 'package:cryptography_plus/cryptography_plus.dart';
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
abstract class Blake2s extends HashAlgorithm implements MacAlgorithm {
  /// Default value of [hashLengthInBytes] and [macLength].
  static const int defaultHashLengthInBytes = 32;

  factory Blake2s({
    int hashLengthInBytes = defaultHashLengthInBytes,
  }) {
    if (hashLengthInBytes < 1 || hashLengthInBytes > defaultHashLengthInBytes) {
      throw ArgumentError.value(hashLengthInBytes);
    }
    return Cryptography.instance.blake2s(
      hashLengthInBytes: hashLengthInBytes,
    );
  }

  /// Constructor for subclasses.
  const Blake2s.constructor({
    this.hashLengthInBytes = defaultHashLengthInBytes,
  })  : assert(hashLengthInBytes > 0),
        assert(hashLengthInBytes <= defaultHashLengthInBytes);

  @override
  int get blockLengthInBytes => 32;

  @override
  int get hashCode => (Blake2s).hashCode;

  @override
  final int hashLengthInBytes;

  @override
  void checkParameters({
    int? length,
    required SecretKey secretKey,
    required int nonceLength,
    required int aadLength,
    required int keyStreamIndex,
  }) {}

  @override
  int get keyStreamUsed => 0;

  @override
  int get macLength => hashLengthInBytes;

  @override
  bool get supportsAad => false;

  @override
  bool get supportsKeyStreamIndex => false;

  @override
  bool operator ==(other) => other is Blake2s;

  @override
  String toString() {
    if (hashLengthInBytes == defaultHashLengthInBytes) {
      return 'Blake2s()';
    }
    return 'Blake2s(hashLengthInBytes: $hashLengthInBytes)';
  }

  @override
  DartBlake2s toSync() => DartBlake2s(
        hashLengthInBytes: hashLengthInBytes,
      );
}

/// _ChaCha20_ ([RFC 7539](https://tools.ietf.org/html/rfc7539))
/// [StreamingCipher].
///
/// Unless you really know what you are doing, you should use
/// [Chacha20.poly1305Aead] constructor, which constructs the popular AEAD
/// version of the cipher.
///
/// ## Implementations
/// By default, [DartChacha20] will be used. It is a pure Dart implementation.
///
/// If you use Flutter, you can enable
/// [cryptography_flutter](https://pub.dev/packages/cryptography_flutter_plus).
/// It can improve performance in many cases.
///
/// ## Things to know
///   * [secretKeyLength] is 32 bytes.
///   * [nonceLength] is 12 bytes.
///   * If you use [Chacha20.poly1305Aead] (like you should), MAC algorithm
///     is not needed. Otherwise must specify some [MacAlgorithm].
///
/// ## Example
/// ```dart
/// import 'package:cryptography_plus/cryptography_plus.dart';
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
abstract class Chacha20 extends StreamingCipher {
  /// Constructs a ChaCha20 with any MAC.
  ///
  /// Unless you really know what you are doing, you should use
  /// [Chacha20.poly1305Aead], which implements _AEAD_CHACHA20_POLY1305_ cipher
  /// (([RFC 7539](https://tools.ietf.org/html/rfc7539)).
  factory Chacha20({required MacAlgorithm macAlgorithm}) {
    if (macAlgorithm is DartChacha20Poly1305AeadMacAlgorithm) {
      return Cryptography.instance.chacha20Poly1305Aead();
    }
    return Cryptography.instance.chacha20(macAlgorithm: macAlgorithm);
  }

  /// Constructor for classes that extend this class.
  ///
  /// Optional parameter [random] is used by [newSecretKey] and [newNonce].
  const Chacha20.constructor({Random? random}) : super(random: random);

  /// Constructs ChaCha20-Poly1305-AEAD cipher
  /// (([RFC 7539](https://tools.ietf.org/html/rfc7539), also known as
  /// _AEAD_CHACHA20_POLY1305_), which is a popular authenticating cipher based
  /// on _ChaCha20_.
  ///
  /// If you use Flutter, you can enable
  /// [cryptography_flutter](https://pub.dev/packages/cryptography_flutter_plus).
  /// It can improve performance in many cases.
  ///
  /// ## Things to know
  ///   * [secretKeyLength] is 32 bytes.
  ///   * [nonceLength] is 12 bytes.
  ///   * MAC length is 16 bytes.
  ///   * Associated Authenticated Data (AAD) is supported.
  ///
  /// ## Example
  /// ```dart
  /// import 'package:cryptography_plus/cryptography_plus.dart';
  ///
  /// Future<void> main() async {
  ///   final message = <int>[1,2,3];
  ///
  ///   final algorithm = Chacha20.poly1305Aead();
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
      return '$runtimeType.poly1305Aead()';
    }
    return '$runtimeType(macAlgorithm: $macAlgorithm)';
  }

  @override
  DartChacha20 toSync() {
    if (macAlgorithm is DartChacha20Poly1305AeadMacAlgorithm) {
      return DartChacha20.poly1305Aead(
        random: random,
      );
    }
    return DartChacha20(
      macAlgorithm: macAlgorithm,
      random: random,
    );
  }
}

/// ECDH with P-256 / P-384 / P-521 elliptic curve.
///
/// Private keys must be instances of [EcKeyPair].
///
/// In browsers, the default implementation will use
/// [Web Cryptography API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API).
/// On other platforms, [DartEcdh] will be used.
///
/// If you use Flutter, you can enable
/// [cryptography_flutter](https://pub.dev/packages/cryptography_flutter_plus).
/// It can improve performance in many cases.
///
/// ## Things to know
///   * Private keys are instances of [EcKeyPair].
///   * Public keys are instances of [EcPublicKey].
///   * You can use [package:jwk](https://pub.dev/packages/jwk) to encode/decode
///     JSON Web Key (JWK) data.
///
/// ## Example
/// ```dart
/// import 'package:cryptography_plus/cryptography_plus.dart';
///
/// Future<void> main() async {
///   final algorithm = Ecdh.p256();
///
///   // We need the private key pair of Alice.
///   final aliceKeyPair = await algorithm.newKeyPair();
///
///   // We need only public key of Bob.
///   final bobKeyPair = await algorithm.newKeyPair();
///   final bobPublicKey = await bobKeyPair.extractPublicKey();
///
///   // We can now calculate a 32-byte shared secret key.
///   final sharedSecretKey = await algorithm.sharedSecretKey(
///     keyPair: aliceKeyPair,
///     remotePublicKey: bobPublicKey,
///   );
/// }
abstract class Ecdh extends KeyExchangeAlgorithm {
  /// Constructor for classes that extend this class.
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
  String toString() => '$runtimeType.p${keyPairType.ellipticBits}()';
}

/// ECDSA with P-256 / P-384 / P-521 elliptic curve.
///
/// For more information about ECDSA, read
/// [RFC 6090](https://www.ietf.org/rfc/rfc6090.txt)
/// ("Fundamental Elliptic Curve Cryptography Algorithms").
///
/// Key pairs must be instances of [EcKeyPair].
///
/// In browsers, the default implementation will use
/// [Web Cryptography API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API).
/// On other platforms, [DartEcdsa] will be used.
///
/// If you use Flutter, you can enable
/// [cryptography_flutter](https://pub.dev/packages/cryptography_flutter_plus).
/// It can improve performance in many cases.
///
/// ## Things to know
///   * Private keys are instances of [EcKeyPair].
///   * Public keys are instances of [EcPublicKey].
///   * You can use [package:jwk](https://pub.dev/packages/jwk) to encode/decode
///     JSON Web Key (JWK) data.
///
/// ## Example
/// ```
/// import 'package:cryptography_plus/cryptography_plus.dart';
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
  String toString() =>
      '$runtimeType.p${keyPairType.ellipticBits}($hashAlgorithm)';
}

/// _Ed25519_ ([RFC 8032](https://tools.ietf.org/html/rfc8032)) signature
/// algorithm.
///
/// By default, [DartEd25519] will be used.
/// If you use Flutter, you can enable
/// [cryptography_flutter](https://pub.dev/packages/cryptography_flutter_plus).
/// It can improve performance in many cases.
///
/// ## Things to know
///   * Private key is any 32 bytes ([SimpleKeyPair]).
///   * Public key is 32 bytes ([SimplePublicKey]).
///   * Output is 32 bytes.
///   * RFC 8032 says that the signatures are deterministic, but some widely
///     used implementations such as Apple CryptoKit return non-deterministic
///     signatures.
///   * You can use [package:jwk](https://pub.dev/packages/jwk) to encode/decode
///     JSON Web Key (JWK) data.
///
/// ## Example
/// ```
/// import 'package:cryptography_plus/cryptography_plus.dart';
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
///
/// ## In need of synchronous APIs?
///
/// If you need to perform operations synchronously, use [DartEd25519] in
/// _package:cryptography_plus/dart.dart_.
///
abstract class Ed25519 extends SignatureAlgorithm {
  final Random? _random;

  factory Ed25519() {
    return Cryptography.instance.ed25519();
  }

  /// Constructor for classes that extend this class.
  const Ed25519.constructor({Random? random}) : _random = random;

  @override
  Future<SimpleKeyPair> newKeyPair() {
    final seed = Uint8List(keyPairType.privateKeyLength);
    fillBytesWithSecureRandom(seed, random: _random);
    return newKeyPairFromSeed(seed);
  }

  @override
  Future<SimpleKeyPair> newKeyPairFromSeed(List<int> seed);

  @override
  String toString() => '$runtimeType()';
}

/// _Hchacha20_ ([draft-irtf-cfrg-xchacha](https://tools.ietf.org/html/draft-arciszewski-xchacha-03))
/// key derivation algorithm.
///
/// Hchacha20 produces a 256-bit secret key from 256-bit secret key and 96-bit
/// nonce. The algorithm is used by [Xchacha20].
///
/// The only implementation we have is [DartHChacha20].
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
/// [DartHkdf] is the pure Dart implementation of the HKDF algorithm. It's
/// used when no faster implementation is available.
///
/// In browsers, "package:cryptography" will automatically attempt to use
/// [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API),
/// which has very good HKDF performance.
///
/// Flutter developers should add [cryptography_flutter](https://pub.dev/packages/cryptography_flutter_plus),
/// as a dependency for the best possible HKDF performance.
///
/// ## Example
/// ```
/// import 'package:cryptography_plus/cryptography_plus.dart';
///
/// void main() async {
///   final algorithm = Hkdf(
///     hmac: Hmac.sha256(),
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

  const Hkdf.constructor();

  @override
  int get hashCode => 11 * hmac.hashCode ^ outputLength;

  Hmac get hmac;

  int get outputLength;

  @override
  bool operator ==(other) =>
      other is Hkdf && hmac == other.hmac && outputLength == other.outputLength;

  @override
  Future<SecretKeyData> deriveKey({
    required SecretKey secretKey,
    List<int> nonce = const <int>[],
    List<int> info = const <int>[],
  });

  @override
  String toString() => '$runtimeType($hmac)';
}

/// _HMAC_, a widely used [MacAlgorithm].
///
/// [DartHmac] is the pure Dart implementation of the HMAC algorithm. It's
/// used when no faster implementation is available.
///
/// In browsers, "package:cryptography" will automatically attempt to use
/// [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API),
/// which has very good HMAC performance.
///
/// Flutter developers should add [cryptography_flutter](https://pub.dev/packages/cryptography_flutter_plus),
/// as a dependency for the best possible HMAC performance.
///
/// ## Things to know
///   * You must choose some [HashAlgorithm]. We have shorthands constructors
///     such as [Hmac.sha256], but the hash algorithm can be anything.
///   * HMAC does not support nonces. Our implementation ignores any nonce.
///   * HMAC does not support AAD (Associated Authenticated Data). Our
///     implementation throws [ArgumentError] if you try to give some.
///
/// ## Constructors
///   * [Hmac.blake2b] for _HMAC-BLAKE2B_.
///   * [Hmac.blake2s] for _HMAC-BLAKE2S_.
///   * [Hmac.sha1] for _HMAC-SHA1_.
///   * [Hmac.sha224] for _HMAC-SHA224_.
///   * [Hmac.sha256] for _HMAC-SHA256_.
///   * [Hmac.sha384] for _HMAC-SHA384_.
///   * [Hmac.sha512] for _HMAC-SHA512_.
///   * For other combinations, give hash algorithm in the constructor
///     (example: `Hmac(Blake2s())`).
///
/// ## Example
/// ```
/// import 'package:cryptography_plus/cryptography_plus.dart';
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
///
/// ## Example: synchronous usage
/// [DartHmac], a pure Dart implementation of HMAC, can be used when you
/// absolutely need do computations synchronously:
///
/// ```dart
/// import 'package:cryptography_plus/cryptography_plus.dart';
/// import 'package:cryptography_plus/dart.dart';
///
/// void main() {
///   final algorithm = DartHmac.sha256();
///   final mac = algorithm.calculateMacSync(
///     bytes,
///     secretKey: secretKey,
///   );
/// }
/// ```
abstract class Hmac extends MacAlgorithm {
  /// Constructs HMAC with any hash algorithm.
  factory Hmac(HashAlgorithm hashAlgorithm) {
    return Cryptography.instance.hmac(hashAlgorithm);
  }

  /// HMAC-BLAKE2B.
  factory Hmac.blake2b() {
    return Hmac(Blake2b());
  }

  /// HMAC-BLAKE2S.
  factory Hmac.blake2s() {
    return Hmac(Blake2s());
  }

  /// Constructor for classes that extend this class.
  const Hmac.constructor();

  /// HMAC with [Sha1].
  factory Hmac.sha1() {
    return Hmac(Sha1());
  }

  /// HMAC with [Sha224].
  factory Hmac.sha224() {
    return Hmac(Sha224());
  }

  /// HMAC with [Sha256].
  factory Hmac.sha256() {
    return Hmac(Sha256());
  }

  /// HMAC with [Sha384].
  factory Hmac.sha384() {
    return Hmac(Sha384());
  }

  /// HMAC with [Sha512].
  factory Hmac.sha512() {
    return Hmac(Sha512());
  }

  /// Hash algorithm used by the HMAC.
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
      return '$runtimeType.sha256()';
    }
    if (hashAlgorithm is Sha512) {
      return '$runtimeType.sha512()';
    }
    return '$runtimeType($hashAlgorithm)';
  }

  @override
  DartHmac toSync() {
    return DartHmac(hashAlgorithm.toSync());
  }
}

/// _PBKDF2_ password hashing algorithm implemented in pure Dart.
///
/// [DartPbkdf2] is the pure Dart implementation of the PBKDF2 algorithm. It's
/// used when no faster implementation is available.
///
/// In browsers, "package:cryptography" will automatically attempt to use
/// [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API),
/// which has very good PBKDF2 performance.
///
/// Flutter developers should add [cryptography_flutter](https://pub.dev/packages/cryptography_flutter_plus),
/// as a dependency for the best possible PBKDF2 performance.
///
/// ## Things to know
///   * [macAlgorithm] can be any [MacAlgorithm] (such as [Hmac.sha256()]).
///   * [iterations] is the number of times output of hashing will be used as
///     input of the next hashing iteration. The idea of password hashing
///     algorithms is to make password hashing as slow as possible so the higher
///     the better. A good value is usually at least 10 000.
///   * [bits] is the number of bits you want as output. A good value may be
///     256 bits (32 bytes).
///   * PBKDF2 is a popular choice for password hashing, but much better
///     algorithms exists (such as [Argon2id]).
///
/// ## Example
/// ```dart
/// import 'package:cryptography_plus/cryptography_plus.dart';
///
/// Future<void> main() async {
///   final pbkdf2 = Pbkdf2(
///     macAlgorithm: Hmac.sha256(),
///     iterations: 10000, // 20k iterations
///     bits: 256, // 256 bits = 32 bytes output
///   );
///
///   // Calculate a hash that can be stored in the database
///   final newSecretKey = await pbkdf2.deriveKeyFromPassword(
///     // Password given by the user.
///     password: 'qwerty',
///
///     // Nonce (also known as "salt") should be some random sequence of
///     // bytes.
///     //
///     // You should have a different nonce for each user in the system
///     // (which you store in the database along with the hash).
///     // If you can't do that for some reason, choose a random value not
///     // used by other applications.
///     nonce: const [1,2,3],
///   );
///
///   final secretKeyBytes = await secretKey.extractBytes();
///   print('Result: $secretKeyBytes');
/// }
/// ```
abstract class Pbkdf2 extends KdfAlgorithm {
  /// Constructs PBKDF2 with any [MacAlgorithm].
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

  /// Constructor for subclasses.
  const Pbkdf2.constructor();

  /// Constructs PBKDF2 with [Hmac.sha256].
  factory Pbkdf2.hmacSha256({
    required int iterations,
    required int bits,
  }) {
    return Pbkdf2(
      macAlgorithm: Hmac.sha256(),
      iterations: iterations,
      bits: bits,
    );
  }

  /// Number of bits that will be returned by [deriveKey] method.
  int get bits;

  @override
  int get hashCode => macAlgorithm.hashCode ^ iterations ^ bits;

  /// Number of iterations.
  int get iterations;

  /// MAC algorithm.
  MacAlgorithm get macAlgorithm;

  @override
  bool operator ==(other) =>
      other is Pbkdf2 &&
      iterations == other.iterations &&
      bits == other.bits &&
      macAlgorithm == other.macAlgorithm;

  @override
  String toString() {
    return '$runtimeType(\n'
        '  macAlgorithm: $macAlgorithm,\n'
        '  iterations: $iterations,\n'
        '  bits: $bits,\n'
        ')';
  }

  /// Returns a pure Dart implementation of PBKDF2 with the same parameters.
  DartPbkdf2 toSync() {
    return DartPbkdf2(
      macAlgorithm: macAlgorithm.toSync(),
      iterations: iterations,
      bits: bits,
    );
  }
}

/// _Poly1305_ ([RFC 7539](https://tools.ietf.org/html/rfc7539)) [MacAlgorithm].
///
/// If you want ChaCha20 with Poly1305 MAC, you should use
/// [ChaCha20.poly1305Aead] constructor.
///
/// ## Things to know
///   * Produces a 128 bit authentication code.
///   * DO NOT use the same (key, nonce) tuple twice.
///   * DO NOT use the algorithm for key derivation.
///   * Poly1305 and Poly1305-AEAD ([DartChacha20Poly1305AeadMacAlgorithm])
///     are NOT the same.
abstract class Poly1305 extends MacAlgorithm {
  factory Poly1305() {
    return Cryptography.instance.poly1305();
  }

  /// Constructor for subclasses.
  const Poly1305.constructor();

  @override
  int get hashCode => (Poly1305).hashCode;

  @override
  int get macLength => 16;

  @override
  bool operator ==(other) => other is Poly1305;

  @override
  DartPoly1305 toSync() => const DartPoly1305();
}

/// _RSA-PSS_ [SignatureAlgorithm].
///
/// In browsers, the default implementation will use
/// [Web Cryptography API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API).
/// On other platforms, [DartRsaPss] will be used.
///
/// Private keys must be instances of [RsaKeyPair].
/// Public keys must be instances of [RsaPublicKey].
///
/// You can use [package:jwk](https://pub.dev/packages/jwk) to encode/decode
/// JSON Web Key (JWK) data.
///
/// ## Example
/// ```dart
/// import 'package:cryptography_plus/cryptography_plus.dart';
///
/// Future<void> main() async {
///   final algorithm = RsaPss(Sha256());
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
  /// Default nonce length (in bytes).
  static const int defaultNonceLengthInBytes = 16;

  /// Default modulus length (in bits).
  static const int defaultModulusLength = 4096;

  /// Default public exponent.
  static const List<int> defaultPublicExponent = <int>[0x01, 0x00, 0x01];

  /// Constructs RSA-PSS with the given hash algorithm.
  ///
  /// You can also choose a [nonceLengthInBytes] that is different from the
  /// default ([RsaPss.defaultNonceLengthInBytes]).
  factory RsaPss(
    HashAlgorithm hashAlgorithm, {
    int nonceLengthInBytes = defaultNonceLengthInBytes,
  }) {
    return Cryptography.instance.rsaPss(
      hashAlgorithm,
      nonceLengthInBytes: nonceLengthInBytes,
    );
  }

  /// Constructor for subclasses.
  const RsaPss.constructor();

  /// A shorthand for constructing RSA-PSS-SHA256.
  factory RsaPss.sha256({
    int nonceLengthInBytes = defaultNonceLengthInBytes,
  }) {
    return RsaPss(
      Sha256(),
      nonceLengthInBytes: nonceLengthInBytes,
    );
  }

  /// A shorthand for constructing RSA-PSS-SHA512.
  factory RsaPss.sha512({
    int nonceLengthInBytes = defaultNonceLengthInBytes,
  }) {
    return RsaPss(
      Sha512(),
      nonceLengthInBytes: nonceLengthInBytes,
    );
  }

  /// Hash algorithm used by the RSA-PSS.
  HashAlgorithm get hashAlgorithm;

  @override
  int get hashCode => (RsaSsaPkcs1v15).hashCode ^ hashAlgorithm.hashCode;

  @override
  KeyPairType<KeyPairData, PublicKey> get keyPairType => KeyPairType.rsa;

  int get nonceLengthInBytes;

  @override
  bool operator ==(other) =>
      other is RsaPss &&
      hashAlgorithm == other.hashAlgorithm &&
      nonceLengthInBytes == other.nonceLengthInBytes;

  @override
  Future<RsaKeyPair> newKeyPair({
    int modulusLength = defaultModulusLength,
    List<int> publicExponent = defaultPublicExponent,
  });

  @override
  String toString() =>
      '$runtimeType($hashAlgorithm, nonceLengthInBytes: $nonceLengthInBytes)';
}

/// _RSA-SSA-PKCS1v15_ [SignatureAlgorithm].
///
/// In browsers, the default implementation will use
/// [Web Cryptography API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API).
/// On other platforms, [DartRsaSsaPkcs1v15] will be used.
///
/// Private keys must be instances of [RsaKeyPair].
/// Public keys must be instances of [RsaPublicKey].
///
/// You can use [package:jwk](https://pub.dev/packages/jwk) to encode/decode
/// JSON Web Key (JWK) data.
///
/// ## Example
/// ```
/// import 'package:cryptography_plus/cryptography_plus.dart';
///
/// Future<void> main() async {
///   final algorithm = RsaSsaPkcs1v15(Sha256());
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

  /// Constructor for subclasses.
  const RsaSsaPkcs1v15.constructor();

  /// A shorthand for RSA-SSA-PKCS1v15-SHA256.
  factory RsaSsaPkcs1v15.sha256() {
    return RsaSsaPkcs1v15(Sha256());
  }

  /// A shorthand for RSA-SSA-PKCS1v15-SHA512.
  factory RsaSsaPkcs1v15.sha512() {
    return RsaSsaPkcs1v15(Sha512());
  }

  /// Hashing algorithm.
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
  String toString() => '$runtimeType(hashAlgorithm: $hashAlgorithm)';
}

/// _SHA-1_ [HashAlgorithm].
///
/// In browsers, the default implementation will use
/// [Web Cryptography API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API).
/// On other platforms, [DartSha1] will be used.
///
/// ## Asynchronous usage (recommended)
/// ```
/// import 'package:cryptography_plus/cryptography_plus.dart';
///
/// Future<void> main() async {
///   final message = <int>[1,2,3];
///   final algorithm = Sha1();
///   final hash = await algorithm.hash(message);
///   print('Hash: ${hash.bytes}');
/// }
/// ```
///
/// If you really need synchronous computations, use [DartSha1].
///
/// ## Streaming usage
/// This enables you to handle very large inputs without keeping everything in
/// memory:
/// ```
/// import 'package:cryptography_plus/cryptography_plus.dart';
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
abstract class Sha1 extends HashAlgorithm {
  factory Sha1() => Cryptography.instance.sha1();

  /// Constructor for classes that extend this class.

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
  DartHashAlgorithm toSync() => const DartSha1();
}

/// _SHA-224_ (SHA2-224) [HashAlgorithm].
///
/// By default, [DartSha224] will be used.
///
/// ## Asynchronous usage (recommended)
/// ```
/// import 'package:cryptography_plus/cryptography_plus.dart';
///
/// Future<void> main() async {
///   final message = <int>[1,2,3];
///   final algorithm = Sha224();
///   final hash = await algorithm.hash(message);
///   print('Hash: ${hash.bytes}');
/// }
/// ```
///
/// If you really need synchronous computations, use [DartSha224].
///
/// ## Streaming usage
/// This enables you to handle very large inputs without keeping everything in
/// memory:
/// ```
/// import 'package:cryptography_plus/cryptography_plus.dart';
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
abstract class Sha224 extends HashAlgorithm {
  factory Sha224() => Cryptography.instance.sha224();

  /// Constructor for classes that extend this class.

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
  DartHashAlgorithm toSync() => const DartSha224();
}

/// _SHA-256_ (SHA2-256) [HashAlgorithm].
///
/// In browsers, the default implementation will use
/// [Web Cryptography API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API).
/// On other platforms, [DartSha256] will be used.
///
/// ## Asynchronous usage (recommended)
/// ```
/// import 'package:cryptography_plus/cryptography_plus.dart';
///
/// Future<void> main() async {
///   final message = <int>[1,2,3];
///   final algorithm = Sha256();
///   final hash = await algorithm.hash(message);
///   print('Hash: ${hash.bytes}');
/// }
/// ```
///
/// If you really need synchronous computations, use [DartSha256].
///
/// ## Streaming usage
/// This enables you to handle very large inputs without keeping everything in
/// memory:
/// ```
/// import 'package:cryptography_plus/cryptography_plus.dart';
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
abstract class Sha256 extends HashAlgorithm {
  factory Sha256() => Cryptography.instance.sha256();

  /// Constructor for classes that extend this class.

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
  DartHashAlgorithm toSync() => const DartSha256();
}

/// _SHA-384_ (SHA2-384) [HashAlgorithm].
///
/// In browsers, the default implementation will use
/// [Web Cryptography API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API).
/// On other platforms, [DartSha384] will be used.
///
/// ## Asynchronous usage (recommended)
/// ```
/// import 'package:cryptography_plus/cryptography_plus.dart';
///
/// Future<void> main() async {
///   final message = <int>[1,2,3];
///   final algorithm = Sha384();
///   final hash = await algorithm.hash(message);
///   print('Hash: ${hash.bytes}');
/// }
/// ```
///
/// If you really need synchronous computations, use [DartSha384].
///
/// ## Streaming usage
/// This enables you to handle very large inputs without keeping everything in
/// memory:
/// ```
/// import 'package:cryptography_plus/cryptography_plus.dart';
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
abstract class Sha384 extends HashAlgorithm {
  factory Sha384() => Cryptography.instance.sha384();

  /// Constructor for classes that extend this class.

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
  DartHashAlgorithm toSync() => const DartSha384();
}

/// _SHA-512_ [HashAlgorithm] (sometimes called _SHA2-512_).
///
/// In browsers, the default implementation will use
/// [Web Cryptography API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API).
/// On other platforms, [DartSha512] will be used.
///
/// ## Asynchronous usage (recommended)
/// ```
/// import 'package:cryptography_plus/cryptography_plus.dart';
///
/// Future<void> main() async {
///   final message = <int>[1,2,3];
///   final algorithm = Sha512();
///   final hash = await algorithm.hash(message);
///   print('Hash: ${hash.bytes}');
/// }
/// ```
///
/// If you really need synchronous computations, use [DartSha512].
///
/// ## Streaming usage
/// This enables you to handle very large inputs without keeping everything in
/// memory:
/// ```
/// import 'package:cryptography_plus/cryptography_plus.dart';
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
abstract class Sha512 extends HashAlgorithm {
  factory Sha512() => Cryptography.instance.sha512();

  /// Constructor for classes that extend this class.

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
  DartHashAlgorithm toSync() => const DartSha512();
}

/// Superclass of streaming ciphers such as [AesGcm] and [Chacha20] that allow
/// encrypter/decrypter to choose an offset in the keystream.
abstract class StreamingCipher extends Cipher {
  /// Constructor for subclasses.
  ///
  /// Optional parameter [random] is used by [newSecretKey] and [newNonce].
  const StreamingCipher({Random? random}) : super(random: random);

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
    Uint8List? possibleBuffer,
  });

  /// Encrypts a cleartext.
  ///
  /// Parameter [keyStreamIndex] allows you to choose offset in the keystream.
  ///
  /// For other arguments, see [Cipher.encrypt].
  @override
  Future<SecretBox> encrypt(
    List<int> clearText, {
    required SecretKey secretKey,
    List<int>? nonce,
    List<int> aad = const <int>[],
    int keyStreamIndex = 0,
    Uint8List? possibleBuffer,
  });
}

/// _X25519_ ([RFC 7748](https://tools.ietf.org/html/rfc7748))
/// [KeyExchangeAlgorithm].
///
/// X25519 is an elliptic curve Diffie-Hellman key exchange algorithm that uses
/// Curve25519.
///
/// By default, [DartX25519] will be used.
/// If you use Flutter, you can enable
/// [cryptography_flutter](https://pub.dev/packages/cryptography_flutter_plus).
/// It can improve performance in many cases.
///
/// ## Things to know
///   * Private key is any 32 bytes ([SimpleKeyPair]).
///   * Public key is 32 bytes ([SimplePublicKey]).
///   * Output is 32 bytes.
///   * You can use [package:jwk](https://pub.dev/packages/jwk) to encode/decode
///     JSON Web Key (JWK) data.
///
/// ## Example
/// ```
/// import 'package:cryptography_plus/cryptography_plus.dart';
///
/// Future<void> main() async {
///   final algorithm = X25519();
///
///   // We need the private key pair of Alice.
///   final aliceKeyPair = await algorithm.newKeyPair();
///
///   // We need only public key of Bob.
///   final bobKeyPair = await algorithm.newKeyPair();
///   final bobPublicKey = await bobKeyPair.extractPublicKey();
///
///   // We can now calculate a 32-byte shared secret key.
///   final sharedSecretKey = await algorithm.sharedSecretKey(
///     keyPair: aliceKeyPair,
///     remotePublicKey: bobPublicKey,
///   );
/// }
///
/// ## In need of synchronous APIs?
///
/// If you need to perform operations synchronously, use [DartX25519] in
/// _package:cryptography_plus/dart.dart_.
///
abstract class X25519 extends KeyExchangeAlgorithm {
  final Random? _random;

  factory X25519() {
    return Cryptography.instance.x25519();
  }

  /// Constructor for classes that extend this class.
  const X25519.constructor({Random? random}) : _random = random;

  @override
  Future<SimpleKeyPair> newKeyPair() {
    final seed = Uint8List(keyPairType.privateKeyLength);
    fillBytesWithSecureRandom(seed, random: _random);
    return newKeyPairFromSeed(seed);
  }

  @override
  Future<SimpleKeyPair> newKeyPairFromSeed(List<int> seed);

  @override
  String toString() => '$runtimeType()';
}

/// _Xchacha20_ ([draft-irtf-cfrg-xchacha](https://tools.ietf.org/html/draft-arciszewski-xchacha-03)).
/// cipher.
///
/// The only difference between _Xchacha20_ and [Chacha20] is that _Xchacha20_
/// uses 192-bit nonces whereas _Chacha20_ uses 96-bit nonces.
///
/// By default, [DartXchacha20] will be used.
///
/// If you use Flutter, you can enable
/// [cryptography_flutter](https://pub.dev/packages/cryptography_flutter_plus).
/// It can improve performance in many cases.
///
/// ## Things to know
///   * Secret key must be 32 bytes.
///   * Nonce must be 24 bytes.
///   * `keyStreamIndex` enables choosing index in the key  stream.
///   * It's dangerous to use the same (key, nonce) combination twice.
///   * It's dangerous to use the cipher without authentication.
abstract class Xchacha20 extends StreamingCipher {
  factory Xchacha20({required MacAlgorithm macAlgorithm}) {
    return Cryptography.instance.xchacha20(macAlgorithm: macAlgorithm);
  }

  /// Constructor for classes that extend this class.
  const Xchacha20.constructor({Random? random}) : super(random: random);

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

  @override
  String toString() {
    return '$runtimeType(macAlgorithm: $macAlgorithm)';
  }

  @override
  DartXchacha20 toSync() => DartXchacha20(macAlgorithm: macAlgorithm);
}
