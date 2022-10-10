import 'package:cryptography/cryptography.dart';
import 'package:cryptography/dart.dart';

Future<void> main() async {
  try {
    // NOTE: If using addPadding, MAC authentication will not pass.
    MacAlgorithm macAlgorithm = MacAlgorithm.empty;
    final DartAesCbc dartAesCbc = DartAesCbc(
      macAlgorithm: macAlgorithm,
      secretKeyLength: 32,
    );

    final SecretKey secretKey = await dartAesCbc.newSecretKeyFromBytes([
      int.parse('60', radix: 16),
      int.parse('3d', radix: 16),
      int.parse('eb', radix: 16),
      int.parse('10', radix: 16),
      int.parse('15', radix: 16),
      int.parse('ca', radix: 16),
      int.parse('71', radix: 16),
      int.parse('be', radix: 16),
      int.parse('2b', radix: 16),
      int.parse('73', radix: 16),
      int.parse('ae', radix: 16),
      int.parse('f0', radix: 16),
      int.parse('85', radix: 16),
      int.parse('7d', radix: 16),
      int.parse('77', radix: 16),
      int.parse('81', radix: 16),
      int.parse('1f', radix: 16),
      int.parse('35', radix: 16),
      int.parse('2c', radix: 16),
      int.parse('07', radix: 16),
      int.parse('3b', radix: 16),
      int.parse('61', radix: 16),
      int.parse('08', radix: 16),
      int.parse('d7', radix: 16),
      int.parse('2d', radix: 16),
      int.parse('98', radix: 16),
      int.parse('10', radix: 16),
      int.parse('a3', radix: 16),
      int.parse('09', radix: 16),
      int.parse('14', radix: 16),
      int.parse('df', radix: 16),
      int.parse('f4', radix: 16),
    ]);

    List<int> initialNonce = [
      51,
      15,
      17,
      218,
      210,
      125,
      138,
      35,
      140,
      250,
      29,
      52,
      232,
      180,
      151,
      213
    ];
    List<int> nextNonce = initialNonce;

    print('----------------------Encrypting----------------------------');
    print('secretKey... \n${hexFromBytes(await secretKey.extractBytes())}');
    print('initialNonce... \n${hexFromBytes(initialNonce)}');

    // Try with each range to show that padding works...
    List<int> inputBytes = List.filled(1023, 0);
    //List<int> inputBytes = List.filled(1024, 0);
    //List<int> inputBytes = List.filled(1025, 0);

    print('--------------------------------------------------------------');
    print('inputBytes: \n${hexFromBytes(inputBytes)}');

    // DartAesCbc chunked Loop
    int kChunkLength = 256; // must be a multiple of 16 (128 bits)
    int paddingLength = 16 - inputBytes.length % 16;
    late SecretBox secretBoxDart;

    bool addPadding = false;
    int endOfChunk = 0;

    print('inputBytes.length: ${inputBytes.length}');
    print('paddingLength:     $paddingLength');

    List<int> encryptedBytes = <int>[];

    int remainingBytes = 0;

    for (int inputOffset = 0;
        inputOffset < inputBytes.length;
        inputOffset += kChunkLength) {
      if (inputOffset + kChunkLength >= inputBytes.length) {
        // add padding if this is the final block
        remainingBytes = (inputOffset + kChunkLength) - inputBytes.length;
        addPadding = true;
      }

      endOfChunk = inputOffset + kChunkLength - remainingBytes;

      secretBoxDart = await dartAesCbc.encrypt(
        inputBytes.sublist(inputOffset, endOfChunk),
        secretKey: secretKey,
        nonce: nextNonce,
        addPadding: addPadding,
      );

      // set the latest ciphertext block as the next nonce
      nextNonce = secretBoxDart.cipherText
          .sublist(secretBoxDart.cipherText.length - 16);

      // accumulate the chunk of encrypted bytes
      encryptedBytes.addAll(secretBoxDart.cipherText);
    }

    print('--------------------------------------------------------------');
    print('encryptedBytes... \n${hexFromBytes(encryptedBytes)}');

    print('----------------------Decrypting----------------------------');
    print('secretKey... \n${hexFromBytes(await secretKey.extractBytes())}');
    print('initialNonce... \n${hexFromBytes(initialNonce)}');

    List<int> decryptedBytes = <int>[];
    bool removePadding = false;

    nextNonce = initialNonce;

    for (int inputOffset = 0;
        inputOffset < encryptedBytes.length;
        inputOffset += kChunkLength) {
      // remove padding if this is the last chunk
      removePadding = (inputOffset + kChunkLength >= encryptedBytes.length);

      decryptedBytes.addAll(await dartAesCbc.decrypt(
        SecretBox(
          encryptedBytes.sublist(inputOffset, inputOffset + kChunkLength),
          nonce: nextNonce,
          mac: Mac.empty,
        ),
        secretKey: secretKey,
        removePadding: removePadding,
      ));

      // set the latest ciphertext block as the next nonce
      nextNonce = encryptedBytes.sublist(
          (inputOffset + kChunkLength) - 16, inputOffset + kChunkLength);
    }

    // assert that all input bytes are equal to decrypted bytes
    for (int i = 0; i < inputBytes.length; i++) {
      assert(inputBytes[i].toRadixString(16) ==
          decryptedBytes[i].toRadixString(16));
    }

    print('decryptedBytes: \n${hexFromBytes(decryptedBytes)}');
  } catch (e) {
    print(e);
  }
}

/// Converts a list of bytes to a hexadecimal string.
String hexFromBytes(Iterable<int> iterable) {
  final list = iterable.toList();
  final sb = StringBuffer();
  for (var i = 0; i < list.length; i++) {
    if (i > 0) {
      if (i % 16 == 0) {
        sb.write('\n');
      } else {
        sb.write(' ');
      }
    }
    sb.write(list[i].toRadixString(16).padLeft(2, '0'));
  }
  return sb.toString();
}
