# Introduction

If you are implementing a cryptographic algorithm that implements interfaces of
[pub.dev/packages/cryptography_plus](https://pub.dev/packages/cryptography_plus), this package helps you test
that:

- Your implementation complies with the API specifications.
- Your implementation doesn't fail any sanity checks.
- Your implementation produces same outputs as some existing implementation (when there is one).

# Usage

In pubspec.yaml:

```yaml
dev_dependencies:
  cryptography_test: any
```

If you have something like:

```dart
import 'package:cryptography_plus/cryptography_plus.dart';

class MyExample extends Cipher {
  // ...
}
```

Your unit tests will look like:

```dart
import 'package:cryptography_test/cryptography_test.dart';
import 'package:cryptography_test/cipher.dart';

void main() {
  testCipher(
    builder: () => MyCipher(someParameter: 123),
    // `testCipher` will do various automatic sanity checks such as:
    //   decrypt(encrypt(input))
    // ...with various interesting inputs.
    //
    // You can give it real test vectors too:
    otherTests: () {
      test('test vector', () async {
        await expectCipherExample(
          clearText: hexToBytes('01 23 45 67 89 ab cd ef'),
          secretKey: hexToBytes('01 23 45 67 89 ab cd ef'),
          nonce: hexToBytes('01 23 45 67 89 ab cd ef'),
          aad: hexToBytes('01 23 45 67 89 ab cd ef'),
          cipherText: hexToBytes('01 23 45 67 89 ab cd ef'),
          mac: hexToBytes('01 23 45 67 89 ab cd ef'),
        );
      });
    },
  );
}
```
