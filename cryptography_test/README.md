# Introduction

If you are implementing a cryptographic algorithm that implements interfaces of
[pub.dev/packages/cryptography](https://pub.dev/packages/cryptography), this package helps you test
that:
  * Your implementation complies with the API specifications.
  * Your implementation doesn't fail any sanity checks.
  * Your implementation produces same outputs as some existing implementation (when there is one).

# Usage
In pubspec.yaml:
```yaml
dev_dependencies:
  cryptography_test: any
```

In your test file:
```dart
import 'package:cryptography_test/cryptography_test.dart';
import 'package:cryptography_test/cipher.dart';

void main() {
  testCipher(
    builder: () => MyCipher(),
    otherTests: () {
      test('test vector', () async {
        await expectCipherExample(
          clearText: hexToBytes('aa bb cc dd'),
          secretKey: hexToBytes('aa bb cc dd'),
          nonce: hexToBytes('aa bb cc dd'),
          aad: hexToBytes('aa bb cc dd'),
          cipherText: hexToBytes('aa bb cc dd'),
          mac: hexToBytes('aa bb cc dd'),
        );
      });
    },
  );
}
```