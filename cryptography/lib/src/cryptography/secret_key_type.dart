// // Copyright 2019-2020 Gohilla.
// //
// // Licensed under the Apache License, Version 2.0 (the "License");
// // you may not use this file except in compliance with the License.
// // You may obtain a copy of the License at
// //
// // http://www.apache.org/licenses/LICENSE-2.0
// //
// // Unless required by applicable law or agreed to in writing, software
// // distributed under the License is distributed on an "AS IS" BASIS,
// // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// // See the License for the specific language governing permissions and
// // limitations under the License.
//
// import 'package:cryptography_plus/cryptography_plus.dart';
// import 'package:meta/meta.dart';
//
// class SecretKeyType {
//   static const SecretKeyType aes = SecretKeyType._(
//     name: 'aes',
//     possibleLengths: {16, 24, 32},
//   );
//
//   static const SecretKeyType chacha20 = SecretKeyType._(
//     name: 'chacha20',
//     possibleLengths: {32},
//   );
//
//   static const SecretKeyType unspecified = SecretKeyType._(
//     name: 'unspecified',
//     possibleLengths: {},
//   );
//
//   final String name;
//   final Set<int> possibleLengths;
//
//   @literal
//   const SecretKeyType._({
//     required this.name,
//     required this.possibleLengths,
//   });
//
//   bool isValidKeyLength(int length) {
//     if (possibleLengths.isEmpty) {
//       return true;
//     }
//     return possibleLengths.contains(length);
//   }
//
//   bool isValidSecretKeyData(SecretKeyData secretKeyData) {
//     final type = secretKeyData.type;
//     if (this != type && SecretKeyType.unspecified != type) {
//       return false;
//     }
//     return isValidKeyLength(secretKeyData.bytes.length);
//   }
//
//   @override
//   String toString() => 'SecretKeyType.$name';
// }
