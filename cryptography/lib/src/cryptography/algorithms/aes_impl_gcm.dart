// Copyright 2019-2020 Gohilla Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import 'package:cryptography/cryptography.dart';

import 'aes_impl_base.dart';

const Cipher dartAesGcm = _AesGcm();

class _AesGcm extends AesCipher {
  const _AesGcm();

  @override
  bool get isAuthenticated => true;

  @override
  String get name => 'aesGcm';

  @override
  int get nonceLength => 12;

  @override
  List<int> decryptSync(List<int> input,
      {SecretKey secretKey,
      Nonce nonce,
      List<int> aad,
      int keyStreamIndex = 0}) {
    throw UnimplementedError();
  }

  @override
  List<int> encryptSync(List<int> input,
      {SecretKey secretKey,
      Nonce nonce,
      List<int> aad,
      int keyStreamIndex = 0}) {
    throw UnimplementedError();
  }
}
