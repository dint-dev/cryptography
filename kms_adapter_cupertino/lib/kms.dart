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

library kms_adapter_cupertino;

import 'package:kms/kms.dart';
import 'package:meta/meta.dart';

class CupertinoKms extends KmsBase {
  const CupertinoKms({Kms wrapped}) : super(wrapped: wrapped);

  @override
  Future<KmsKey> createKeyPair({
    @required String keyRingId,
    @required KeyExchangeType keyExchangeType,
    @required SignatureType signatureType,
    String id,
  }) {
    throw UnimplementedError();
  }

  @override
  Future<void> delete(KmsKey kmsKey) {
    throw UnimplementedError();
  }

  @override
  Future<SecretKey> sharedSecret({
    @required KmsKey kmsKey,
    @required PublicKey remotePublicKey,
    @required KeyExchangeType keyExchangeType,
  }) {
    throw UnimplementedError();
  }

  @override
  Future<Signature> sign(
    List<int> bytes, {
    @required KmsKey kmsKey,
    @required SignatureType signatureType,
  }) {
    throw UnimplementedError();
  }
}
