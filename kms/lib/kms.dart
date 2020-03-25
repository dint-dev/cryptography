// Copyright 2019 Gohilla Ltd (https://gohilla.com).
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

/// A vendor-agnostic API for using Key Management Service (KMS) products/APIs.
library kms;

export 'src/kms_base.dart';
export 'src/kms.dart';
export 'src/kms_key.dart';
export 'src/memory_kms.dart';

export 'package:cryptography/cryptography.dart'
    show PublicKey, SecretKey, Nonce;
