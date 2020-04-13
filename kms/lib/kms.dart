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

/// A vendor-agnostic API for using Key Management Service (KMS) products/APIs.
library kms;

export 'package:cryptography/cryptography.dart'
    show PublicKey, SecretKey, Nonce;

export 'src/algorithm_types.dart';
export 'src/kms.dart';
export 'src/kms_base.dart';
export 'src/kms_key.dart';
export 'src/kms_key_query.dart';
export 'src/memory_kms.dart';
