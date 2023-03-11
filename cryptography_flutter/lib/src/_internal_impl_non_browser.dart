// Copyright 2019-2020 Gohilla.
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

import 'dart:io';

final bool isAndroid = Platform.isAndroid;

final bool isIOS = Platform.isIOS;

final bool isMacOS = Platform.isMacOS;

/// For example, "iOS 13.3.1".
String get operatingSystemNameAndVersion =>
    '${Platform.operatingSystem} ${Platform.operatingSystemVersion}';

/// For example, "iOS".
String get operatingSystemName => Platform.operatingSystem;
