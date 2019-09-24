// Copyright 2019 Gohilla (opensource@gohilla.com).
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

/// For ensuring that result of calculation will be 32-bit integer.
const int uint32mask = 0xFFFFFFFF;

/// Rotates 32-bit integer to the left.
int rotateLeft32(int value, int shift) {
  assert(shift >= 0 && shift <= 32);
  return (uint32mask & (value << shift)) | (value >> (32 - shift));
}

/// Rotates 32-bit integer to the right.
int rotateRight32(int value, int shift) {
  assert(shift >= 0 && shift <= 32);
  return (uint32mask & (value << (32 - shift))) | (value >> shift);
}
