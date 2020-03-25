#!/bin/sh
set -e
cd `dirname $0`

cd cryptography
pub run test
cd ..

cd kms
pub run test
cd ..

cd kms_adapter_cupertino
pub run test
cd ..