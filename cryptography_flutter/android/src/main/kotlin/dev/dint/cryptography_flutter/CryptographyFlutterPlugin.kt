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

package dev.dint.cryptography_flutter

import android.os.Build
import androidx.annotation.RequiresApi
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import io.flutter.plugin.common.PluginRegistry.Registrar
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.NoSuchAlgorithmException
import java.security.Signature
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.*
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/** CryptographyFlutterPlugin */
class CryptographyFlutterPlugin : FlutterPlugin, MethodCallHandler {
    private lateinit var channel: MethodChannel

    override fun onAttachedToEngine(flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
        channel = MethodChannel(flutterPluginBinding.binaryMessenger, "cryptography_flutter")
        channel.setMethodCallHandler(this)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
    }

    override fun onMethodCall(call: MethodCall, result: Result) {
        when (call.method) {
            "decrypt" -> {
                propagateError(result) {
                    decrypt(call, result)
                }
            }
            "encrypt" -> {
                propagateError(result) {
                    encrypt(call, result)
                }
            }
            "Ecdsa.KeyPair" -> {
                propagateError(result) {
                    ecNewKeyPair(call, result)
                }
            }
            "Ecdsa.sign" -> {
                propagateError(result) {
                    ecdsaSign(call, result)
                }
            }
            "Ecdsa.verify" -> {
                propagateError(result) {
                    ecdsaVerify(call, result)
                }
            }
            else -> {
                result.notImplemented()
            }
        }
    }

    private fun <T> propagateError(result: MethodChannel.Result, fn: () -> T) {
        try {
            fn()
        } catch (e: Exception) {
            result.error("CATCHED_ERROR", e.message, null)
        }
    }


    private fun decrypt(call: MethodCall, result: Result) {
        val dartAlgo = call.argument<String>("algo")!!
        val algo = when (dartAlgo) {
            "AesCbc" -> "AES"
            "AesCtr" -> "AES"
            "AesGcm" -> "AES"
            "Chacha20" -> "Chacha20"
            "Chacha20.poly1305Aead" -> "Chacha20"
            else -> null
        }
        if (algo == null) {
            result.error("UNSUPPORTED_ALGORITHM", "Unsupported algorithm: $dartAlgo", null)
            return
        }
        val mode = when (dartAlgo) {
            "AesCbc" -> "CBC"
            "AesCtr" -> "CTR"
            "AesGcm" -> "GCM"
            "Chacha20.poly1305Aead" -> "Poly1305"
            else -> null
        }
        val cipherText = call.argument<ByteArray>("cipherText")!!
        val secretKey = call.argument<ByteArray>("secretKey")!!
        val nonce = call.argument<ByteArray>("nonce")!!
        val mac = call.argument<ByteArray>("mac")!!
        val input = cipherText + mac

        // Handle the request
        val params = if (mode == "GCM") {
            GCMParameterSpec(16 * 8, nonce)
        } else {
            IvParameterSpec(nonce)
        }
        var cipher: Cipher;
        val instanceId = "$algo/$mode/NoPadding"
        try {
            cipher = Cipher.getInstance(instanceId)
        } catch (error: NoSuchAlgorithmException) {
            result.error("UNSUPPORTED_ALGORITHM", "Android does not support ${instanceId}", null)
            return
        }
        cipher.init(
                Cipher.DECRYPT_MODE,
                SecretKeySpec(secretKey, algo),
                params,
        )
        val clearText: ByteArray
        try {
            clearText = cipher.doFinal(input)
        } catch (e: AEADBadTagException) {
            result.error("INCORRECT_MAC", null, null)
            return
        }
        result.success(hashMapOf(
                "clearText" to clearText,
        ))
    }

    private fun encrypt(call: MethodCall, result: Result) {
        val dartAlgo = call.argument<String>("algo")!!
        val algo = when (dartAlgo) {
            "AesCbc" -> "AES"
            "AesCtr" -> "AES"
            "AesGcm" -> "AES"
            "Chacha20" -> "ChaCha20"
            "Chacha20.poly1305Aead" -> "ChaCha20"
            else -> null
        }
        if (algo == null) {
            result.error("UNSUPPORTED_ALGORITHM", null, null)
            return
        }
        val mode = when (dartAlgo) {
            "AesCbc" -> "CBC"
            "AesCtr" -> "CTR"
            "AesGcm" -> "GCM"
            "Chacha20.poly1305Aead" -> "Poly1305"
            else -> "None"
        }
        val macLength = when (dartAlgo) {
            "AesGcm" -> 16
            "Chacha20.poly1305Aead" -> 16
            else -> 0
        }
        val clearText = call.argument<ByteArray>("clearText")!!
        val secretKey = call.argument<ByteArray>("secretKey")!!
        val nonce = call.argument<ByteArray>("nonce")!!

        // Handle the request
        val params = if (mode == "GCM") {
            GCMParameterSpec(macLength * 8, nonce)
        } else {
            IvParameterSpec(nonce)
        }
        var cipher: Cipher
        val instanceId = "$algo/$mode/NoPadding"
        try {
            cipher = Cipher.getInstance(instanceId)
        } catch (error: NoSuchAlgorithmException) {
            result.error("UNSUPPORTED_ALGORITHM", "Android does not support ${instanceId}", null)
            return
        }
        cipher.init(
                Cipher.ENCRYPT_MODE,
                SecretKeySpec(secretKey, algo),
                params,
        )
        val cipherTextAndMac = cipher.doFinal(clearText)
        val cipherText = cipherTextAndMac.copyOfRange(0, cipherTextAndMac.size - macLength)
        val mac = cipherTextAndMac.copyOfRange(cipherTextAndMac.size - macLength, cipherTextAndMac.size)
        result.success(hashMapOf(
                "cipherText" to cipherText,
                "mac" to mac,
        ))
    }

    private fun ecNewKeyPair(call: MethodCall, result: Result) {
        val dartAlgo = call.argument<String>("algo")!!
        val curve = when (dartAlgo) {
            "Ecdsa.p256" -> "P-256"
            "Ecdsa.p384" -> "P-384"
            "Ecdsa.p521" -> "P-521"
            else -> null
        }
        if (curve == null) {
            result.error("UNSUPPORTED_ALGORITHM", "Unsupported algorithm: $curve", null)
            return
        }

    }

    private fun ecdsaSign(call: MethodCall, result: Result) {
        val curve = when (call.argument<String>("algo")!!) {
            "Ecdsa.p256" -> "P-256"
            "Ecdsa.p384" -> "P-384"
            "Ecdsa.p521" -> "P-521"
            else -> null
        }
        if (curve == null) {
            result.error("UNSUPPORTED_ALGORITHM", "Unsupported algorithm: $curve", null)
            return
        }
        val hash = call.argument<String>("hash")!!.replace("-", "")
        val data = call.argument<ByteArray>("data")!!
        val privateKey = call.argument<ByteArray>("privateKey")!!

        // Handle the request
        val parameters = AlgorithmParameters.getInstance("EC")
        parameters.init(ECGenParameterSpec("secp256r1"))
        val ecParameters = parameters.getParameterSpec(ECParameterSpec::class.java)
        val privateSpec = ECPrivateKeySpec(BigInteger(privateKey), ecParameters)
        val kf = KeyFactory.getInstance("EC")
        val key = kf.generatePrivate(privateSpec) as ECPrivateKey
        val dsa = Signature.getInstance(hash + "withECDSA")
        dsa.initSign(key);
        dsa.update(data)
        val signature = dsa.sign()

        // Set result
        result.success(hashMapOf(
                "signature" to signature,
        ))
    }

    private fun ecdsaVerify(call: MethodCall, result: Result) {
        val curve = when (call.argument<String>("algo")!!) {
            "Ecdsa.p256" -> "P-256"
            "Ecdsa.p384" -> "P-384"
            "Ecdsa.p521" -> "P-521"
            else -> null
        }
        if (curve == null) {
            result.error("UNSUPPORTED_ALGORITHM", null, null)
            return
        }
        val hash = call.argument<String>("hash")!!.replace("-", "")
        val message = call.argument<ByteArray>("data")!!
        val x = BigInteger(call.argument<String>("x")!!)
        val y = BigInteger(call.argument<String>("y")!!)
        val signature = call.argument<ByteArray>("signature")!!

        // Handle the request
        val publicPoint = ECPoint(x, y)
        val parameters = AlgorithmParameters.getInstance("EC")
        parameters.init(ECGenParameterSpec(curve))
        val ecParameters = parameters.getParameterSpec(ECParameterSpec::class.java)
        val publicSpec = ECPublicKeySpec(publicPoint, ecParameters)
        val kf = KeyFactory.getInstance("EC")
        val key = kf.generatePublic(publicSpec) as ECPublicKey
        val dsa = Signature.getInstance(hash + "withECDSA")
        dsa.initVerify(key)
        dsa.update(message)
        val ok = dsa.verify(signature)

        // Set result
        result.success(hashMapOf(
                "ok" to ok,
        ))
    }
}
