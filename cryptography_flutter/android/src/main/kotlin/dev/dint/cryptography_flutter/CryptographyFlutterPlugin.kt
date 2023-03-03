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
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.Mac
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
        try {
            when (call.method) {
                "encrypt" -> encrypt(call, result)
                "decrypt" -> decrypt(call, result)
                "Ecdh.newKeyPair" -> ecNewKeyPair(call, result)
                "Ecdh.sharedSecretKey" -> ecdsaSign(call, result)
                "Ecdsa.newKeyPair" -> ecNewKeyPair(call, result)
                "Ecdsa.sign" -> ecdsaSign(call, result)
                "Ecdsa.verify" -> ecdsaVerify(call, result)
                "Ed25519.newKeyPair" -> ed25519NewKeyPair(call, result)
                "Ed25519.sign" -> ed25519Sign(call, result)
                "Ed25519.verify" -> ed25519Verify(call, result)
                "X25519.newKeyPair" -> x25519NewKeyPair(call, result)
                "X25519.sign" -> x25519SharedSecretKey(call, result)
                else -> {
                    result.notImplemented()
                }
            }
        } catch (e: Throwable) {
            result.error("CAUGHT_ERROR", "Unexpected error ${e}: ${e.message}\nCause: ${e.cause}", null)
        }
    }

    private fun androidCipherAlgo(dartAlgo: String?): String? {
        return when (dartAlgo) {
            "AES_GCM" -> "AES/GCM/NoPadding"
            "CHACHA20_POLY1305_AEAD" -> "ChaCha20/Poly1305/NoPadding"
            else -> null
        }
    }

    private fun cipherMacLength(dartMacAlgo: String?): Int? {
        return when (dartMacAlgo) {
            "AES_GCM" -> 16
            "CHACHA20_POLY1305_AEAD" -> 16
            else -> null
        }
    }

    private fun decrypt(call: MethodCall, result: Result) {
        val dartAlgo = call.argument<String>("algo")
        val androidAlgo = androidCipherAlgo(dartAlgo)
        val macLength = cipherMacLength(dartAlgo)
        if (androidAlgo == null || macLength == null) {
            result.error(
                    "UNSUPPORTED_ALGORITHM",
                    "cryptography_flutter does not support algorithm ${dartAlgo} in Android.",
                    null)
            return
        }
        var cipher: Cipher;
        try {
            cipher = Cipher.getInstance(androidAlgo)
        } catch (error: NoSuchAlgorithmException) {
            result.error(
                    "UNSUPPORTED_ALGORITHM",
                    "Your version of Android does not support ${androidAlgo}.",
                    null)
            return
        }

        val cipherText = call.argument<ByteArray>("data")!!
        val secretKey = call.argument<ByteArray>("key")!!
        val nonce = call.argument<ByteArray>("nonce")!!
        val aad = call.argument<ByteArray>("aad")
        var mac = call.argument<ByteArray>("mac")
        val params = if (dartAlgo == "AES_GCM") {
            GCMParameterSpec(16 * 8, nonce)
        } else {
            IvParameterSpec(nonce)
        }
        cipher.init(
                Cipher.DECRYPT_MODE,
                SecretKeySpec(secretKey, androidAlgo),
                params,
        )

        // AAD
        if (aad!=null) {
            cipher.updateAAD(aad)
        }

        cipher.update(cipherText)
        try {
            val clearText = cipher.doFinal(mac)
            result.success(hashMapOf(
                    "clearText" to clearText,
            ))
        } catch (e: AEADBadTagException) {
            result.error("INCORRECT_MAC", "Caught error when decrypting ${androidAlgo}: ${e.message}", null)
        } catch (e: BadPaddingException) {
            result.error("INCORRECT_PADDING", "Caught error when decrypting ${androidAlgo}: ${e.message}", null)
        } catch (e: Throwable) {
            result.error("CAUGHT_ERROR", "Caught error when decrypting ${androidAlgo}: ${e.message}", null)
        }
    }

    private fun encrypt(call: MethodCall, result: Result) {
        val dartAlgo = call.argument<String>("algo")
        val androidAlgo = androidCipherAlgo(dartAlgo)
        val macLength = cipherMacLength(dartAlgo)
        if (androidAlgo == null || macLength == null) {
            result.error(
                    "UNSUPPORTED_ALGORITHM",
                    "cryptography_flutter does not support algorithm ${dartAlgo} in Android.",
                    null)
            return
        }
        var cipher: Cipher;
        try {
            cipher = Cipher.getInstance(androidAlgo)
        } catch (error: NoSuchAlgorithmException) {
            result.error(
                    "UNSUPPORTED_ALGORITHM",
                    "Your version of Android does not support ${androidAlgo}.",
                    null)
            return
        }

        val clearText = call.argument<ByteArray>("data")!!
        val secretKey = call.argument<ByteArray>("key")
        val nonce = call.argument<ByteArray>("nonce")
        val aad = call.argument<ByteArray>("aad")
        val dartMacAlgo = call.argument<String>("macAlgo")

        val params = if (dartAlgo == "AES_GCM") {
            GCMParameterSpec(macLength * 8, nonce)
        } else {
            IvParameterSpec(nonce)
        }
        cipher.init(
                Cipher.ENCRYPT_MODE,
                SecretKeySpec(secretKey, androidAlgo),
                params,
        )

        // AAD
        if (aad!=null) {
            cipher.updateAAD(aad)
        }
        val cipherTextAndMac = cipher.doFinal(clearText)
        val cipherTextEnd = cipherTextAndMac.size - macLength
        val cipherText = cipherTextAndMac.copyOfRange(0, cipherTextEnd)
        val mac = cipherTextAndMac.copyOfRange(cipherTextEnd, cipherTextAndMac.size)
        result.success(hashMapOf(
                "cipherText" to cipherText,
                "mac" to mac,
        ))
    }

    private fun ecNewKeyPair(call: MethodCall, result: Result) {
//        val dartAlgo = call.argument<String>("algo")!!
//        val curve = when (dartAlgo) {
//            "Ecdsa.p256" -> "P-256"
//            "Ecdsa.p384" -> "P-384"
//            "Ecdsa.p521" -> "P-521"
//            else -> null
//        }
//        if (curve == null) {
//            result.error("UNSUPPORTED_ALGORITHM", null, null)
//            return
//        }
        result.error("UNSUPPORTED_ALGORITHM", null, null)
    }

    private fun ecdhSharedSecretKey(call: MethodCall, result: Result) {
        result.error("UNSUPPORTED_ALGORITHM", null, null)
    }

    private fun ecdsaSign(call: MethodCall, result: Result) {
//        val dartAlgo = call.argument<String>("algo")!!
//        val curve = when (dartAlgo) {
//            "Ecdsa.p256" -> "P-256"
//            "Ecdsa.p384" -> "P-384"
//            "Ecdsa.p521" -> "P-521"
//            else -> null
//        }
//        if (curve == null) {
//            result.error("UNSUPPORTED_ALGORITHM", null, null)
//            return
//        }
//        val dartHash = call.argument<String>("hash")!!
//        val hash = when (dartHash) {
//            "Sha512" -> "SHA512"
//            "Sha384" -> "SHA384"
//            "Sha256" -> "SHA256"
//            "Sha1" -> "SHA1"
//            else -> null
//        }
//        if (hash == null) {
//            result.error("UNSUPPORTED_ALGORITHM", null, null)
//            return
//        }
//        val message = call.argument<ByteArray>("data")!!
//        val privateKey = call.argument<ByteArray>("privateKey")!!
//
//        // Handle the request
//        val parameters = AlgorithmParameters.getInstance("EC")
//        parameters.init(ECGenParameterSpec("secp256r1"))
//        val ecParameters = parameters.getParameterSpec(ECParameterSpec::class.java)
//        val privateSpec = ECPrivateKeySpec(BigInteger(privateKey), ecParameters)
//        val kf = KeyFactory.getInstance("EC")
//        val key = kf.generatePrivate(privateSpec) as ECPrivateKey
//        val dsa = Signature.getInstance(hash + "withECDSA")
//        dsa.initSign(key);
//        dsa.update(message)
//        val signature = dsa.sign()
//
//        // Set result
//        result.success(hashMapOf(
//                "signature" to signature,
//        ))
        result.error("UNSUPPORTED_ALGORITHM", null, null)
    }

    private fun ecdsaVerify(call: MethodCall, result: Result) {
//        val dartAlgo = call.argument<String>("algo")!!
//        val curve = when (dartAlgo) {
//            "Ecdsa.p256" -> "P-256"
//            "Ecdsa.p384" -> "P-384"
//            "Ecdsa.p521" -> "P-521"
//            else -> null
//        }
//        if (curve == null) {
//            result.error("UNSUPPORTED_ALGORITHM", null, null)
//            return
//        }
//        val dartHash = call.argument<String>("hash")!!
//        val hash = when (call.argument<String>("hash")!!) {
//            "Sha512" -> "SHA512"
//            "Sha384" -> "SHA384"
//            "Sha256" -> "SHA256"
//            "Sha1" -> "SHA1"
//            else -> null
//        }
//        val message = call.argument<ByteArray>("data")!!
//        val x = BigInteger(call.argument<String>("x")!!)
//        val y = BigInteger(call.argument<String>("y")!!)
//        val signature = call.argument<ByteArray>("signature")!!
//
//        // Handle the request
//        val publicPoint = ECPoint(x, y)
//        val parameters = AlgorithmParameters.getInstance("EC")
//        parameters.init(ECGenParameterSpec(curve))
//        val ecParameters = parameters.getParameterSpec(ECParameterSpec::class.java)
//        val publicSpec = ECPublicKeySpec(publicPoint, ecParameters)
//        val kf = KeyFactory.getInstance("EC")
//        val key = kf.generatePublic(publicSpec) as ECPublicKey
//        val dsa = Signature.getInstance(hash + "withECDSA")
//        dsa.initVerify(key)
//        dsa.update(message)
//        val ok = dsa.verify(signature)
//
//        // Set result
//        result.success(hashMapOf(
//                "ok" to ok,
//        ))
        result.error("UNSUPPORTED_ALGORITHM", null, null)
    }

    private fun ed25519NewKeyPair(call: MethodCall, result: Result) {
        result.error("UNSUPPORTED_ALGORITHM", null, null)
    }

    private fun ed25519Sign(call: MethodCall, result: Result) {
        result.error("UNSUPPORTED_ALGORITHM", null, null)
    }

    private fun ed25519Verify(call: MethodCall, result: Result) {
        result.error("UNSUPPORTED_ALGORITHM", null, null)
    }

    private fun x25519NewKeyPair(call: MethodCall, result: Result) {
        result.error("UNSUPPORTED_ALGORITHM", null, null)
    }

    private fun x25519SharedSecretKey(call: MethodCall, result: Result) {
        result.error("UNSUPPORTED_ALGORITHM", null, null)
    }
}
