package nz.scuttlebutt.tremolavossbol.crypto

import java.security.SecureRandom
import android.util.Base64
import com.goterl.lazysodium.interfaces.Sign
import com.goterl.lazysodium.utils.KeyPair
import nz.scuttlebutt.tremolavossbol.crypto.SodiumAPI.Companion.ed25519PktoCurve
import nz.scuttlebutt.tremolavossbol.crypto.SodiumAPI.Companion.ed25519SktoCurve
import org.json.JSONObject

import nz.scuttlebutt.tremolavossbol.crypto.SodiumAPI.Companion.signDetached
import nz.scuttlebutt.tremolavossbol.utils.HelperFunctions.Companion.toBase64
import nz.scuttlebutt.tremolavossbol.utils.Json_PP

class SSBid { // ed25519

    constructor(secret: ByteArray, public: ByteArray) {
        privateKeyOps = SodiumPrivateKeyOps(secret)
        verifyKey = public
    }

    constructor(key: ByteArray) {
        if (key.size == Sign.ED25519_PUBLICKEYBYTES) {
            privateKeyOps = null
            verifyKey = key
        } else { // secret key
            privateKeyOps = SodiumPrivateKeyOps(key)
            verifyKey = ByteArray(Sign.ED25519_PUBLICKEYBYTES)
            lazySodiumInst.cryptoSignEd25519SkToPk(verifyKey, key)
        }
    }

    constructor(str: String) {
        val s = str.slice(1..str.lastIndex).removeSuffix(".ed25519")
        verifyKey = Base64.decode(s, Base64.NO_WRAP)
    }

    constructor(k: KeyPair) {
        privateKeyOps = SodiumPrivateKeyOps(k.secretKey.asBytes)
        verifyKey = k.publicKey.asBytes
    }

    constructor() { // generate new ID
        val keypair = lazySodiumInst.cryptoSignKeypair()
        privateKeyOps = SodiumPrivateKeyOps(keypair.secretKey.asBytes)
        verifyKey = keypair.publicKey.asBytes
    }

    var privateKeyOps:   PrivateKeyOps? = null
    var verifyKey:    ByteArray         // public i.e., the SSB ID proper
    private val lazySodiumInst = SodiumAPI.lazySodiumInst

    // ------------------------------------------------------------------------

    fun toRef(): String {
        return "@" + verifyKey.toBase64() + ".ed25519"
    }

    fun toExportString(): String? {
        if (privateKeyOps == null) return null
        val privateKey = privateKeyOps!!.getSigningKey()
        if (privateKey == null) return null
        val s = Base64.encode(privateKey, Base64.NO_WRAP).decodeToString()
        return "{\"curve\":\"ed25519\",\"secret\":\"${s}\"}"
    }

    fun sign(data: ByteArray): ByteArray? {
        return privateKeyOps!!.sign(data)
    }

    fun verify(signature: ByteArray, data: ByteArray): Boolean {
        return lazySodiumInst.cryptoSignVerifyDetached(signature, data, data.size, verifyKey)
    }

    fun deriveSharedSecretAb(publicKey: ByteArray): ByteArray {
        return privateKeyOps!!.cryptoScalarMult(publicKey)!!
    }

    fun encryptPrivateMessage(message: ByteArray, recps: List<ByteArray>): ByteArray {
        // val txt = message.encodeToByteArray()
        val nonce = SecureRandom().generateSeed(24)
        val cdek = SecureRandom().generateSeed(33) // count plus data encryption key
        cdek[0] = recps.size.toByte()
        val dek = cdek.sliceArray(1..32)
        val aKeyPair = lazySodiumInst.cryptoSignKeypair()
        val secret = ed25519SktoCurve(aKeyPair.secretKey.asBytes)
        val public = ed25519PktoCurve(aKeyPair.publicKey.asBytes)
        var boxes = ByteArray(0)
        val kek = ByteArray(32)
        for (k in recps) {
            val sbox = ByteArray(cdek.size + 16)
            lazySodiumInst.cryptoScalarMult(kek, secret, ed25519PktoCurve(k))
            lazySodiumInst.cryptoSecretBoxEasy(sbox, cdek, cdek.size.toLong(), nonce, kek)
            boxes += sbox
        }
        val lastbox = ByteArray(message.size + 16)
        lazySodiumInst.cryptoSecretBoxEasy(lastbox, message, message.size.toLong(), nonce, dek)
        val total = nonce + public + boxes + lastbox
        return total // Base64.encodeToString(total, Base64.NO_WRAP) + ".box"
    }

    fun decryptPrivateMessage(raw: ByteArray): ByteArray? {
        // val raw = Base64.decode(message.removeSuffix(".box"), Base64.NO_WRAP)
        val nonce = raw.sliceArray(0..23)
        val pubkey = raw.sliceArray(24..55)
        val kek = privateKeyOps!!.cryptoScalarMult(pubkey)!!
        var recipients = raw.sliceArray(56..raw.lastIndex)

        for (i in 0..6) {
            if (recipients.size < 49) return null
            val cdek = SodiumAPI.secretUnbox(recipients.copyOfRange(0, 49), nonce, kek)
            if (cdek != null) {
                val numberRecipients = cdek[0].toInt()
                val data = raw.sliceArray(56 + numberRecipients * 49..raw.lastIndex)
                return SodiumAPI.secretUnbox(data, nonce, cdek.sliceArray(1..32))
            }
            recipients = raw.sliceArray(56 + (i + 1) * 49..raw.lastIndex)
        }
        return null
    }

     fun formatEvent(prev: String?, seq: Int, auth: String, ts: String,
                            hash: String, cont: Any, sig: ByteArray?): String {
         // returns SSB-compliant JSON string, cont is either JSONObject/dict or a string
         var cstr = if (cont is String) "\"${cont}\"" else ((cont as JSONObject)).toString(2)
         cstr = cstr.replace("\n", "\n  ")
         cstr = cstr.replace("\\/", "/") // argh, silly json.org formatting
         var estr = if (prev == null) "{\n  \"previous\": null," else
                                     "{\n  \"previous\": \"${prev}\","
         estr += """
  "sequence": ${seq},
  "author": "${auth}",
  "timestamp": ${ts},
  "hash": "${hash}",
  "content": ${cstr}"""
        if (sig != null)
            estr += ",\n  \"signature\": \"{sig}\"\n}"
        else
            estr += "\n}"
        return Json_PP().makePretty(estr)
    }

    fun signSSBEvent(prev: String?, seq: Int, content: Any): String {
        val estr = formatEvent(prev, seq, this.toRef(), System.currentTimeMillis().toString(),
                         "sha256", content, null)
        val sig = Base64.encode(privateKeyOps!!.sign(estr.encodeToByteArray())!!, Base64.NO_WRAP)
        return ( estr.slice(0..(estr.lastIndex-2)) +
                             ",\n  \"signature\": \"${sig.decodeToString()}.sig.ed25519\"\n}" )
    }
}
