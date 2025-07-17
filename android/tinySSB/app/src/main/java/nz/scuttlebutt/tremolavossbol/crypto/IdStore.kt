package nz.scuttlebutt.tremolavossbol.crypto

import android.content.Context
import android.util.Base64
import android.util.Log
import com.goterl.lazysodium.LazySodiumAndroid
import com.goterl.lazysodium.SodiumAndroid
import com.goterl.lazysodium.interfaces.Sign
import com.yubico.yubikit.core.keys.PrivateKeyValues.fromPrivateKey
import com.yubico.yubikit.piv.PinPolicy
import com.yubico.yubikit.piv.PivSession
import com.yubico.yubikit.piv.Slot
import com.yubico.yubikit.piv.TouchPolicy
import nz.scuttlebutt.tremolavossbol.MainActivity
import nz.scuttlebutt.tremolavossbol.utils.Constants
import org.json.JSONObject
import java.io.FileOutputStream

import nz.scuttlebutt.tremolavossbol.utils.HelperFunctions.Companion.toBase64
import nz.scuttlebutt.tremolavossbol.utils.HelperFunctions.Companion.toHex
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory
import java.io.File
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.spec.PKCS8EncodedKeySpec

class IdStore(val context: MainActivity) {

    var identity : SSBid

    init {
        val id = readFromFile()
        if (id == null) {
            // Log.d("IdStore init", "no secret found")
            val keypair = SodiumAPI.lazySodiumInst.cryptoSignKeypair()
            identity = SSBid(
                SodiumPrivateKeyOps(keypair.secretKey.asBytes),
                keypair.publicKey.asBytes
            )
            writeToFile(identity)
        } else
            identity = id
        // for tinyssb:
        val fdir = File(context.getDir(Constants.TINYSSB_DIR, Context.MODE_PRIVATE), context.tinyRepo.FEED_DIR)
        if (!File(fdir, "${identity.verifyKey.toHex()}").exists()) {
            Log.d("idstore","create new feed repo")
            context.tinyRepo.add_replica(identity.verifyKey)
        } else
            Log.d("idstore","no need to create new feed repo")
    }

    private fun writeToFile(newId: SSBid): Boolean {
        val private = (newId.privateKeyOps as? YubiPrivateKeyOps)?.let { "YUBIKEY" }
            ?: newId.privateKeyOps?.getSigningKey()?.toBase64() // Placeholder for yubikey
        val jsonSecret: String = "# this is your SECRET name.\n" +
                "# this name gives you magical powers.\n" +
                "# with it you can mark your messages so that your friends can verify\n" +
                "# that they really did come from you.\n" +
                "#\n" +
                "# if any one learns this name, they can use it to destroy your identity\n" +
                "# NEVER show this to anyone!!!\n" +
                "\n" +
                "{\n" +
                "  \"curve\": \"ed25519\",\n" +
                "  \"public\": \"${newId.verifyKey.toBase64()}\",\n" +
                "  \"private\": \"$private\",\n" +
                "  \"id\": \"${newId.toRef()}\"\n" +
                "}\n" +
                "\n" +
                "# WARNING! It's vital that you DO NOT edit OR share your secret name\n" +
                "# instead, share your public name\n" +
                "# your public name: ${newId.toRef()}\n"
        val fileOutputStream: FileOutputStream
        try {
            try { context.deleteFile("secret") } catch (e: java.lang.Exception) {
                // Log.d("IdStore write", "no delete?")
            }
            fileOutputStream = context.openFileOutput("secret", Context.MODE_PRIVATE)
            fileOutputStream.write(jsonSecret.encodeToByteArray())
            fileOutputStream.close()
            // Log.d("IdStore write", "done")
            return true
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return false
    }

    private fun storeOnYubiKey(piv: PivSession, seed: ByteArray): Boolean {
        try {
            // Generate the Ed25519 key
            val edPrivateKeyParams = Ed25519PrivateKeyParameters(seed)
            val edKeyFactory = KeyFactory.getInstance("Ed25519", "BC")
            val edPrivateKey: PrivateKey = edKeyFactory.generatePrivate(
                PKCS8EncodedKeySpec(PrivateKeyInfoFactory.createPrivateKeyInfo(edPrivateKeyParams).encoded)
            )

            // To derive the correct X25519 key, we need to hash the seed first
            val sodiumInstance = LazySodiumAndroid(SodiumAndroid(), StandardCharsets.UTF_8)
            val seedHash = ByteArray(64)
            sodiumInstance.cryptoHashSha512(seedHash, seed, seed.size.toLong())

            // Generate the X25519 key from (first 32 bytes of) the hashed seed
            val xPrivateKeyParams = X25519PrivateKeyParameters(seedHash.take(32).toByteArray(), 0)
            val xKeyFactory = KeyFactory.getInstance("X25519", "BC")
            val xPrivateKey: PrivateKey = xKeyFactory.generatePrivate(
                PKCS8EncodedKeySpec(PrivateKeyInfoFactory.createPrivateKeyInfo(xPrivateKeyParams).encoded)
            )

            // Write the keys to the YubiKey
            piv.putKey(
                Slot.AUTHENTICATION,
                fromPrivateKey(edPrivateKey),
                PinPolicy.ONCE,
                TouchPolicy.NEVER
            )
            piv.putKey(
                Slot.KEY_MANAGEMENT,
                fromPrivateKey(xPrivateKey),
                PinPolicy.ONCE,
                TouchPolicy.NEVER
            )
            return true
        } catch (e: Exception) {
            Log.e("IdStore", "Error writing to YubiKey: ${e.message}")
        }
        return false
    }

    private fun readFromFile(): SSBid? {
        try {
            val inputStream = context.openFileInput("secret")
            val buffer = ByteArray(inputStream.available())
            inputStream.read(buffer)
            inputStream.close()
            val jsonObject = JSONObject(buffer.decodeToString())
            if (jsonObject.getString("curve") == "ed25519") {
                val private = Base64.decode(jsonObject.getString("private"), Base64.NO_WRAP)
                val public = Base64.decode(jsonObject.getString("public"), Base64.NO_WRAP)
                val privateKeyOps =
                    if (private.contentEquals(Base64.decode("YUBIKEY", Base64.NO_WRAP))) {
                        YubiPrivateKeyOps()
                    } else {
                        SodiumPrivateKeyOps(private)
                    }
                return SSBid(privateKeyOps, public)
            }
        } catch (e: java.lang.Exception) {
            // e.message?.let { Log.d("IdStore", it) }
        }
        return null
    }

    fun setNewIdentity(newSecret: ByteArray?, piv: PivSession?): Boolean {
        // TODO: Check if newSecret is a valid Ed25519 key
        val secretKey = newSecret ?: SodiumAPI.lazySodiumInst.cryptoSignKeypair().secretKey.asBytes
        val publicKey = ByteArray(Sign.ED25519_PUBLICKEYBYTES)
        SodiumAPI.lazySodiumInst.cryptoSignEd25519SkToPk(publicKey, secretKey)

        val newId = if (piv != null) {
            if (storeOnYubiKey(piv, secretKey)) {
                SSBid(YubiPrivateKeyOps(), publicKey)
            } else {
                Log.d("IdStore", "Failed to store keys on YubiKey")
                return false
            }
        } else {
            SSBid(SodiumPrivateKeyOps(secretKey), publicKey)
        }

        val oldId = identity
        if (writeToFile(newId)) {
            val id = readFromFile()
            if (id != null) {
                identity = id
                return true
            }
        }
        identity = oldId
        return false
    }
}
