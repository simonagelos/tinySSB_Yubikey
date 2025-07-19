package nz.scuttlebutt.tremolavossbol.crypto

import android.util.Log
import com.yubico.yubikit.piv.Slot
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory
import java.security.KeyFactory
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import javax.crypto.KeyAgreement

class YubiPrivateKeyOps : PrivateKeyOps {

    companion object {
        val DEFAULT_PIN: CharArray = "123456".toCharArray()
        val DEFAULT_MGMT = byteArrayOf(
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
        )
    }

    /**
     * Signs the given data using an Ed25519 private key stored on the YubiKey.
     * The private key should be stored in [Slot.AUTHENTICATION].
     * It is assumed that a PIV session has already been established and verified with
     * [com.yubico.yubikit.piv.PivSession.verifyPin].
     */
    override fun sign(data: ByteArray): ByteArray? {
        Log.d("YubiKey", "Signing")

        val privateKey = loadPrivateKey(Slot.AUTHENTICATION) // Ed25519 key

        try { // Sign the data using the private key
            val signature = Signature.getInstance("Ed25519")
            signature.initSign(privateKey)
            signature.update(data)
            return signature.sign()
        } catch (e: Exception) {
            Log.e("YubiKey", "Error signing data: ${e.message}")
            return null
        }
    }

    /**
     * Derives a shared secret using an X25519 private key stored on the YubiKey.
     * The private key should be stored in [Slot.KEY_MANAGEMENT].
     * It is assumed that a PIV session has already been established and verified with
     * [com.yubico.yubikit.piv.PivSession.verifyPin].
     */
    override fun cryptoScalarMult(publicKey: ByteArray): ByteArray? {
        Log.d("YubiKey", "Deriving shared secret")

        val privateKey = loadPrivateKey(Slot.KEY_MANAGEMENT) // X25519 key

        try {
            // Convert the public key to a JCA format suitable for KeyAgreement
            val pubParams = X25519PublicKeyParameters(publicKey, 0);
            val spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(pubParams);
            val x509PubBytes = spki.getEncoded();
            val pubSpec = X509EncodedKeySpec(x509PubBytes);
            val kf = KeyFactory.getInstance("X25519", "BC");
            val publicKeyJCA = kf.generatePublic(pubSpec);

            // Perform the key agreement
            val keyAgreement = KeyAgreement.getInstance("X25519")
            keyAgreement.init(privateKey)
            keyAgreement.doPhase(publicKeyJCA, true)
            return keyAgreement.generateSecret()
        } catch (e: Exception) {
            Log.e("YubiKey", "Error deriving shared secret: ${e.message}")
            return null
        }
    }


    /**
     * Fetches the reference to the respective private key from the YubiKey.
     * This method assumes that a PIV session has already been established and verified with
     * [com.yubico.yubikit.piv.PivSession.verifyPin].
     *
     * @param slot Use [Slot.AUTHENTICATION] for Ed25519 and [Slot.KEY_MANAGEMENT] for X25519.
     */
    private fun loadPrivateKey(slot: Slot): PrivateKey? {
        try {
            val keyStore = KeyStore.getInstance("YKPiv")
            keyStore.load(null)
            val privateKey = keyStore.getKey(slot.stringAlias, DEFAULT_PIN) as PrivateKey
            return privateKey
        } catch (e: Exception) {
            Log.e("YubiKey", "Error loading key: ${e.message}")
            return null
        }
    }

    override fun getSigningKey(): ByteArray? {
        return null // YubiKeys do not expose the private key
    }

}