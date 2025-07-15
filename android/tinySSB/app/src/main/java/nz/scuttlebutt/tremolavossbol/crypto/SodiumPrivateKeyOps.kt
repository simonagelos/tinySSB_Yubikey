package nz.scuttlebutt.tremolavossbol.crypto

import com.goterl.lazysodium.interfaces.Box
import nz.scuttlebutt.tremolavossbol.crypto.SodiumAPI.Companion.signDetached
import nz.scuttlebutt.tremolavossbol.crypto.SodiumAPI.Companion.ed25519SktoCurve


class SodiumPrivateKeyOps : PrivateKeyOps {

    private val signingKey: ByteArray

    constructor(private: ByteArray) {
        signingKey = private
    }

    override fun sign(data: ByteArray): ByteArray? {
        return signDetached(data, signingKey)
    }

    override fun cryptoScalarMult(publicKey: ByteArray): ByteArray? {
        val sodium = SodiumAPI.lazySodiumInst
        val shared = ByteArray(Box.SECRETKEYBYTES)
        if (sodium.cryptoScalarMult(shared, ed25519SktoCurve(signingKey), publicKey)) {
            return shared
        }
        return null
    }

    override fun getSigningKey(): ByteArray? {
        return signingKey
    }

}