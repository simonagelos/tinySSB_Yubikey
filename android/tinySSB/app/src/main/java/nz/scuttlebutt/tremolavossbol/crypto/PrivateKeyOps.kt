package nz.scuttlebutt.tremolavossbol.crypto

interface PrivateKeyOps {
    fun sign(data: ByteArray): ByteArray?

    fun cryptoScalarMult(publicKey: ByteArray): ByteArray?

    fun getSigningKey(): ByteArray?
}