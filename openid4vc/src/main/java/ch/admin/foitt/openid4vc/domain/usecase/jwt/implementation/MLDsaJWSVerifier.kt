package ch.admin.foitt.openid4vc.domain.usecase.jwt.implementation

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.jca.JCAContext
import com.nimbusds.jose.util.Base64URL
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jcajce.spec.MLDSAPublicKeySpec
import java.security.KeyFactory
import java.security.PublicKey
import java.security.Signature

/**
* A [JWSVerifier] implementation for the ML-DSA-44 signature algorithm.
*
* This verifier uses the Bouncy Castle provider to verify signatures generated
* with the ML-DSA-44 algorithm. It supports the corresponding JWS algorithm
* defined in [MLDsaJWSSigner].
*
* @property publicKey The public key used for signature verification.
*/
class MLDsaJWSVerifier(private val publicKey: PublicKey) : JWSVerifier {

    private val jcaContext = JCAContext()

    override fun supportedJWSAlgorithms(): Set<JWSAlgorithm> = MLDsaJWSSigner.SUPPORTED_ALGORITHMS
    override fun getJCAContext(): JCAContext = jcaContext

    override fun verify(header: JWSHeader, signingInput: ByteArray, signature: Base64URL): Boolean {
        if (header.algorithm !in supportedJWSAlgorithms()) return false
        return Signature.getInstance("ML-DSA-44", BouncyCastleProvider.PROVIDER_NAME).apply {
            initVerify(publicKey)
            update(signingInput)
        }.verify(signature.decode())
    }

    companion object {
        /**
         * Converts raw ML-DSA public key bytes to a [PublicKey] instance.
         *
         * @param rawKey The raw public key bytes.
         * @return The corresponding [PublicKey] instance.
         */
        fun publicKeyFromRawBytes(rawKey: ByteArray): PublicKey =
            KeyFactory.getInstance("ML-DSA", BouncyCastleProvider.PROVIDER_NAME)
                .generatePublic(MLDSAPublicKeySpec(MLDSAParameterSpec.ml_dsa_44, rawKey))
    }
}
