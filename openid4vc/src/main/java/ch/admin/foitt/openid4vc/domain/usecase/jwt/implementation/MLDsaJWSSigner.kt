package ch.admin.foitt.openid4vc.domain.usecase.jwt.implementation

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.crypto.impl.BaseJWSProvider
import com.nimbusds.jose.jca.JCAContext
import com.nimbusds.jose.util.Base64URL
import java.security.PrivateKey
import java.security.Signature

/**
 * A [JWSSigner] implementation for the ML-DSA-44 signature algorithm.
 */
class MLDsaJWSSigner(private val privateKey: PrivateKey) : JWSSigner {

    private val jcaContext = JCAContext()

    override fun supportedJWSAlgorithms(): Set<JWSAlgorithm> = SUPPORTED_ALGORITHMS
    override fun getJCAContext(): JCAContext = jcaContext

    override fun sign(header: JWSHeader, signingInput: ByteArray): Base64URL {
        if (header.algorithm !in SUPPORTED_ALGORITHMS) {
            throw JOSEException("Unsupported JWS algorithm: ${header.algorithm}")
        }
        val signature = (jcaContext.provider?.let { Signature.getInstance(JCA_ALGORITHM, it) }
            ?: Signature.getInstance(JCA_ALGORITHM)).apply {
            initSign(privateKey)
            update(signingInput)
        }
        return Base64URL.encode(signature.sign())
    }

    companion object {
        private const val JCA_ALGORITHM = "ML-DSA-44"
        val SUPPORTED_ALGORITHMS: Set<JWSAlgorithm> = setOf(JWSAlgorithm(JCA_ALGORITHM))
    }
}
