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
 * Nimbus [JWSSigner] for ML-DSA-65, backed by a [PrivateKey] obtained from `AndroidKeyStore`
 * (or, in principle, any JCA provider that registers a "ML-DSA-65" [Signature] algorithm).
 *
 * Nimbus JOSE+JWT 10.9.1 has no built-in ML-DSA support — draft-ietf-cose-dilithium is still on
 * its roadmap as of Aug 2026 — so this bridges Nimbus's pluggable signer interface to the
 * platform `java.security.Signature` API added by Android 17's AndroidKeyStore.
 *
 * When [privateKey] is an AndroidKeyStore key, the private key material never leaves secure
 * hardware: `Signature.sign()` on a Keystore-backed key delegates to the TEE/StrongBox, exactly
 * like the existing SHA256withECDSA usage elsewhere in this codebase.
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
        private const val JCA_ALGORITHM = "ML-DSA-65"
        val SUPPORTED_ALGORITHMS: Set<JWSAlgorithm> = setOf(JWSAlgorithm(JCA_ALGORITHM))
    }
}
