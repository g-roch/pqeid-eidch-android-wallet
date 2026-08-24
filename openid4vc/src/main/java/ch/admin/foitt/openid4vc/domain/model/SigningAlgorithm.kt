package ch.admin.foitt.openid4vc.domain.model

import com.nimbusds.jose.JWSAlgorithm
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Algorithms the wallet supports for key generation and signing.
 *
 * In contrast to [SignatureAlgorithm], these algorithms are used to generate the
 * wallet's own key pairs and create signatures (proofs, DPoP, key binding, ...).
 */
@Serializable
enum class SigningAlgorithm(override val stdName: String) : Algorithm {
    @SerialName("ML-DSA-65")
    ML_DSA_65("ML-DSA-65"),
    ;

    companion object {
        fun fromStdName(name: String): SigningAlgorithm? = entries.firstOrNull { it.stdName == name }
    }
}

// Nimbus 10.9.1 has no built-in JWSAlgorithm constant for ML-DSA-65 (draft-ietf-cose-dilithium
// is still on its roadmap as of Aug 2026), so this constructs the header value manually and
// relies on a custom JWSSigner/JWSVerifier pair (see MLDsaJWSSigner / MLDsaJWSVerifier) to
// actually sign/verify it.
fun SigningAlgorithm.toJWSAlgorithm(): JWSAlgorithm = when (this) {
    SigningAlgorithm.ML_DSA_65 -> JWSAlgorithm("ML-DSA-65")
}

// ML-DSA has no elliptic-curve parameter, so toCurve() is gone. Any caller that used
// signingAlgorithm.toCurve() (search the old CreateKeyGenSpecImpl) needs to be updated —
// see the AndroidKeyStore diff below.
