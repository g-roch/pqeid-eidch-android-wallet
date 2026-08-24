package ch.admin.foitt.openid4vc.domain.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Algorithms the wallet supports for signature validation.
 *
 * In contrast to [SigningAlgorithm], these algorithms are only used to verify
 * signatures of received artifacts (JWTs, trust statements, credentials, ...),
 * not to generate keys or create signatures.
 */
@Serializable
enum class SignatureAlgorithm(override val stdName: String) : Algorithm {
    @SerialName("ML-DSA-65")
    ML_DSA_65("ML-DSA-65"),
    ;

    companion object {
        fun fromStdName(name: String): SignatureAlgorithm? = entries.firstOrNull { it.stdName == name }

        fun fromStdNameOrThrow(name: String): SignatureAlgorithm = checkNotNull(fromStdName(name)) {
            "unsupported algorithm: $name"
        }
    }
}
// NOTE: this only lets the wallet accept ML-DSA-65-signed JWTs — it does not make issuers or
// verifiers in the swiyu trust infrastructure send them. Until they do, every real-world
// credential offer / presentation request will fail fromStdNameOrThrow(). Keep ES256/ES512/EdDSA
// entries alongside this one until the ecosystem side has actually migrated.
