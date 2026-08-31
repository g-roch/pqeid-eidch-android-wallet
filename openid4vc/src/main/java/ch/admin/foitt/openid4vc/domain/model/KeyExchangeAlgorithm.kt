package ch.admin.foitt.openid4vc.domain.model

import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.jwk.Curve
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Algorithms the wallet supports for key generation and key exchange during
 * response payload encryption (as opposed to [SigningAlgorithm], which is
 * used for signing/proofs/DPoP/key binding).
 */
@Serializable
enum class KeyExchangeAlgorithm(override val stdName: String) : Algorithm {
    @SerialName("ECDH-ES")
    ECDH_ES("ECDH-ES"),

    @SerialName("XWING")
    X_WING("XWING"),
    ;

    companion object {
        fun fromStdName(name: String): KeyExchangeAlgorithm? = entries.firstOrNull { it.stdName == name }
    }
}

fun KeyExchangeAlgorithm.toJWEAlgorithm(): JWEAlgorithm = when (this) {
    KeyExchangeAlgorithm.ECDH_ES -> JWEAlgorithm.ECDH_ES
    KeyExchangeAlgorithm.X_WING -> JWEAlgorithm("XWING")
}

fun KeyExchangeAlgorithm.toCurve(): Curve = when (this) {
    KeyExchangeAlgorithm.ECDH_ES -> Curve.P_256
    KeyExchangeAlgorithm.X_WING -> error("XWING has no elliptic curve")
}
