package ch.admin.foitt.wallet.platform.appAttestation.domain.model

import ch.admin.foitt.openid4vc.domain.model.SignatureAlgorithm
import ch.admin.foitt.openid4vc.domain.model.jwt.Jwt

enum class AttestationAlgorithm(val value: String) {
    ML_DSA_65("ML-DSA-65"),
    ;

    companion object {
        fun fromJwt(jwt: Jwt): AttestationAlgorithm? = when (SignatureAlgorithm.fromStdName(jwt.algorithm)) {
            SignatureAlgorithm.ML_DSA_65 -> ML_DSA_65
            else -> null
        }
    }
}
