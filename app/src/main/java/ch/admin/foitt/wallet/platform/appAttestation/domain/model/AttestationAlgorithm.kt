package ch.admin.foitt.wallet.platform.appAttestation.domain.model

import ch.admin.foitt.openid4vc.domain.model.SignatureAlgorithm
import ch.admin.foitt.openid4vc.domain.model.jwt.Jwt

enum class AttestationAlgorithm(val value: String) {
    ES256("ES256"),
    EdDSA("EdDSA"),
    ML_DSA_44("ML-DSA-44"),
    ;

    companion object {
        fun fromJwt(jwt: Jwt): AttestationAlgorithm? = when (SignatureAlgorithm.fromStdName(jwt.algorithm)) {
            SignatureAlgorithm.ES256 -> ES256
            SignatureAlgorithm.EdDSA -> EdDSA
            SignatureAlgorithm.ML_DSA_44 -> ML_DSA_44
            SignatureAlgorithm.ES512, null -> null
        }
    }
}
