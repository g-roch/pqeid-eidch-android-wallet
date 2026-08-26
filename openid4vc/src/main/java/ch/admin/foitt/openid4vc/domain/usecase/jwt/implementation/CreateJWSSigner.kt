package ch.admin.foitt.openid4vc.domain.usecase.jwt.implementation

import ch.admin.foitt.openid4vc.domain.model.SigningAlgorithm
import ch.admin.foitt.openid4vc.domain.model.toCurve
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.crypto.ECDSASigner
import java.security.PrivateKey

fun SigningAlgorithm.toJWSSigner(privateKey: PrivateKey): JWSSigner = when (this) {
    SigningAlgorithm.ML_DSA_44 -> MLDsaJWSSigner(privateKey)
    SigningAlgorithm.ES256 -> ECDSASigner(privateKey, this.toCurve())
}
