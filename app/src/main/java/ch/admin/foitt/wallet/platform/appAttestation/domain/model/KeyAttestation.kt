package ch.admin.foitt.wallet.platform.appAttestation.domain.model

import ch.admin.foitt.openid4vc.domain.model.SigningAlgorithm
import ch.admin.foitt.openid4vc.domain.model.credentialoffer.JWSKeyPair
import ch.admin.foitt.openid4vc.domain.model.jwt.Jwt

data class KeyAttestation(
    val keyPair: JWSKeyPair,
    val attestation: Jwt,
) {
    companion object {
        const val KEY_ALIAS = "keyAttestation"

        // See ClientAttestation.SIGNING_ALGORITHM for why this defaults to ES256. Note that
        // GenerateProofKeyPairsImpl.createHardwareKeyPairWithKeyAttestation already overrides
        // this default with the issuer-negotiated algorithm on every real call — this default
        // only applies to callers that don't specify one explicitly.
        val signingAlgorithm = SigningAlgorithm.ES256
    }
}
