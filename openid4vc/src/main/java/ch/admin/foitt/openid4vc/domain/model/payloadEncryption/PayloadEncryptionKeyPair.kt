package ch.admin.foitt.openid4vc.domain.model.payloadEncryption

import ch.admin.foitt.openid4vc.domain.model.credentialoffer.JWEKeyPair

data class PayloadEncryptionKeyPair(
    val keyPair: JWEKeyPair,
    val alg: String,
    val enc: String,
    val zip: String?,
)
