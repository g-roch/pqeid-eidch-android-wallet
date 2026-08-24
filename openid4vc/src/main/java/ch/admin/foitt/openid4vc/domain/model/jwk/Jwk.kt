package ch.admin.foitt.openid4vc.domain.model.jwk

import com.github.michaelbull.result.coroutines.runSuspendCatching
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.util.Base64URL
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * https://datatracker.ietf.org/doc/html/rfc7517
 */
@Serializable
data class Jwk(
    @SerialName("x")
    val x: String,
    @SerialName("y")
    val y: String? = null,
    // ML-DSA keys have no elliptic-curve parameter, so crv is EC-only now. Making it nullable
    // rather than removing it keeps this a single Jwk type instead of a sealed hierarchy — a
    // sealed EcJwk/MLDsaJwk split would be cleaner but touches every call site that pattern-
    // matches on Jwk, which is out of scope here.
    @SerialName("crv")
    val crv: String? = null,
    @SerialName("kty")
    val kty: String,
    @SerialName("kid")
    val kid: String? = null,
    @SerialName("x5c")
    val x5c: List<String>? = null,
    @SerialName("use")
    val use: String? = null,
    @SerialName("alg")
    val alg: String? = null,
) {
    companion object {
        fun fromEcKey(
            ecKeyString: String,
            certificateChainBase64: List<String>?,
        ) = runSuspendCatching {
            ECKey.parse(ecKeyString).toEcJwk(certificateChainBase64)
        }
    }
}

fun ECKey.toEcJwk(certificateChainBase64: List<String>?): Jwk = Jwk(
    x = x.toString(),
    y = y.toString(),
    crv = curve.name,
    kid = keyID,
    kty = keyType.value,
    x5c = certificateChainBase64,
)

// "AKP" (Algorithm Key Pair) and a single opaque "x" holding the raw public key encoding is
// this codebase's placeholder for ML-DSA JWKs — draft-ietf-cose-dilithium / the corresponding
// JOSE key-type registration were not finalized as of this codebase's last update. Confirm the
// actual field names/kty value the issuer/verifier side uses before relying on this in
// production; this is the one place that needs to change if they differ.
fun mlDsaPublicKeyToJwk(
    rawPublicKey: ByteArray,
    kid: String?,
    certificateChainBase64: List<String>?,
): Jwk = Jwk(
    x = Base64URL.encode(rawPublicKey).toString(),
    y = null,
    crv = null,
    kty = "AKP",
    kid = kid,
    x5c = certificateChainBase64,
    alg = "ML-DSA-65",
)

fun Jwk.hasSameCurveAs(otherJwk: Jwk): Boolean =
    kty == otherJwk.kty &&
        crv == otherJwk.crv &&
        x == otherJwk.x &&
        y == otherJwk.y
