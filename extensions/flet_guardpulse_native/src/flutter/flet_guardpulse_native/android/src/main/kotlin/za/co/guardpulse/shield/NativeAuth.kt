package za.co.guardpulse.shield

import java.io.File
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Verifies the partner PIN while the Flet app is closed.
 *
 * Python writes ``pin.verify`` (a PBKDF2-HMAC-SHA256 hash, matching
 * security.pbkdf2_hash) and ``pin.verify.sig`` (HMAC-SHA256 of it under
 * seal.key). We check the signature first, so a hand-edited hash is rejected.
 * No PIN is ever stored in the clear.
 */
object NativeAuth {

    /** Read + signature-check the stored hash. Null if missing or tampered. */
    fun storedHash(folder: File): String? {
        val hashFile = File(folder, "pin.verify")
        val sigFile = File(folder, "pin.verify.sig")
        val keyFile = File(folder, "seal.key")
        if (!hashFile.exists() || !sigFile.exists() || !keyFile.exists()) return null
        val payload = hashFile.readBytes()
        val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(keyFile.readBytes(), "HmacSHA256")) }
        val actual = mac.doFinal(payload).joinToString("") { "%02x".format(it) }
        if (!MessageDigest.isEqual(actual.toByteArray(), sigFile.readText().trim().toByteArray())) return null
        return String(payload, Charsets.UTF_8).trim()
    }

    fun hasPin(folder: File): Boolean = storedHash(folder) != null

    /** Constant-time PBKDF2 check of ``pin`` against "pbkdf2$iters$salt$hash". */
    fun verify(folder: File, pin: String): Boolean {
        val stored = storedHash(folder) ?: return false
        return verifyHash(pin, stored)
    }

    fun verifyHash(pin: String, stored: String): Boolean {
        val parts = stored.split("$")
        if (parts.size != 4 || parts[0] != "pbkdf2") return false
        val iterations = parts[1].toIntOrNull() ?: return false
        val salt = parts[2].hexToBytes() ?: return false
        val expected = parts[3].hexToBytes() ?: return false
        val spec = PBEKeySpec(pin.toCharArray(), salt, iterations, expected.size * 8)
        val actual = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        return MessageDigest.isEqual(actual, expected)
    }

    private fun String.hexToBytes(): ByteArray? {
        if (length % 2 != 0) return null
        return try {
            ByteArray(length / 2) { substring(it * 2, it * 2 + 2).toInt(16).toByte() }
        } catch (e: NumberFormatException) {
            null
        }
    }
}

/**
 * Back-off after wrong PINs at a guarded Settings screen, mirroring
 * security.lockout_seconds (3 free tries, then 30 s doubling to 1 h).
 */
class PinGate(private val clock: () -> Long = System::currentTimeMillis) {
    private var failures = 0
    private var lockedUntil = 0L

    val lockedForMs: Long get() = (lockedUntil - clock()).coerceAtLeast(0)

    /** Returns true on the right PIN; applies back-off on a wrong one. */
    fun attempt(ok: Boolean): Boolean {
        if (clock() < lockedUntil) return false
        if (ok) {
            failures = 0
            lockedUntil = 0
            return true
        }
        failures++
        val wait = lockoutSeconds(failures)
        if (wait > 0) lockedUntil = clock() + wait * 1000L
        return false
    }

    companion object {
        fun lockoutSeconds(failures: Int): Long =
            if (failures < 3) 0 else minOf(30L shl (failures - 3), 3600L)
    }
}
