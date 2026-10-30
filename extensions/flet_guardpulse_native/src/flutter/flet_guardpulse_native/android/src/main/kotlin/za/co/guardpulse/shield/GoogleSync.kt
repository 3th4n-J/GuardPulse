package za.co.guardpulse.shield

import android.app.Activity
import android.os.CancellationSignal
import android.os.Handler
import android.os.Looper
import androidx.credentials.CredentialManager
import androidx.credentials.CredentialManagerCallback
import androidx.credentials.CustomCredential
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetCredentialResponse
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialException
import com.google.android.libraries.identity.googleid.GetSignInWithGoogleOption
import com.google.android.libraries.identity.googleid.GoogleIdTokenCredential
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.codescanner.GmsBarcodeScannerOptions
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning
import java.util.concurrent.Executor

/**
 * Phase 6 helpers that need Google Play services:
 * - "Sign in with Google" through Android's Credential Manager, returning the
 *   Google ID token that the Python side exchanges for a Firebase session.
 * - Google's built-in QR scanner (no camera permission; Play services shows
 *   its own scanner UI) for the pairing code.
 */
object GoogleSync {
    private val main = Handler(Looper.getMainLooper())
    private val mainExecutor = Executor { main.post(it) }

    /** ``onDone(idToken, error)``; both null means the user cancelled. */
    fun signIn(activity: Activity, webClientId: String, onDone: (String?, String?) -> Unit) {
        val request = GetCredentialRequest.Builder()
            .addCredentialOption(GetSignInWithGoogleOption.Builder(webClientId).build())
            .build()
        CredentialManager.create(activity).getCredentialAsync(
            activity,
            request,
            CancellationSignal(),
            mainExecutor,
            object : CredentialManagerCallback<GetCredentialResponse, GetCredentialException> {
                override fun onResult(result: GetCredentialResponse) {
                    val credential = result.credential
                    if (credential is CustomCredential &&
                        credential.type == GoogleIdTokenCredential.TYPE_GOOGLE_ID_TOKEN_CREDENTIAL
                    ) {
                        onDone(GoogleIdTokenCredential.createFrom(credential.data).idToken, null)
                    } else {
                        onDone(null, "Google returned an unexpected sign-in type.")
                    }
                }

                override fun onError(e: GetCredentialException) {
                    if (e is GetCredentialCancellationException) onDone(null, null)
                    else onDone(null, e.message ?: e.type)
                }
            },
        )
    }

    /** ``onDone(text, error)``; both null means the user closed the scanner. */
    fun scanQr(activity: Activity, onDone: (String?, String?) -> Unit) {
        val options = GmsBarcodeScannerOptions.Builder()
            .setBarcodeFormats(Barcode.FORMAT_QR_CODE)
            .build()
        GmsBarcodeScanning.getClient(activity, options).startScan()
            .addOnSuccessListener { barcode -> onDone(barcode.rawValue, null) }
            .addOnCanceledListener { onDone(null, null) }
            .addOnFailureListener { e -> onDone(null, e.message ?: "The scanner couldn't start.") }
    }
}
