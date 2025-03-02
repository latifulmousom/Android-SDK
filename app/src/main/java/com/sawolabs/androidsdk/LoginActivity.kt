package com.sawolabs.androidsdk

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.view.View
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.ProgressBar
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricPrompt
import androidx.lifecycle.lifecycleScope
import com.onesignal.OSSubscriptionObserver
import com.onesignal.OSSubscriptionStateChanges
import com.onesignal.OneSignal
import io.sentry.Breadcrumb
import io.sentry.Sentry
import io.sentry.SentryLevel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import okhttp3.OkHttpClient
import org.json.JSONObject
import retrofit2.Call
import retrofit2.Callback
import retrofit2.Response
import java.util.concurrent.TimeUnit


private const val TAG = "LoginActivity"

class LoginActivity : AppCompatActivity(), OSSubscriptionObserver {
    private lateinit var biometricPrompt: BiometricPrompt
    private lateinit var promptInfo: BiometricPrompt.PromptInfo
    private lateinit var cryptographyManager: CryptographyManager
    private lateinit var mWebView: WebView
    private lateinit var dataToEncrypt: String
    private lateinit var callBackClassName: String
    private lateinit var sawoWebSDKURL: String
    private lateinit var mProgressBar: ProgressBar
    private val encryptedData
        get() = cryptographyManager.getEncryptedDataFromSharedPrefs(
            applicationContext,
            SHARED_PREF_FILENAME,
            Context.MODE_APPEND,
            SHARED_PREF_ENC_PAIR_KEY
        )
    private var readyToEncrypt: Boolean = false
    private val secretKeyName = "SAWO_BIOMETRIC_ENCRYPTION_KEY"
    private var keyExistInStorage: Boolean = false
    private var canStoreKeyInStorage: Boolean = false


    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_login)

        OneSignal.addSubscriptionObserver(this)
        registerDevice()
        sawoWebSDKURL = intent.getStringExtra(SAWO_WEBSDK_URL).toString()
        callBackClassName = intent.getStringExtra(CALLBACK_CLASS).toString()
        cryptographyManager = CryptographyManager()
        biometricPrompt = BiometricPromptUtils.createBiometricPrompt(
            this, ::processCancel, ::processData
        )
        promptInfo = BiometricPromptUtils.createPromptInfo(this)
        mWebView = findViewById(R.id.webview)
        mProgressBar = findViewById(R.id.progressBar)
        keyExistInStorage = cryptographyManager.isDataExistInSharedPrefs(
            this, SHARED_PREF_FILENAME, Context.MODE_APPEND, SHARED_PREF_ENC_PAIR_KEY
        )
        canStoreKeyInStorage =
            BiometricManager.from(applicationContext)
                .canAuthenticate(BIOMETRIC_STRONG) == BiometricManager
                .BIOMETRIC_SUCCESS

        if (!isOnline(this)) {
            Toast.makeText(this, "Internet connection unavailable", Toast.LENGTH_LONG).show()
            mWebView.destroy()
        }
        sawoWebSDKURL += "&keysExistInStorage=${keyExistInStorage}&canStoreKeyInStorage=${canStoreKeyInStorage}"
        mWebView.apply {
            this.settings.javaScriptEnabled = true
            this.settings.domStorageEnabled = true
            this.settings.databaseEnabled = true
            this.webViewClient = object : WebViewClient() {
                override fun shouldOverrideUrlLoading(
                    view: WebView?,
                    request: WebResourceRequest?
                ): Boolean {
                    view?.loadUrl(request?.url.toString())
                    return super.shouldOverrideUrlLoading(view, request)
                }

                override fun onPageFinished(view: WebView?, url: String?) {
                    super.onPageFinished(view, url)
                    mProgressBar.visibility = View.GONE
                    mWebView.visibility = View.VISIBLE
                }
            }
        }

        lifecycleScope.launch {

            val sharedPref = getSharedPreferences(SHARED_PREF_FILENAME, Context.MODE_APPEND)
            mWebView.addJavascriptInterface(
                SawoWebSDKInterface(
                    ::passPayloadToCallbackActivity,
                    ::authenticateToEncrypt,
                    ::authenticateToDecrypt,
                    sharedPref.getString(SHARED_PREF_DEVICE_ID_KEY, null).toString()
                ),
                "webSDKInterface"
            )

            delay(2000L)
            mWebView.loadUrl(sawoWebSDKURL)
        }

    }

    private fun isOnline(context: Context): Boolean {
        val connectivityManager =
            context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val capabilities =
            connectivityManager.getNetworkCapabilities(connectivityManager.activeNetwork)
        if (capabilities != null) {
            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
                Log.i("Internet", "NetworkCapabilities.TRANSPORT_CELLULAR")
                return true
            } else if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
                Log.i("Internet", "NetworkCapabilities.TRANSPORT_WIFI")
                return true
            } else if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) {
                Log.i("Internet", "NetworkCapabilities.TRANSPORT_ETHERNET")
                return true
            }
        }
        return false
    }

    override fun onDestroy() {
        super.onDestroy()
        mWebView.destroy()
    }


    private fun processCancel() {
        Toast.makeText(
            this, R.string.prompt_cancel_toast, Toast.LENGTH_LONG
        ).show()
        finish()
    }

    private fun passPayloadToCallbackActivity(message: String) {
        val intent = Intent(this, Class.forName(callBackClassName)).apply {
            flags = Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra(LOGIN_SUCCESS_MESSAGE, message)
        }
        startActivity(intent)
        finish()
    }

    private fun authenticateToEncrypt(message: String) {
        readyToEncrypt = true
        dataToEncrypt = message
        if (canStoreKeyInStorage) {
            runOnUiThread(Runnable {
                val cipher = cryptographyManager.getInitializedCipherForEncryption(secretKeyName)
                biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
            })
        }
    }

    private fun authenticateToDecrypt() {
        readyToEncrypt = false
        if (canStoreKeyInStorage && encryptedData != null) {
            runOnUiThread(Runnable {
                encryptedData?.let { encryptedData ->
                    val cipher = cryptographyManager.getInitializedCipherForDecryption(
                        secretKeyName,
                        encryptedData.initializationVector
                    )
                    biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
                }
            })
        }
    }

    private fun processData(cryptoObject: BiometricPrompt.CryptoObject?) {
        if (readyToEncrypt) {
            runOnUiThread(Runnable {
                mWebView.evaluateJavascript(
                    "(function() { window.dispatchEvent(new CustomEvent('keysFromAndroid', {'detail': \'${dataToEncrypt}\'})); })();",
                    null
                )
            })
            val encryptedData =
                cryptographyManager.encryptData(dataToEncrypt, cryptoObject?.cipher!!)
            cryptographyManager.saveEncryptedDataToSharedPrefs(
                encryptedData,
                applicationContext,
                SHARED_PREF_FILENAME,
                Context.MODE_APPEND,
                SHARED_PREF_ENC_PAIR_KEY
            )
        } else {
            if (encryptedData != null) {
                encryptedData?.let { encryptedData ->
                    val data = cryptographyManager.decryptData(
                        encryptedData.ciphertext,
                        cryptoObject?.cipher!!
                    )
                    runOnUiThread(Runnable {
                        mWebView.evaluateJavascript(
                            "(function() { window.dispatchEvent(new CustomEvent('keysFromAndroid', {'detail': \'${data}\'})); })();",
                            null
                        )
                    })
                }
            }
        }
    }

    private fun getDeviceName(): String? {
        return "${capitalize(Build.MANUFACTURER)} ${capitalize(Build.MODEL)}"
    }

    private fun capitalize(s: String?): String {
        if (s == null || s.isEmpty()) {
            return ""
        }
        return if (Character.isUpperCase(s[0])) {
            s
        } else {
            Character.toUpperCase(s[0]).toString() + s.substring(1)
        }
    }

    private fun registerDevice() {
        val device = OneSignal.getDeviceState()

        val deviceID = device?.userId
        val deviceToken = device?.pushToken

        if ((deviceID != null) and (deviceToken != null)) {
            if (deviceID != null) {
                getSharedPreferences(SHARED_PREF_FILENAME, Context.MODE_APPEND).edit().putString(
                    SHARED_PREF_DEVICE_ID_KEY, deviceID
                ).apply()
            }

            val httpClient = OkHttpClient.Builder()
                .callTimeout(2, TimeUnit.MINUTES)
                .connectTimeout(30, TimeUnit.SECONDS)

            val builder = HttpApiUtils.getRetrofitBuilder()

            builder.client(httpClient.build())
            val retrofit = builder.build()

            val registerDeviceApi = retrofit.create(RegisterDeviceApi::class.java)
            val deviceData = Device(
                deviceToken.toString(),
                deviceID.toString(),
                Build.MANUFACTURER.toString(),
                Build.MODEL.toString(),
                getDeviceName().toString(),
                "android"
            )
            val call = registerDeviceApi.sendDeviceData(deviceData)

            // SENTRY Tag and Breadcrumb
            val activity = this.javaClass.simpleName
            Sentry.setTag("activity", activity)


            val breadcrumb = Breadcrumb()
            breadcrumb.message = "Retrofit call to register device information"
            breadcrumb.level = SentryLevel.INFO
            breadcrumb.setData("Activity Name", activity)
            Sentry.addBreadcrumb(breadcrumb)



            call.enqueue(object : Callback<Void> {
                override fun onResponse(call: Call<Void>, response: Response<Void>) {
                    if (response.isSuccessful) {
                        Log.d(
                            TAG,
                            "RegisterDeviceApi: Successful"
                        )
                    } else {
                        try {
                            Log.d(
                                TAG,
                                "RegisterDeviceApi: ${JSONObject(response.errorBody()!!.string())}"
                            )
                        } catch (e: Exception) {
                            Sentry.captureException(e)
                            Log.d(
                                TAG,
                                "RegisterDeviceApi: Error in parsing server error response ${e.message}"
                            )
                        }
                    }
                }

                override fun onFailure(call: Call<Void>, t: Throwable) {
                    Log.d(TAG, "RegisterDeviceApi: Error in requesting API ${t.message}")
                }
            })
        }
    }

    override fun onOSSubscriptionChanged(stateChanges: OSSubscriptionStateChanges) {
        Log.d(TAG, "OSSubscriptionStateChanged, calling registerDevice")
        registerDevice()
    }

}
