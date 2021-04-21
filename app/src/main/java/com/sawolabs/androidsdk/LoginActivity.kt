package com.sawolabs.androidsdk

import android.annotation.SuppressLint
import com.android.volley.DefaultRetryPolicy
import com.android.volley.Request


import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.util.Log
import android.view.View
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.ProgressBar
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import com.android.volley.toolbox.JsonObjectRequest
import com.android.volley.toolbox.Volley
import com.google.android.gms.common.api.Response
import com.google.gson.Gson
import com.onesignal.OSSubscriptionObserver
import com.onesignal.OSSubscriptionStateChanges
import com.onesignal.OneSignal
import okhttp3.OkHttpClient
import org.json.JSONObject

import java.net.URL
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
            Context.MODE_PRIVATE,
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
        sawoWebSDKURL = intent.getStringExtra(SAWO_WEBSDK_URL)
        callBackClassName = intent.getStringExtra(CALLBACK_CLASS)
        cryptographyManager = CryptographyManager()
        biometricPrompt = BiometricPromptUtils.createBiometricPrompt(
            this, ::processCancel, ::processData
        )
        promptInfo = BiometricPromptUtils.createPromptInfo(this)
        mWebView = findViewById(R.id.webview)
        mProgressBar = findViewById(R.id.progressBar)
        keyExistInStorage = cryptographyManager.isDataExistInSharedPrefs(
            this, SHARED_PREF_FILENAME, Context.MODE_PRIVATE, SHARED_PREF_ENC_PAIR_KEY
        )
        canStoreKeyInStorage =
            BiometricManager.from(applicationContext).canAuthenticate() == BiometricManager
                .BIOMETRIC_SUCCESS
        sawoWebSDKURL += "&keysExistInStorage=${keyExistInStorage}&canStoreKeyInStorage=${canStoreKeyInStorage}"
        mWebView.settings.javaScriptEnabled = true
        mWebView.settings.domStorageEnabled = true
        mWebView.settings.databaseEnabled = true
        mWebView.webViewClient = object : WebViewClient() {
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
        Handler().postDelayed(
            Runnable {
                val sharedPref = getSharedPreferences(SHARED_PREF_FILENAME, Context.MODE_PRIVATE)
                mWebView.addJavascriptInterface(
                    SawoWebSDKInterface(
                        ::passPayloadToCallbackActivity,
                        ::authenticateToEncrypt,
                        ::authenticateToDecrypt,
                        sharedPref.getString(SHARED_PREF_DEVICE_ID_KEY, null).toString()
                    ),
                    "webSDKInterface"
                )
                mWebView.loadUrl(sawoWebSDKURL)
            },
            2000
        )
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
                Context.MODE_PRIVATE,
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

        val deviceID = device!!.userId
        val deviceToken = device.pushToken

        if ((deviceID != null) and (deviceToken != null)) {
            if (deviceID != null) {
                getSharedPreferences(SHARED_PREF_FILENAME, Context.MODE_PRIVATE).edit().putString(
                    SHARED_PREF_DEVICE_ID_KEY, deviceID
                ).apply()
            }

/*
            val httpClient = OkHttpClient.Builder()
                .callTimeout(2, TimeUnit.MINUTES)
                .connectTimeout(30, TimeUnit.SECONDS)
*/

            /*val builder = HttpApiUtils.getRetrofitBuilder()

            builder.client(httpClient.build())
            val retrofit = builder.build()

            val registerDeviceApi = retrofit.create(RegisterDeviceApi::class.java)
            val deviceData = Device(
                deviceToken,
                deviceID,
                Build.MANUFACTURER.toString(),
                Build.MODEL.toString(),
                getDeviceName().toString(),
                "android"
            )
             val call = registerDeviceApi.sendDeviceData(deviceData)

            call.enqueue(object : Callback<Void> {
                override fun onResponse(call: Call<Void>, response: Response<Void>) {
                    if (response.isSuccessful) {
                        Log.d(TAG, "RegisterDeviceApi: Successful")
                    } else {
                        try {
                            Log.d(
                                TAG,
                                "RegisterDeviceApi: ${JSONObject(response.errorBody()!!.string())}"
                            )
                        } catch (e: Exception) {
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
*/

            val jsonObject = JSONObject()
            jsonObject.put("device_token",deviceToken)
            jsonObject.put("device_id",deviceID)
            jsonObject.put("device_brand",Build.MANUFACTURER.toString())
            jsonObject.put("device_model",Build.MODEL.toString())
            jsonObject.put("device_name",getDeviceName().toString())
            jsonObject.put("sdk_variant","android")

            val queue=Volley.newRequestQueue(this)

            val URL="https://api.sawolabs.com/api/v1/register_device/"

            val request = JsonObjectRequest(Request.Method.POST,URL,jsonObject,com.android.volley.Response.Listener { response ->
                val str = response.toString()
                Log.d("TAG","response: $str")
            }, com.android.volley.Response.ErrorListener{
                    error ->
                Log.d("TAG","response: ${error.message}")
            })

            queue.add(request)




        }
    }

    override fun onOSSubscriptionChanged(stateChanges: OSSubscriptionStateChanges) {
        Log.d(TAG, "OSSubscriptionStateChanged, calling registerDevice")
        registerDevice()
    }
}