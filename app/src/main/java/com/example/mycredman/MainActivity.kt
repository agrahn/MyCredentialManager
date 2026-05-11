package com.example.mycredman

import android.util.Base64
import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.util.Log
import androidx.activity.compose.setContent
import androidx.appcompat.app.AppCompatActivity
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.provider.PendingIntentHandler
import androidx.credentials.webauthn.AuthenticatorAssertionResponse
import androidx.credentials.webauthn.AuthenticatorAttestationResponse
import androidx.credentials.webauthn.FidoPublicKeyCredential
import androidx.credentials.webauthn.PublicKeyCredentialCreationOptions
import androidx.credentials.webauthn.PublicKeyCredentialRequestOptions
import com.example.mycredman.ui.theme.MyCredManTheme
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.math.BigInteger
import java.security.KeyPair
import java.security.PrivateKey
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature

@OptIn(kotlin.ExperimentalStdlibApi::class)
class MainActivity : AppCompatActivity() {

    private val EXTRA_KEY_ACCOUNT_ID  = "com.example.mycredman.extra.EXTRA_KEY_ACCOUNT_ID"


    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        if(intent != null && intent.action == "com.example.mycredman.action.CREATE_PASSKEY") {
            val request =
                PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)

            val accountId = intent.getStringExtra(EXTRA_KEY_ACCOUNT_ID)
            if (request != null && request.callingRequest is CreatePublicKeyCredentialRequest) {
                val publicKeyRequest: CreatePublicKeyCredentialRequest =
                    request.callingRequest as CreatePublicKeyCredentialRequest
                createPasskey(
                    publicKeyRequest.requestJson,
                    request.callingAppInfo,
                    publicKeyRequest.clientDataHash,
                    accountId
                )
            }
        }else if(intent.action == "com.example.mycredman.action.GET_PASSKEY"){
            val getRequest =
                PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
            val publicKeyRequests =
                getRequest!!.credentialOptions as List<GetPublicKeyCredentialOption>

            val requestInfo = intent.getBundleExtra("CREDENTIAL_DATA")

            publicKeyRequests.forEach { credentialOption ->
                Log.d("MainActivity", "requsetJson:${credentialOption.requestJson}")
            }

            val credIdEnc = requestInfo?.getString("credId")
            val requestJson = (Json {ignoreUnknownKeys = true}).decodeFromString<GetPublicKeyCredentialRequestJson>(publicKeyRequests[0].requestJson)
            Log.d("MainActivity", "onCreate rpid:${requestJson.rpId}")
            Log.d("MainActivity", "${credIdEnc}")

            // Get the saved passkey from your database based on the credential ID
            // from the publickeyRequest
            
            // Decode the credential ID, private key and user ID

            val credId = Base64.decode(credIdEnc, Base64.URL_SAFE)
            val rpid = CredmanUtils.validateRpId(getRequest.callingAppInfo,requestJson.rpId)
            val passkey = MyCredentialDataManager.load(this,rpid,credId!!)
            val privateKey = passkey!!.keyPair!!.private
            val uid = passkey.userHandle
            val origin = CredmanUtils.appInfoToOrigin(getRequest.callingAppInfo)
            val packageName = getRequest.callingAppInfo.packageName
            val clientDataHash = publicKeyRequests[0].requestData.getByteArray("androidx.credentials.BUNDLE_KEY_CLIENT_DATA_HASH")
            Log.d("MainActivity","+++ clientDataHash: "+Base64.encodeToString(clientDataHash!!, Base64.URL_SAFE or Base64.NO_PADDING))

            validatePasskey(
                publicKeyRequests[0].requestJson,
                origin,
                packageName,
                uid,
                passkey.displayName,
                credId,
                privateKey,
                clientDataHash
            )
        }

    }

    @OptIn(ExperimentalMaterial3Api::class)
    override fun onResume() {
        super.onResume()
        setContent {
            MyCredManTheme {
                val credentialList = MyCredentialDataManager.loadAll(this@MainActivity)
                if (credentialList.size > 0) {
                    Column {
                        TopAppBar(
                            title = { Text(text = "My Credential Manager") },
                        )
                        CredentialList(credentialList)

                    }
                } else {
                    Column {
                        TopAppBar(
                            title = { Text(text = "My Credential Manager") },
                        )
                        Text("No Credential Yet", color = MaterialTheme.colorScheme.primary)
                    }
                }

            }
        }
    }


    @Composable
    fun CredentialList(credentials: MutableList <MyCredentialDataManager.Credential>) {

        val intent = Intent(LocalContext.current,CredentialDetailsActivity::class.java)
        Column (
            modifier = Modifier
                .verticalScroll(rememberScrollState())
        ) {
            credentials.forEach {
                Column (
                    Modifier
                        .padding(12.dp)
                        .border(
                            width = 2.dp,
                            color = MaterialTheme.colorScheme.secondary,
                            shape = RoundedCornerShape(20.dp)
                        )
                        .clickable(onClick = {
                            Log.d("MainActivity", "onClick")
                            intent.putExtra("ServiceName", it.serviceName)
                            intent.putExtra("ServiceNameUrl", it.rpid)
                            intent.putExtra("ServiceNameId", it.displayName)
                            intent.putExtra("stringcredentialId", it.credentialId)
                            Log.d("MainActivity",it.credentialId.toString())
                            startActivity(intent)
                        })
                        .padding(16.dp)
                        .fillMaxWidth()
                )  {
                    Text(text = it.serviceName, color = MaterialTheme.colorScheme.primary, fontSize = 30.sp, fontWeight = FontWeight.Bold, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Text(text = "URL: ${it.rpid}", color = MaterialTheme.colorScheme.secondary, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Text(text = "ID:  ${it.displayName}", color = MaterialTheme.colorScheme.secondary, maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
            }
        }
    }


    @Preview
    @Composable
    fun PreviewCredentialEntry() {
        val credentials = mutableListOf<MyCredentialDataManager.Credential>(
            MyCredentialDataManager.Credential(serviceName = "Sample1", rpid = "www.example.com", displayName="apple1", credentialId = byteArrayOf(0x01)),
            MyCredentialDataManager.Credential(serviceName = "Sample1", rpid = "www.example.com", displayName="apple2", credentialId = byteArrayOf(0x02)),
            MyCredentialDataManager.Credential(serviceName = "Sample1", rpid = "www.example.com", displayName="apple3", credentialId = byteArrayOf(0x03)),

        )
        CredentialList(credentials)
    }

    // https://developer.android.com/training/sign-in/credential-provider#handle-passkey-credential
    private fun createPasskey(
        requestJson: String,
        callingAppInfo: androidx.credentials.provider.CallingAppInfo?,
        clientDataHash: ByteArray?,
        accountId: String?
    ) {
        Log.d("MainActivity", "===requestJson===: "+requestJson)

        val request = PublicKeyCredentialCreationOptions(requestJson)


        // Generate a credentialId
        val credentialId = ByteArray(32)
        SecureRandom().nextBytes(credentialId)

        // Generate a credential key pair
        val keyPairGen = KeyPairGenerator.getInstance("Ed25519")
        val keyPair = keyPairGen.generateKeyPair()


        // check if rpid is a subdomain of origin
        val rpid = CredmanUtils.validateRpId(callingAppInfo!!,request.rp.id)
        Log.d("MainActivity", "===rpid === :" + rpid)

        // Save passkey in your database as per your own implementation

        MyCredentialDataManager.save(this@MainActivity, MyCredentialDataManager.Credential(
            rpid = rpid,
            serviceName = request.rp.name,
            credentialId = credentialId,
            displayName = request.user.displayName,
            userHandle = request.user.id,
            keyPair = keyPair
        ))

        // Create AuthenticatorAttestationResponse object to pass to
        // FidoPublicKeyCredential

        val response = AuthenticatorAttestationResponse(
            requestOptions = request,
            credentialId = credentialId,
            credentialPublicKey = getPublicKeyFromKeyPair(keyPair), //CBOR
            origin = CredmanUtils.appInfoToOrigin(callingAppInfo),
            up = true,
            uv = true,
            be = true,
            bs = true,
            packageName = callingAppInfo.packageName,
            clientDataHash = clientDataHash
        )

        val credential = FidoPublicKeyCredential(
            rawId = credentialId, response = response , authenticatorAttachment = "platform"
        )

        //add easy accessors fields as defined in https://github.com/w3c/webauthn/pull/1887
        val credentialJson = populateEasyAccessorFields(credential.json(),rpid, keyPair,credentialId)

        val result = Intent()

        val createPublicKeyCredResponse =
            CreatePublicKeyCredentialResponse(credentialJson)

        // Set the CreateCredentialResponse as the result of the Activity
        PendingIntentHandler.setCreateCredentialResponse(
            result, createPublicKeyCredResponse
        )
        setResult(Activity.RESULT_OK, result)
        finish()

    }

    private fun populateEasyAccessorFields(json: String, rpid: String, keyPair: KeyPair, credentialId: ByteArray): String {
        Log.d("MainActivity", "=== populateEasyAccessorFields BEFORE === " + json)
        val response = Json.decodeFromString<CreatePublicKeyCredentialResponseJson>(json)
    
        // EdDSA algorithm ID
        response.response.publicKeyAlgorithm = -8
    
        // Extract raw 32-byte Ed25519 public key
        val encodedKey = keyPair.public.encoded
        val rawKeyBytes = if (encodedKey.size >= 32) {
            encodedKey.sliceArray((encodedKey.size - 32) until encodedKey.size)
        } else {
            byteArrayOf()
        }
    
        response.response.publicKey = Base64.encodeToString(rawKeyBytes, Base64.URL_SAFE or Base64.NO_PADDING)
        response.response.authenticatorData = getAuthData(rpid, credentialId, keyPair)
    
        Log.d("MainActivity", "=== populateEasyAccessorFields AFTER === " + Json.encodeToString(response))
        return Json.encodeToString(response)
    }

    private fun getAuthData(rpid:String, credentialRawId:ByteArray, keyPair: KeyPair ):String{
        /**
         * https://github.com/passkeydeveloper/passkey-authenticator-aaguids, to be superseeded by
         * FIDO Alliance Metadata Service (MDS) at some point in the future https://fidoalliance.org/metadata
         * (not mandatory)
         */
        val AAGUID = "00000000000000000000000000000000"
        check(AAGUID.length % 2 == 0) { "AAGUID Must have an even length" }

        val rpIdHash:ByteArray = MessageDigest.getInstance("SHA-256")
            .digest(rpid.toByteArray())

        val flags: ByteArray = byteArrayOf(0x5d.toByte())
        val signCount:ByteArray = byteArrayOf(0x00, 0x00, 0x00, 0x00)
        val aaguid = AAGUID.hexToByteArray()
        val credentialIdLength:ByteArray = byteArrayOf(0x00, credentialRawId.size.toByte()) // = 20 bytes
        // val credentialId
        val credentialPublicKey:ByteArray =getPublicKeyFromKeyPair(keyPair)

        val retVal = rpIdHash + flags + signCount + aaguid + credentialIdLength + credentialRawId + credentialPublicKey
        return Base64.encodeToString(retVal, Base64.URL_SAFE or Base64.NO_PADDING)
    }

    // https://developer.android.com/training/sign-in/credential-provider#passkeys-implement
    fun validatePasskey(
        requestJson: String,
        origin: String,
        packageName: String,
        uid: ByteArray,
        username: String,
        credId: ByteArray,
        privateKey: PrivateKey,
        clientDataHash: ByteArray?
    ) {
        val request = PublicKeyCredentialRequestOptions(requestJson)
    
        val response = AuthenticatorAssertionResponse(
            requestOptions = request,
            credentialId = credId,
            origin = origin,
            up = true,
            uv = true,
            be = true,
            bs = true,
            userHandle = uid,
            clientDataHash = clientDataHash
        )
    
        Log.d("MainActivity", "response.dataToSign(): ${Base64.encodeToString(response.dataToSign(), Base64.URL_SAFE or Base64.NO_PADDING)}")
    
        // Try signature algorithms in order of preference
        val signatureAlgorithms = listOf("Ed25519", "SHA256withECDSA", "SHA256withRSA")
        var signature: ByteArray? = null
    
        for (algorithm in signatureAlgorithms) {
            try {
                Log.d("MainActivity", "Trying signature algorithm: $algorithm")
                val sig = Signature.getInstance(algorithm)
                sig.initSign(privateKey)
                sig.update(response.dataToSign())
                signature = sig.sign()
                Log.d("MainActivity", "Successfully signed with algorithm: $algorithm")
                break
            } catch (e: Exception) {
                Log.d("MainActivity", "Algorithm $algorithm failed: ${e.message}")
                continue
            }
        }
    
        if (signature == null) {
            Log.e("MainActivity", "Failed to sign with any supported algorithm")
            return
        }
    
        response.signature = signature
    
        val credential = FidoPublicKeyCredential(
            rawId = credId,
            response = response,
            authenticatorAttachment = "platform"
        )
    
        Log.d("MainActivity", "+++ credential.json(): " + credential.json())
    
        // add clientDataJSON to the response
        val clientDataJSONb64 = getClientDataJSONb64(origin, Base64.encodeToString(request.challenge, Base64.URL_SAFE or Base64.NO_PADDING))
        val delimiter = "response\":{"
        val credentialJson = credential.json().substringBeforeLast(delimiter) + delimiter +
                "\"clientDataJSON\":\"$clientDataJSONb64\"," +
                credential.json().substringAfterLast(delimiter)
    
        Log.d("MainActivity", "+++ credentialJson: " + credentialJson)
    
        val result = Intent()
        val passkeyCredential = PublicKeyCredential(credentialJson)
        PendingIntentHandler.setGetCredentialResponse(
            result, GetCredentialResponse(passkeyCredential)
        )
        setResult(RESULT_OK, result)
        finish()
    }

    private fun getClientDataJSONb64(origin: String,challenge:String): String {

        val origin = origin.replace(Regex("/$"), "")

        val jsonString =
            "{\"type\":\"webauthn.get\",\"challenge\":\"$challenge\",\"origin\":\"$origin\",\"crossOrigin\":false}"
        val jsonByteArray = jsonString.toByteArray()
        Log.d("MainActivity","+++ ClientDataJSON: $jsonString")
        return Base64.encodeToString(jsonByteArray, Base64.URL_SAFE or Base64.NO_PADDING)
    }

    @Serializable
    private data class CreatePublicKeyCredentialResponseJson(
        //RegistrationResponseJSON
        val id:String,
        val rawId: String,
        val response: Response,
        val authenticatorAttachment: String?,
        val clientExtensionResults: EmptyClass = EmptyClass(),
        val type: String,
    ) {
        @Serializable
        data class Response(
            //AuthenticatorAttestationResponseJSON
            val clientDataJSON: String? = null,
            var authenticatorData: String? = null,
            val transports: List<String>? = arrayOf("internal").toList(),
            var publicKey: String? = null, // easy accessors fields
            var publicKeyAlgorithm: Long? =null, // easy accessors fields
            val attestationObject: String? // easy accessors fields
        )
        @Serializable
        class EmptyClass
    }

    private fun getPublicKeyFromKeyPair(keyPair: KeyPair?): ByteArray {
      // credentialPublicKey CBOR for Ed25519
      if (keyPair == null) return ByteArray(0)

      // Extract the raw 32-byte Ed25519 public key from the encoded form
      val encodedKey = keyPair.public.encoded

      // Ed25519 public keys in X.509 format have the raw 32 bytes at the end
      // Structure: SEQUENCE { SEQUENCE { OID }, BIT STRING { raw key } }
      // We need to extract just the 32-byte key
      val rawKeyBytes = if (encodedKey.size >= 32) {
          encodedKey.sliceArray((encodedKey.size - 32) until encodedKey.size)
      } else {
          return ByteArray(0)
      }

      // CBOR encoding for Ed25519:
      // A4 = map with 4 items
      // 01 = key 1 (kty: Key Type)
      // 01 = value 1 (OKP: Octet string key pairs)
      // 03 = key 3 (alg: Algorithm)
      // 27 = value -8 (EdDSA)
      // -1 (20 in CBOR) = key -1 (crv: Curve)
      // 06 = value 6 (Ed25519)
      // -2 (21 in CBOR) = key -2 (x: public key coordinate)
      // 58 20 = byte string of length 32
      // [32 bytes of key]
      val cborHeader = "A4010103272006215820".hexToByteArray()

      return cborHeader + rawKeyBytes
    } 

}

