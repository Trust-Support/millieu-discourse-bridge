const express = require("express")
const crypto = require("crypto")
const querystring = require("querystring")
const app = express()
const port = 4000

const SSO_SECRET = "xxx"
const RETURN_URL = "xxx"
const CLIENT_URL = "xxx"
const DISCOURSE_ROOT_URL = "xxx"

let nonce = ""

app.get("/auth/discourse_sso", (req, res) => {
  let hmac = crypto.createHmac("sha256", SSO_SECRET)

  crypto.randomBytes(16, (err, buf) => {
    if (err) throw err

    // 1. Generate a random nonce. Save it temporarily so that you can
    //     verify it with returned nonce value
    nonce = buf.toString("hex")
    console.log("nonce:", nonce)

    // 2. Create a new payload with nonce and return url (where the Discourse
    //    will redirect user after verification).
    //    Payload should look like: nonce=NONCE&return_sso_url=RETURN_URL
    const payload = "nonce=" + nonce + "&return_sso_url=" + RETURN_URL
    console.log("payload", payload)

    // 3. Base64 encode the above raw payload. Let’s call this payload BASE64_PAYLOAD
    const payload_b64 = Buffer.from(payload).toString("base64")
    console.log("payload_b64", payload_b64)

    // 4. URL encode the above BASE64_PAYLOAD. Let’s call this payload as URL_ENCODED_PAYLOAD
    const urlenc_payload_b64 = encodeURIComponent(payload_b64)
    console.log("urlenc_payload_b64", urlenc_payload_b64)

    // 5. Generate a HMAC-SHA256 signature from BASE64_PAYLOAD using your sso provider secret as the key,
    //    then create a lower case hex string from this. Let’s call this signature as HEX_SIGNATURE
    hmac.update(payload_b64)
    const hex_sig = hmac.digest("hex")
    console.log("hex_sig", hex_sig)

    // Redirect the user to DISCOURSE_ROOT_URL/session/sso_provider?sso=URL_ENCODED_PAYLOAD&sig=HEX_SIGNATURE
    const redirectURL =
      DISCOURSE_ROOT_URL +
      "/session/sso_provider?sso=" +
      urlenc_payload_b64 +
      "&sig=" +
      hex_sig
    console.log("redirectURL", redirectURL)
    res.redirect(redirectURL)
  })
})

app.get("/discourse_sso/verify_discourse_sso", (req, res) => {
  console.dir(req.query)

  if (req.query.sig && req.query.sso) {
    // Compute the HMAC-SHA256 of sso using sso provider secret as your key.
    let hmac = crypto.createHmac("sha256", SSO_SECRET)
    const decoded_sso = decodeURIComponent(req.query.sso)
    hmac.update(decoded_sso)
    const hash = hmac.digest("hex")
    console.log("hash", hash)
    // Convert sig from it’s hex string representation back into bytes.

    // Make sure the above two values are equal.
    if (req.query.sig == hash) {
      // Base64 decode sso, you’ll get the passed embedded query string.
      // This will have a key called nonce whose value should match the
      // nonce passed originally. Make sure that this is the case.
      const b = Buffer.from(req.query.sso, "base64")
      const inner_qstring = b.toString("utf8")
      let ret = querystring.parse(inner_qstring)
      console.dir(ret)
      // res.json(ret)
      res.redirect(
        CLIENT_URL + "/authenticate/" + req.query.sso + "/" + req.query.sig
      )

      // var orig_req = thiz.NONCE_TABLE[ret.nonce];
      // if(ret.nonce && orig_req) {
      //     // ret.opts = thiz.NONCE_TABLE[ret.nonce].opts;
      //     // delete thiz.NONCE_TABLE[ret.nonce];
      //     console.log("AUTH was successful");
      //     res.send('sucess')
      // }
    }
  }
})

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`)
})
