let subtle = self.crypto.subtle;

function ab2str(buf) {
    return String.fromCharCode.apply(null, new Uint16Array(buf));
}

addEventListener('fetch', event => {
    event.respondWith(handleRequest(event.request))
})

async function generateSignandVerify(algorithm) {
    let rawMessage = "alice and bob"
    let key = await subtle.generateKey(algorithm, true, ["sign", "verify"]);
    let enc = new TextEncoder();
    let encoded = enc.encode(rawMessage);
    signature = await self.crypto.subtle.sign(
        algorithm,
        key,
        encoded
    );
    let result = await self.crypto.subtle.verify(
        algorithm,
        key,
        signature,
        encoded
    );
    return result;
}

async function generateEncryptDecrypt(algorithm, msg) {
    let key = await subtle.generateKey(
        algorithm,
        true,
        ["encrypt", "decrypt"]
    );
    let enc = new TextEncoder();
    let encoded = enc.encode(msg);
    algorithm.iv = crypto.getRandomValues(new Uint8Array(16))
    signature = await self.crypto.subtle.encrypt(
        algorithm,
        key,
        encoded
    );
    let result = await self.crypto.subtle.decrypt(
        algorithm,
        key,
        signature,
        encoded
    );
    return result;
}

async function handleRequest(request) {
    let msg = "alice and bob"
    let hmacresult = await generateSignandVerify({
        name: "HMAC",
        hash: "sha-256"
    })
    console.log("Result of HMAC generate, sign, verify: ", hmacresult)
    let aesresult = await generateEncryptDecrypt({
        name: "AES-GCM",
        length: 256
    }, msg)
    if (msg == ab2str(new Uint8Array(aesresult))) {
        console.log("AES encrypt decrypt successful")
    } else {
        console.log("AES encrypt decrypt failed")
    }
    return new Response()
}
