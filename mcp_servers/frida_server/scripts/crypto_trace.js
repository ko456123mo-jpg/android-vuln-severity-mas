// crypto_trace.js — تتبع استدعاءات التشفير (أدلة MASVS-CRYPTO)
// Logs Cipher/MessageDigest/Mac algorithms and SecretKeySpec key material.
// Weak algorithms/modes (ECB, MD5, DES, SHA1) are flagged as (weak) in detail.

Java.perform(function () {
    function toHex(bytes) {
        if (!bytes) return "null";
        var hex = "";
        var limit = Math.min(bytes.length, 32);
        for (var i = 0; i < limit; i++) {
            var b = bytes[i] & 0xff;
            hex += ("0" + b.toString(16)).slice(-2);
        }
        return hex + (bytes.length > limit ? ".." : "");
    }
    function flag(alg) {
        return /ECB|MD5|DES|SHA1|RC4/i.test(alg) ? " (weak)" : "";
    }

    // Cipher.getInstance — transformation (algo/mode/padding)
    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        Cipher.getInstance.overload("java.lang.String").implementation = function (alg) {
            send({ event: "Cipher.getInstance", detail: "algorithm=" + alg + flag(alg) });
            return this.getInstance(alg);
        };
    } catch (e) {
        send({ event: "hook.error", detail: "Cipher: " + e });
    }

    // Cipher.doFinal — payload sizes (evidence of crypto in use)
    try {
        var Cipher2 = Java.use("javax.crypto.Cipher");
        Cipher2.doFinal.overload("[B").implementation = function (input) {
            var out = this.doFinal(input);
            send({
                event: "Cipher.doFinal",
                detail: "input_len=" + (input ? input.length : 0) +
                    " output_len=" + (out ? out.length : 0)
            });
            return out;
        };
    } catch (e) {
        send({ event: "hook.error", detail: "Cipher.doFinal: " + e });
    }

    // SecretKeySpec — key material (hardcoded key evidence)
    try {
        var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
        SecretKeySpec.$init.overload("[B", "java.lang.String").implementation = function (key, alg) {
            send({
                event: "SecretKeySpec.init",
                detail: "alg=" + alg + " key_hex=" + toHex(key) + " (hardcoded)"
            });
            return this.$init(key, alg);
        };
    } catch (e) {
        send({ event: "hook.error", detail: "SecretKeySpec: " + e });
    }

    // MessageDigest — hashing algorithms (MD5/SHA1 flagged)
    try {
        var MessageDigest = Java.use("java.security.MessageDigest");
        MessageDigest.getInstance.overload("java.lang.String").implementation = function (alg) {
            send({ event: "MessageDigest.getInstance", detail: "algorithm=" + alg + flag(alg) });
            return this.getInstance(alg);
        };
    } catch (e) {
        send({ event: "hook.error", detail: "MessageDigest: " + e });
    }

    send({ event: "hook.installed", detail: "crypto hooks active (Cipher/SecretKeySpec/MessageDigest)" });
});
