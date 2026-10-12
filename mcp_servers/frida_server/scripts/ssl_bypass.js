// ssl_bypass.js — تجاوز SSL Certificate Pinning (MASVS-NETWORK)
// Real frida script: hooks X509TrustManager + OkHttp CertificatePinner.
// All activity is reported back via send() so the server can archive events.

Java.perform(function () {
    function report(detail) { send({ event: "bypass.active", detail: detail }); }

    // 1) Trust-all X509TrustManager — javax.net.ssl
    try {
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        var SSLContext = Java.use("javax.net.ssl.SSLContext");
        var TrustManager = Java.registerClass({
            name: "com.mas.TrustAllManager",
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) {},
                checkServerTrusted: function (chain, authType) {
                    report("checkServerTrusted bypassed (" + chain.length + " certs)");
                },
                getAcceptedIssuers: function () { return []; }
            }
        });
        var TrustAll = [TrustManager.$new()];
        var TLSContext = SSLContext.getInstance("TLS");
        TLSContext.init.overload(
            "[Ljavax.net.ssl.KeyManager;",
            "[Ljavax.net.ssl.TrustManager;",
            "java.security.SecureRandom"
        ).implementation = function (km, tm, sr) {
            report("SSLContext.init -> injecting TrustAll manager");
            return this.init(km, TrustAll, sr);
        };
        report("SSLContext.init(X509TrustManager)");
    } catch (e) {
        send({ event: "hook.error", detail: "X509TrustManager: " + e });
    }

    // 2) OkHttp3 CertificatePinner.check -> no-op
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload("java.lang.String", "java.util.List")
            .implementation = function (hostname, peerCerts) {
                report("okhttp3.CertificatePinner.check -> allowed for " + hostname);
            };
        report("okhttp3.CertificatePinner.check -> allowed");
    } catch (e) {
        send({ event: "hook.log", detail: "CertificatePinner not found (ok if unused)" });
    }

    // 3) WebViewClient SSL error handler (defence-in-depth)
    try {
        var WebViewClient = Java.use("android.webkit.WebViewClient");
        WebViewClient.onReceivedSslError.implementation = function (view, handler, error) {
            report("WebView SSL error ignored: " + error.toString());
            handler.proceed();
        };
    } catch (e) {
        send({ event: "hook.log", detail: "WebViewClient not hooked" });
    }
});
