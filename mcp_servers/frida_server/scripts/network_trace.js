// network_trace.js — تتبع الشبكة (أدلة MASVS-NETWORK: cleartext, تعريفات endpoints)
// Hooks java.net.URL.openConnection, HttpURLConnection responses and OkHttp requests.
// Cleartext http:// URLs are flagged as (cleartext HTTP).

Java.perform(function () {
    function tag(url) {
        return url.indexOf("http://") === 0 ? " (cleartext HTTP)" : "";
    }

    // 1) URL.openConnection — capture requested URLs
    try {
        var URL = Java.use("java.net.URL");
        URL.openConnection.overload().implementation = function () {
            var url = this.toString();
            send({ event: "openConnection", detail: url + tag(url) });
            return this.openConnection();
        };
    } catch (e) {
        send({ event: "hook.error", detail: "URL.openConnection: " + e });
    }

    // 2) HttpURLConnection.getResponseCode — status per URL
    try {
        var HttpURLConnection = Java.use("java.net.HttpURLConnection");
        HttpURLConnection.getResponseCode.implementation = function () {
            var code = this.getResponseCode();
            send({
                event: "getResponseCode",
                detail: "url=" + this.getURL().toString() + " code=" + code
            });
            return code;
        };
    } catch (e) {
        send({ event: "hook.error", detail: "HttpURLConnection: " + e });
    }

    // 3) OkHttp3 Request.Builder.url — REST endpoints
    try {
        var RequestBuilder = Java.use("okhttp3.Request$Builder");
        RequestBuilder.url.overload("java.lang.String").implementation = function (url) {
            send({ event: "Request.Builder.url", detail: url + tag(url) });
            return this.url(url);
        };
    } catch (e) {
        send({ event: "hook.log", detail: "OkHttp3 not found (ok if unused)" });
    }

    send({ event: "hook.installed", detail: "network hooks active (URL/HttpURLConnection/OkHttp)" });
});
