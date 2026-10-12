// root_bypass.js — تجاوز كشف الروت (اختبار صلابة MASVS-RESILIENCE)
// Hides classic root indicators: su binary paths, 'su' execution, root packages,
// and test-keys build tags. Events are sent back via send().

Java.perform(function () {
    function report(detail) { send({ event: "bypass.active", detail: detail }); }

    var rootPaths = [
        "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
        "/data/local/xbin/su", "/data/local/bin/su", "/system/sd/xbin/su",
        "/magisk", "/system/app/Superuser.apk"
    ];
    var rootPackages = [
        "com.noshufou.android.su", "com.topjohnwu.magisk",
        "eu.chainfire.supersu", "com.koushikdutta.superuser"
    ];

    // 1) java.io.File.exists -> false for root paths
    try {
        var File = Java.use("java.io.File");
        File.exists.implementation = function () {
            var path = this.getAbsolutePath();
            if (rootPaths.indexOf(path) !== -1) {
                report("File.exists -> false for " + path);
                return false;
            }
            return this.exists();
        };
        report("File.exists -> false for su/magisk paths");
    } catch (e) {
        send({ event: "hook.error", detail: "File.exists: " + e });
    }

    // 2) Runtime.exec('su') -> throw (simulates absence)
    try {
        var Runtime = Java.use("java.lang.Runtime");
        Runtime.exec.overload("java.lang.String").implementation = function (cmd) {
            if (cmd === "su" || cmd.indexOf("/su") !== -1) {
                report("Runtime.exec('" + cmd + "') blocked (returns false)");
                throw Java.use("java.io.IOException").$new("Permission denied");
            }
            return this.exec(cmd);
        };
        report("Runtime.exec('su') blocked");
    } catch (e) {
        send({ event: "hook.error", detail: "Runtime.exec: " + e });
    }

    // 3) PackageManager.getPackageInfo(root pkg) -> NameNotFoundException
    try {
        var PackageManager = Java.use("android.app.ApplicationPackageManager");
        var NameNotFound = Java.use("android.content.pm.PackageManager$NameNotFoundException");
        PackageManager.getPackageInfo.overload("java.lang.String", "int")
            .implementation = function (pkg, flags) {
                if (rootPackages.indexOf(pkg) !== -1) {
                    report("PackageManager.getPackageInfo(" + pkg + ") hidden");
                    throw NameNotFound.$new(pkg);
                }
                return this.getPackageInfo(pkg, flags);
            };
        report("PackageManager.getPackageInfo(superuser) hidden");
    } catch (e) {
        send({ event: "hook.error", detail: "PackageManager: " + e });
    }

    // 4) Build.TAGS test-keys spoof
    try {
        var Build = Java.use("android.os.Build");
        Build.TAGS.value = "release-keys";
        report("Build.TAGS -> release-keys");
    } catch (e) {
        send({ event: "hook.log", detail: "Build.TAGS spoof skipped" });
    }
});
