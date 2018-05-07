package lint;

import com.android.tools.lint.checks.infrastructure.LintDetectorTest;
import com.android.tools.lint.detector.api.Detector;
import com.android.tools.lint.detector.api.Issue;
import com.android.tools.lint.detector.api.Severity;

import java.util.Collections;
import java.util.List;

import static com.android.SdkConstants.FN_ANDROID_MANIFEST_XML;

public class WrongPathPermissionPrecedenceTest extends LintDetectorTest {
    @Override
    protected Detector getDetector() {
        return new WrongPathPermissionPrecedenceDetector();
    }

    @Override
    protected List<Issue> getIssues() {
        return Collections.singletonList(WrongPathPermissionPrecedenceDetector.ISSUE);
    }

    public void testProviderWithPathPermission() {
        lint().files(
                xml(FN_ANDROID_MANIFEST_XML, "" +
                        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"+
                        "<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\"\n"+
                        "    package=\"test.pkg\">\n"+
                        "\n"+
                        "    <permission android:name=\"test.pkg.permission.normalRead\" android:protectionLevel=\"normal\"/>\n"+
                        "	<permission android:name=\"test.pkg.permission.internalRead\" android:protectionLevel=\"signature\"/>\n"+
                        "		\n"+
                        "    <application\n"+
                        "        android:allowBackup=\"true\"\n"+
                        "        android:icon=\"@mipmap/ic_launcher\"\n"+
                        "        android:label=\"@string/app_name\"\n"+
                        "        android:supportsRtl=\"true\"\n"+
                        "        android:theme=\"@style/AppTheme\">\n"+
                        "        <activity android:name=\".MainActivity\">\n"+
                        "            <intent-filter>\n"+
                        "                <action android:name=\"android.intent.action.MAIN\" />\n"+
                        "\n"+
                        "                <category android:name=\"android.intent.category.LAUNCHER\" />\n"+
                        "            </intent-filter>\n"+
                        "        </activity>\n"+
                        "\n"+
                        "        <provider\n"+
                        "            android:name=\".provider.UserDetailsContentProvider\"\n"+
                        "            android:authorities=\"test.pkg.userdetails\"\n"+
                        "            android:enabled=\"true\"\n"+
                        "            android:exported=\"true\"\n"+
                        "			android:permission=\"test.pkg.permission.normalRead\">\n"+
                        "            <path-permission android:pathPrefix=\"/user/secret\"\n"+
                        "			android:readPermission=\"test.pkg.permission.internalRead\"\n"+
                        "                   android:writePermission=\"test.pkg.permission.internalRead\"/>\n"+
                        "        </provider>\n"+
                        "\n"+
                        "    </application>\n"+
                        "\n"+
                        "</manifest>\n"))
                .run()
                .expectCount(1, Severity.WARNING).expectMatches(WrongPathPermissionPrecedenceDetector.MESSAGE);
    }

    public void testProviderWithPathPermissionForSearchSuggestion() {
        lint().files(
                xml(FN_ANDROID_MANIFEST_XML, "" +
                        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"+
                        "<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\"\n"+
                        "    package=\"test.pkg\">\n"+
                        "\n"+
                        "    <permission android:name=\"test.pkg.permission.normalRead\" android:protectionLevel=\"normal\"/>\n"+
                        "	<permission android:name=\"test.pkg.permission.internalRead\" android:protectionLevel=\"signature\"/>\n"+
                        "		\n"+
                        "    <application\n"+
                        "        android:allowBackup=\"true\"\n"+
                        "        android:icon=\"@mipmap/ic_launcher\"\n"+
                        "        android:label=\"@string/app_name\"\n"+
                        "        android:supportsRtl=\"true\"\n"+
                        "        android:theme=\"@style/AppTheme\">\n"+
                        "        <activity android:name=\".MainActivity\">\n"+
                        "            <intent-filter>\n"+
                        "                <action android:name=\"android.intent.action.MAIN\" />\n"+
                        "\n"+
                        "                <category android:name=\"android.intent.category.LAUNCHER\" />\n"+
                        "            </intent-filter>\n"+
                        "        </activity>\n"+
                        "\n"+
                        "        <provider\n"+
                        "            android:name=\".provider.UserDetailsContentProvider\"\n"+
                        "            android:authorities=\"test.pkg.userdetails\"\n"+
                        "            android:enabled=\"true\"\n"+
                        "            android:exported=\"true\"\n"+
                        "			android:permission=\"test.pkg.permission.normalRead\">\n"+
                        "            <path-permission android:pathPrefix=\"/user/search_suggest_query\"\n"+
                        "			android:readPermission=\"android.permission.GLOBAL_SEARCH\" />\n"+
                        "        </provider>\n"+
                        "\n"+
                        "    </application>\n"+
                        "\n"+
                        "</manifest>\n"))
                .run()
                .expectClean();
    }

    public void testMultipleProviderWithMultiplePathPermission() {
        lint().files(
                xml(FN_ANDROID_MANIFEST_XML, "" +
                        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"+
                        "<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\"\n"+
                        "    package=\"test.pkg\">\n"+
                        "\n"+
                        "    <permission android:name=\"test.pkg.permission.normalRead\" android:protectionLevel=\"normal\"/>\n"+
                        "	<permission android:name=\"test.pkg.permission.internalRead\" android:protectionLevel=\"signature\"/>\n"+
                        "		\n"+
                        "    <application\n"+
                        "        android:allowBackup=\"true\"\n"+
                        "        android:icon=\"@mipmap/ic_launcher\"\n"+
                        "        android:label=\"@string/app_name\"\n"+
                        "        android:supportsRtl=\"true\"\n"+
                        "        android:theme=\"@style/AppTheme\">\n"+
                        "        <activity android:name=\".MainActivity\">\n"+
                        "            <intent-filter>\n"+
                        "                <action android:name=\"android.intent.action.MAIN\" />\n"+
                        "\n"+
                        "                <category android:name=\"android.intent.category.LAUNCHER\" />\n"+
                        "            </intent-filter>\n"+
                        "        </activity>\n"+
                        "\n"+
                        "        <provider\n"+
                        "            android:name=\".provider.UserDetailsContentProvider\"\n"+
                        "            android:authorities=\"test.pkg.userdetails\"\n"+
                        "            android:enabled=\"true\"\n"+
                        "            android:exported=\"true\"\n"+
                        "			android:permission=\"test.pkg.permission.normalRead\">\n"+
                        "            <path-permission android:pathPrefix=\"/user/secret\"\n"+
                        "			android:readPermission=\"test.pkg.permission.internalRead\"\n"+
                        "                   android:writePermission=\"test.pkg.permission.internalRead\"/>\n"+
                        "        </provider>\n"+
                        "\n"+
                        "        <provider\n"+
                        "            android:name=\".provider.PrivateDataProvider\"\n"+
                        "            android:authorities=\"test.pkg.userdetails\"\n"+
                        "            android:enabled=\"true\"\n"+
                        "            android:exported=\"true\"\n"+
                        "			android:permission=\"test.pkg.permission.normalRead\">\n"+
                        "            <path-permission android:pathPrefix=\"/data/private\"\n"+
                        "			android:Permission=\"test.pkg.permission.internalRead\"/>\n"+
                        "            <path-permission android:pathPrefix=\"/search_suggest_query\"\n"+
                        "			android:readPermission=\"android.permission.GLOBAL_SEARCH\"/>\n"+
                        "        </provider>\n"+
                        "\n"+
                        "    </application>\n"+
                        "\n"+
                        "</manifest>\n"))
                .run()
                .expectCount(2, Severity.WARNING);
    }

    public void testNoPathPermission() {
        lint().files(
                xml(FN_ANDROID_MANIFEST_XML, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"+
                        "<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\"\n"+
                        "    package=\"test.pkg\">\n"+
                        "\n"+
                        "    <permission android:name=\"test.pkg.permission.normalRead\" android:protectionLevel=\"normal\"/>\n"+
                        "	<permission android:name=\"test.pkg.permission.internalRead\" android:protectionLevel=\"signature\"/>\n"+
                        "		\n"+
                        "    <application\n"+
                        "        android:allowBackup=\"true\"\n"+
                        "        android:icon=\"@mipmap/ic_launcher\"\n"+
                        "        android:label=\"@string/app_name\"\n"+
                        "        android:supportsRtl=\"true\"\n"+
                        "        android:theme=\"@style/AppTheme\">\n"+
                        "        <activity android:name=\".MainActivity\">\n"+
                        "            <intent-filter>\n"+
                        "                <action android:name=\"android.intent.action.MAIN\" />\n"+
                        "\n"+
                        "                <category android:name=\"android.intent.category.LAUNCHER\" />\n"+
                        "            </intent-filter>\n"+
                        "        </activity>\n"+
                        "\n"+
                        "        <provider\n"+
                        "            android:name=\".provider.UserDetailsContentProvider\"\n"+
                        "            android:authorities=\"test.pkg.userdetails\"\n"+
                        "            android:enabled=\"true\"\n"+
                        "            android:exported=\"true\">\n"+
                        "            <path-permission android:pathPrefix=\"/user/secret\"\n"+
                        "			android:readPermission=\"test.pkg.permission.internalRead\"\n"+
                        "                   android:writePermission=\"test.pkg.permission.internalRead\"/>\n"+
                        "        </provider>\n"+
                        "\n"+
                        "    </application>\n"+
                        "\n"+
                        "</manifest>\n"))
                .run()
                .expectClean();
    }
}
