/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Pascal Gadient et al. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for the license information.
 *--------------------------------------------------------------------------------------------*/

package lint;

import com.android.tools.lint.checks.infrastructure.LintDetectorTest;
import com.android.tools.lint.detector.api.Detector;
import com.android.tools.lint.detector.api.Issue;
import com.android.tools.lint.detector.api.Severity;

import java.util.Collections;
import java.util.List;

import static com.android.SdkConstants.FN_ANDROID_MANIFEST_XML;

public class PathPermissionProblematicUriMatchingTest extends LintDetectorTest {
    @Override
    protected Detector getDetector() {
        return new PathPermissionProblematicUriMatchingDetector();
    }

    @Override
    protected List<Issue> getIssues() {
        return Collections.singletonList(PathPermissionProblematicUriMatchingDetector.ISSUE);
    }

    public void testProviderUsingUriMatcherAndPathPermission() {
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
                        "            android:exported=\"true\"\n>"+
                        "            <path-permission android:pathPrefix=\"/user/secret\"\n"+
                        "			android:readPermission=\"test.pkg.permission.internalRead\"\n"+
                        "                   android:writePermission=\"test.pkg.permission.internalRead\"/>\n"+
                        "        </provider>\n"+
                        "\n"+
                        "    </application>\n"+
                        "\n"+
                        "</manifest>\n"),
                java("package test.pkg.provider;\n"+
                        "\n"+
                        "import android.content.ContentProvider;\n"+
                        "import android.content.ContentValues;\n"+
                        "import android.content.UriMatcher;\n"+
                        "import android.database.Cursor;\n"+
                        "import android.database.MatrixCursor;\n"+
                        "import android.net.Uri;\n"+
                        "import android.util.Log;\n"+
                        "import java.util.ArrayList;\n"+
                        "import android.os.Build;\n"+
                        "\n"+
                        "public class UserDetailsContentProvider extends ContentProvider {\n"+
                        "\n"+
                        "    private static final UriMatcher sUriMatcher = new UriMatcher(UriMatcher.NO_MATCH);\n"+
                        "    static{\n"+
                        "        sUriMatcher.addURI(\"test.pkg.userdetails\",\"/user/secret\",1);\n"+
                        "    }\n"+
                        "\n"+
                        "    public UserDetailsContentProvider() {\n"+
                        "    }\n"+
                        "\n"+
                        "    @Override\n"+
                        "    public int delete(Uri uri, String selection, String[] selectionArgs) {\n"+
                        "        return 0;\n"+
                        "    }\n"+
                        "\n"+
                        "    @Override\n"+
                        "    public String getType(Uri uri) {\n"+
                        "        return null;\n"+
                        "    }\n"+
                        "\n"+
                        "    @Override\n"+
                        "    public Uri insert(Uri uri, ContentValues values) {\n"+
                        "        return null;\n"+
                        "    }\n"+
                        "\n"+
                        "    @Override\n"+
                        "    public boolean onCreate() {\n"+
                        "        return true;\n"+
                        "    }\n"+
                        "\n"+
                        "    @Override\n"+
                        "    public Cursor query(Uri uri, String[] projection, String selection,\n"+
                        "                        String[] selectionArgs, String sortOrder) {\n"+
                        "\n"+
                        "        MatrixCursor cursor = null;\n"+
                        "		ArrayList columnValues = new ArrayList();\n"+
                        "\n"+
                        "        switch (sUriMatcher.match(uri)){\n"+
                        "            case 1:\n"+
                        "				cursor = new MatrixCursor(new String[]{\"ID\",\"SSN\"});\n"+
                        "				columnValues.add(\"1\");\n"+
                        "				columnValues.add(\"11AA11\");\n"+
                        "				cursor.addRow(columnValues);\n"+
                        "        }\n"+
                        "        return cursor;\n"+
                        "    }\n"+
                        "\n"+
                        "    @Override\n"+
                        "    public int update(Uri uri, ContentValues values, String selection,\n"+
                        "                      String[] selectionArgs) {\n"+
                        "        return 0;\n"+
                        "    }\n"+
                        "}\n"+
                        "\n"))
                .run()
                .expectCount(1, Severity.WARNING).expectMatches(PathPermissionProblematicUriMatchingDetector.MESSAGE);
    }


    public void testProviderNotUsingUriMatcherButWithPathPermission() {
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
                        "            android:exported=\"true\">\n"+
                        "            <path-permission android:pathPrefix=\"/user/secret\"\n"+
                        "			android:readPermission=\"test.pkg.permission.internalRead\"\n"+
                        "                   android:writePermission=\"test.pkg.permission.internalRead\"/>\n"+
                        "        </provider>\n"+
                        "\n"+
                        "    </application>\n"+
                        "\n"+
                        "</manifest>\n"),
                java("package test.pkg.provider;\n"+
                        "\n"+
                        "import android.content.ContentProvider;\n"+
                        "import android.content.ContentValues;\n"+
                        "import android.content.UriMatcher;\n"+
                        "import android.database.Cursor;\n"+
                        "import android.database.MatrixCursor;\n"+
                        "import android.net.Uri;\n"+
                        "import android.util.Log;\n"+
                        "import java.util.ArrayList;\n"+
                        "import android.os.Build;\n"+
                        "\n"+
                        "public class UserDetailsContentProvider extends ContentProvider {\n"+
                        "\n"+
                        "    public UserDetailsContentProvider() {\n"+
                        "    }\n"+
                        "\n"+
                        "    @Override\n"+
                        "    public int delete(Uri uri, String selection, String[] selectionArgs) {\n"+
                        "        return 0;\n"+
                        "    }\n"+
                        "\n"+
                        "    @Override\n"+
                        "    public String getType(Uri uri) {\n"+
                        "        return null;\n"+
                        "    }\n"+
                        "\n"+
                        "    @Override\n"+
                        "    public Uri insert(Uri uri, ContentValues values) {\n"+
                        "        return null;\n"+
                        "    }\n"+
                        "\n"+
                        "    @Override\n"+
                        "    public boolean onCreate() {\n"+
                        "        return true;\n"+
                        "    }\n"+
                        "\n"+
                        "    @Override\n"+
                        "    public Cursor query(Uri uri, String[] projection, String selection,\n"+
                        "                        String[] selectionArgs, String sortOrder) {\n"+
                        "       MatrixCursor cursor = null;\n"+
                        "		ArrayList columnValues = new ArrayList();\n"+
                        "		cursor = new MatrixCursor(new String[]{\"ID\",\"SSN\"});\n"+
                        "		columnValues.add(\"1\");\n"+
                        "		columnValues.add(\"11AA11\");\n"+
                        "		cursor.addRow(columnValues);\n"+
                        "       return cursor;\n"+
                        "    }\n"+
                        "\n"+
                        "    @Override\n"+
                        "    public int update(Uri uri, ContentValues values, String selection,\n"+
                        "                      String[] selectionArgs) {\n"+
                        "        return 0;\n"+
                        "    }\n"+
                        "}\n"+
                        "\n"))
                .run()
                .expectClean();
    }

    public void testProviderUsingUriMatcherWithoutPathPermission() {
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
                        "        </provider>\n"+
                        "\n"+
                        "    </application>\n"+
                        "\n"+
                        "</manifest>\n"),
                java("package test.pkg.provider;\n"+
                        "\n"+
                        "import android.content.ContentProvider;\n"+
                        "import android.content.ContentValues;\n"+
                        "import android.content.UriMatcher;\n"+
                        "import android.database.Cursor;\n"+
                        "import android.database.MatrixCursor;\n"+
                        "import android.net.Uri;\n"+
                        "import android.util.Log;\n"+
                        "import java.util.ArrayList;\n"+
                        "import android.os.Build;\n"+
                        "\n"+
                        "public class UserDetailsContentProvider extends ContentProvider {\n"+
                        "\n"+
                        "    private static final UriMatcher sUriMatcher = new UriMatcher(UriMatcher.NO_MATCH);\n"+
                        "    static{\n"+
                        "        sUriMatcher.addURI(\"test.pkg.userdetails\",\"/user/secret\",1);\n"+
                        "    }\n"+
                        "\n"+
                        "    public UserDetailsContentProvider() {\n"+
                        "    }\n"+
                        "\n"+
                        "    @Override\n"+
                        "    public int delete(Uri uri, String selection, String[] selectionArgs) {\n"+
                        "        return 0;\n"+
                        "    }\n"+
                        "\n"+
                        "    @Override\n"+
                        "    public String getType(Uri uri) {\n"+
                        "        return null;\n"+
                        "    }\n"+
                        "\n"+
                        "    @Override\n"+
                        "    public Uri insert(Uri uri, ContentValues values) {\n"+
                        "        return null;\n"+
                        "    }\n"+
                        "\n"+
                        "    @Override\n"+
                        "    public boolean onCreate() {\n"+
                        "        return true;\n"+
                        "    }\n"+
                        "\n"+
                        "    @Override\n"+
                        "    public Cursor query(Uri uri, String[] projection, String selection,\n"+
                        "                        String[] selectionArgs, String sortOrder) {\n"+
                        "\n"+
                        "        MatrixCursor cursor = null;\n"+
                        "		ArrayList columnValues = new ArrayList();\n"+
                        "\n"+
                        "        switch (sUriMatcher.match(uri)){\n"+
                        "            case 1:\n"+
                        "				cursor = new MatrixCursor(new String[]{\"ID\",\"SSN\"});\n"+
                        "				columnValues.add(\"1\");\n"+
                        "				columnValues.add(\"11AA11\");\n"+
                        "				cursor.addRow(columnValues);\n"+
                        "        }\n"+
                        "        return cursor;\n"+
                        "    }\n"+
                        "\n"+
                        "    @Override\n"+
                        "    public int update(Uri uri, ContentValues values, String selection,\n"+
                        "                      String[] selectionArgs) {\n"+
                        "        return 0;\n"+
                        "    }\n"+
                        "}\n"+
                        "\n"))
                .run()
                .expectClean();
    }
}
