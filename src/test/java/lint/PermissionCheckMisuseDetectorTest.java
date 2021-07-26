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

public class PermissionCheckMisuseDetectorTest extends LintDetectorTest {

    public void testCheckPermissionWithBinderCalls() {
        lint().files(
                java("package com.example.test;\n"+
                        "import android.app.Service;\n"+
                        "import android.content.Intent;\n"+
                        "import android.os.Binder;\n"+
                        "import android.util.Log;\n"+
                        "import android.app.IntentService;\n"+
                        "import android.content.pm.PackageManager;\n"+
                        "\n"+
                        "public class MyService extends IntentService {\n"+
                        "    public MyService() {\n"+
                        "		super(\"MyService\");\n"+
                        "    }\n"+
                        "\n"+
                        "    @Override\n"+
                        "    protected void onHandleIntent(Intent intent){\n"+
                        "		if(checkPermission(\"santos.benign.permission\",Binder.getCallingPid(),Binder.getCallingUid())==PackageManager.PERMISSION_GRANTED)\n"+
                        "			Log.d(\"MyService\",\"Permission granted\");\n"+
                        "		else\n"+
                        "			Log.d(\"MyService\",\"Permission denied\");\n"+
                        "    }\n"+
                        "}\n"))
                .run()
                .expectCount(1, Severity.WARNING).expectMatches(PermissionCheckMisuseDetector.MESSAGE);
    }

    public void testCheckPermissionLocaleFieldsForBinderCalls() {
        lint().files(
                java("package com.example.test;\n"+
                        "import android.app.Service;\n"+
                        "import android.content.Intent;\n"+
                        "import android.os.Binder;\n"+
                        "import android.util.Log;\n"+
                        "import android.app.IntentService;\n"+
                        "import android.content.pm.PackageManager;\n"+
                        "\n"+
                        "public class MyService extends IntentService {\n"+
                        "    public MyService() {\n"+
                        "		super(\"MyService\");\n"+
                        "    }\n"+
                        "\n"+
                        "    @Override\n"+
                        "    protected void onHandleIntent(Intent intent){\n"+
                        "       int pid = Binder.getCallingPid();\n"+
                        "       int uid = Binder.getCallingUid();\n"+
                        "		if(checkPermission(\"santos.benign.permission\",pid,uid)==PackageManager.PERMISSION_GRANTED)\n"+
                        "			Log.d(\"MyService\",\"Permission granted\");\n"+
                        "		else\n"+
                        "			Log.d(\"MyService\",\"Permission denied\");\n"+
                        "    }\n"+
                        "}\n"))
                .run()
                .expectCount(1, Severity.WARNING).expectMatches(PermissionCheckMisuseDetector.MESSAGE);
    }

    public void testCheckUriPermissionLocaleFieldsForBinderCalls() {
        lint().files(
                java("package com.example.test;\n"+
                        "import android.app.Service;\n"+
                        "import android.content.Intent;\n"+
                        "import android.os.Binder;\n"+
                        "import android.util.Log;\n"+
                        "import android.app.IntentService;\n"+
                        "import android.content.pm.PackageManager;\n"+
                        "import android.net.Uri;\n"+
                        "\n"+
                        "public class MyService extends IntentService {\n"+
                        "    public MyService() {\n"+
                        "		super(\"MyService\");\n"+
                        "    }\n"+
                        "\n"+
                        "    @Override\n"+
                        "    protected void onHandleIntent(Intent intent){\n"+
                        "       int pid = Binder.getCallingPid();\n"+
                        "       int uid = Binder.getCallingUid();\n"+
                        "		if(checkUriPermission(Uri.parse(\"content://test.app.userdetails/user/secret\"),pid,uid,0)==PackageManager.PERMISSION_GRANTED)\n"+
                        "			Log.d(\"MyService\",\"Permission granted\");\n"+
                        "		else\n"+
                        "			Log.d(\"MyService\",\"Permission denied\");\n"+
                        "    }\n"+
                        "}\n"))
                .run()
                .expectCount(1, Severity.WARNING).expectMatches(PermissionCheckMisuseDetector.MESSAGE);
    }

    public void testCheckUriPermissionWithAdditionalPermissions() {
        lint().files(
                java("package com.example.test;\n"+
                        "import android.app.Service;\n"+
                        "import android.content.Intent;\n"+
                        "import android.os.Binder;\n"+
                        "import android.util.Log;\n"+
                        "import android.app.IntentService;\n"+
                        "import android.content.pm.PackageManager;\n"+
                        "import android.net.Uri;\n"+
                        "\n"+
                        "public class MyService extends IntentService {\n"+
                        "    public MyService() {\n"+
                        "		super(\"MyService\");\n"+
                        "    }\n"+
                        "\n"+
                        "    @Override\n"+
                        "    protected void onHandleIntent(Intent intent){\n"+
                        "       int pid = Binder.getCallingPid();\n"+
                        "       int uid = Binder.getCallingUid();\n"+
                        "		if(checkUriPermission(Uri.parse(\"content://test.app.userdetails/user/secret\"),\"santos.benign.readpermission\",\"santos.benign.writepermission\",pid,uid,0)==PackageManager.PERMISSION_GRANTED)\n"+
                        "			Log.d(\"MyService\",\"Permission granted\");\n"+
                        "		else\n"+
                        "			Log.d(\"MyService\",\"Permission denied\");\n"+
                        "    }\n"+
                        "}\n"))
                .run()
                .expectCount(1, Severity.WARNING).expectMatches(PermissionCheckMisuseDetector.MESSAGE);
    }


    @Override
    protected Detector getDetector() {
        return new PermissionCheckMisuseDetector();
    }

    @Override
    protected List<Issue> getIssues() {
        return Collections.singletonList(PermissionCheckMisuseDetector.ISSUE);
    }
}
