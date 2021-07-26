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

public class UnrevokedUriPermissionDetectorTest extends LintDetectorTest {

    public void testGrantedButNotRevoked() {
        lint().files(
                java("package com.example.test;\n"+
                        "\n"+
                        "import android.net.Uri;\n"+
                        "import android.content.Context;\n"+
                        "import android.content.Intent;\n"+
                        "import android.content.IntentFilter;\n"+
                        "import android.app.Activity;\n"+
                        "import android.os.Bundle;\n"+
                        "\n"+
                        "public class MainActivity extends Activity {\n"+
                        "\n"+
                        "    @Override\n"+
                        "    protected void onCreate(Bundle savedInstanceState) {\n"+
                        "        super.onCreate(savedInstanceState);\n"+
                        "        Uri uri = Uri.parse(\"content://test.this.app/something/1\");\n"+
                        "        grantUriPermission(\"some.other.app\", uri, Intent.FLAG_GRANT_READ_URI_PERMISSION);\n" +
                        "    }\n" +
                        "}\n"))
                .run()
                .expectCount(1, Severity.WARNING).expectMatches(UnrevokedUriPermissionDetector.MESSAGE);
    }

    public void testGrantedAndRevokedInOtherMethod() {
        lint().files(
                java("package com.example.test;\n"+
                        "\n"+
                        "import android.net.Uri;\n"+
                        "import android.content.Context;\n"+
                        "import android.content.Intent;\n"+
                        "import android.content.IntentFilter;\n"+
                        "import android.app.Activity;\n"+
                        "import android.os.Bundle;\n"+
                        "\n"+
                        "public class MainActivity extends Activity {\n"+
                        "\n"+
                        "    @Override\n"+
                        "    protected void onCreate(Bundle savedInstanceState) {\n"+
                        "        super.onCreate(savedInstanceState);\n"+
                        "        Uri uri = Uri.parse(\"content://test.this.app/something/1\");\n"+
                        "        grantUriPermission(\"some.other.app\", uri, Intent.FLAG_GRANT_READ_URI_PERMISSION);\n" +
                        "    }\n" +
                        "    protected void revokePermission() {\n"+
                        "        Uri uri = Uri.parse(\"content://test.this.app/something/1\");\n"+
                        "        revokeUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION);\n" +
                        "    }\n" +
                        "}\n"))
                .run()
                .expectCount(0);
    }

    public void testNeverGranted() {
        lint().files(
                java("package com.example.test;\n"+
                        "\n"+
                        "import android.net.Uri;\n"+
                        "import android.content.Context;\n"+
                        "import android.content.Intent;\n"+
                        "import android.content.IntentFilter;\n"+
                        "import android.app.Activity;\n"+
                        "import android.os.Bundle;\n"+
                        "\n"+
                        "public class MainActivity extends Activity {\n"+
                        "\n"+
                        "    @Override\n"+
                        "    protected void onCreate(Bundle savedInstanceState) {\n"+
                        "        super.onCreate(savedInstanceState);\n"+
                        "        Uri uri = Uri.parse(\"content://test.this.app/something/1\");\n"+
                        "    }\n" +
                        "}\n"))
                .run()
                .expectCount(0);
    }


    @Override
    protected Detector getDetector() {
        return new UnrevokedUriPermissionDetector();
    }

    @Override
    protected List<Issue> getIssues() {
        return Collections.singletonList(UnrevokedUriPermissionDetector.ISSUE);
    }
}
