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

public class StickyBroadcastDetectorTest extends LintDetectorTest {

    // Checks that the call signature registerReceiver(BroadcastReceiver receiver, IntentFilter filter)
    // raises a warning because it has no permission argument
    public void testSendStickyBroadcast() {
        lint().files(
                java("package com.example.test;\n"+
                        "\n"+
                        "import android.content.BroadcastReceiver;\n"+
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
                        "        sendStickyBroadcast(new Intent(\"abc\"));"+
                        "    }\n"+
                        "}\n"))
                .run()
                .expectCount(1, Severity.WARNING).expectMatches(StickyBroadcastDetector.STICKY_BROADCAST_USED);
    }


    @Override
    protected Detector getDetector() {
        return new StickyBroadcastDetector();
    }

    @Override
    protected List<Issue> getIssues() {
        return Collections.singletonList(StickyBroadcastDetector.ISSUE);
    }
}
