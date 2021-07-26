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

public class UnsafeDynamicBroadcastReceiverDetectorTest extends LintDetectorTest {

    // Checks that the call signature registerReceiver(BroadcastReceiver receiver, IntentFilter filter)
    // raises a warning because it has no permission argument
    public void testRegisterReceiver2Arguments() {
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
                        "\n"+
                        "        BroadcastReceiver br = new BroadcastReceiver() {\n"+
                        "            @Override\n"+
                        "            public void onReceive(Context context, Intent intent) {\n"+
                        "                //do nothing\n"+
                        "            }\n"+
                        "        };\n"+
                        "        IntentFilter filter = new IntentFilter(\"com.example.test.SOME_ACTION\");\n"+
                        "        registerReceiver(br, filter);\n"+
                        "    }\n"+
                        "}\n"))
                .run()
                .expectCount(1, Severity.WARNING).expectMatches(UnsafeDynamicBroadcastReceiverDetector.NO_PERMISSION_ARGUMENT_MESSAGE);
    }

    public void testRegisterReceiver2ArgumentsInService() {
        lint().files(
                java("package com.example.test;\n"+
                        "\n"+
                        "import android.content.BroadcastReceiver;\n"+
                        "import android.content.Context;\n"+
                        "import android.content.Intent;\n"+
                        "import android.content.IntentFilter;\n"+
                        "import android.app.Service;\n" +
                        "import android.os.IBinder;\n" +
                        "import android.location.Location;\n" +
                        "import android.location.LocationListener;\n" +
                        "import android.location.LocationManager;\n"+
                        "import android.os.Bundle;\n"+
                        "\n"+
                        "public class TestService extends Service implements LocationListener {\n"+
                        "\n"+
                        "    @Override\n"+
                        "    public void onCreate() {\n"+
                        "\n"+
                        "        BroadcastReceiver br = new BroadcastReceiver() {\n"+
                        "            @Override\n"+
                        "            public void onReceive(Context context, Intent intent) {\n"+
                        "                //do nothing\n"+
                        "            }\n"+
                        "        };\n"+
                        "        IntentFilter filter = new IntentFilter(\"com.example.test.SOME_ACTION\");\n"+
                        "        registerReceiver(br, filter);\n" +
                        "        super.onCreate();\n"+
                        "    }\n" +
                        "   @Override\n" +
                        "    public IBinder onBind(Intent intent) {\n" +
                        "       return null;\n" +
                        "    }" +
                        "    @Override\n" +
                        "    public void onLocationChanged(Location location) {        \n" +
                        "    }\n" +
                        "    \n" +
                        "    @Override\n" +
                        "    public void onProviderDisabled(String provider) {\n" +
                        "    }\n" +
                        "    @Override\n" +
                        "    public void onProviderEnabled(String provider) {\n" +
                        "    }\n" +
                        "    @Override\n" +
                        "    public void onStatusChanged(String provider, int status, Bundle extras) {\n" +
                        "    }"+
                        "}\n"))
                .run()
                .expectCount(1, Severity.WARNING).expectMatches(UnsafeDynamicBroadcastReceiverDetector.NO_PERMISSION_ARGUMENT_MESSAGE);
    }

    public void testRegisterNullReceiver2Arguments() {
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
                        "\n"+
                        "        IntentFilter filter = new IntentFilter(\"com.example.test.SOME_ACTION\");\n"+
                        "        registerReceiver(null, filter);\n"+
                        "    }\n"+
                        "}\n"))
                .run()
                .expectCount(0);
    }

    // Checks that the call signature registerReceiver(BroadcastReceiver receiver, IntentFilter filter, int flags)
    // raises a warning because it has no permission argument
    public void testRegisterReceiver3Arguments() {
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
                        "\n"+
                        "        BroadcastReceiver br = new BroadcastReceiver() {\n"+
                        "            @Override\n"+
                        "            public void onReceive(Context context, Intent intent) {\n"+
                        "                //do nothing\n"+
                        "            }\n"+
                        "        };\n"+
                        "        IntentFilter filter = new IntentFilter(\"com.example.test.SOME_ACTION\");\n"+
                        "        registerReceiver(br, filter, 0);\n"+
                        "    }\n"+
                        "}\n"))
                .run()
                .expectCount(1, Severity.WARNING).expectMatches(UnsafeDynamicBroadcastReceiverDetector.NO_PERMISSION_ARGUMENT_MESSAGE);
    }

    // Checks that the call signature
    // registerReceiver(BroadcastReceiver receiver, IntentFilter filter, String broadcastPermission, Handler scheduler)
    // raises a warning if the broadcast permission is null
    public void testRegisterReceiver4ArgumentsNullPermission() {
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
                        "\n"+
                        "        BroadcastReceiver br = new BroadcastReceiver() {\n"+
                        "            @Override\n"+
                        "            public void onReceive(Context context, Intent intent) {\n"+
                        "                //do nothing\n"+
                        "            }\n"+
                        "        };\n"+
                        "        IntentFilter filter = new IntentFilter(\"com.example.test.SOME_ACTION\");\n"+
                        "        registerReceiver(br, filter, null, null);\n"+
                        "    }\n"+
                        "}\n"))
                .run()
                .expectCount(1, Severity.WARNING).expectMatches(UnsafeDynamicBroadcastReceiverDetector.EMPTY_PERMISSION_ARGUMENT_MESSAGE);
    }

    // Checks that the call signature
    // registerReceiver(BroadcastReceiver receiver, IntentFilter filter, String broadcastPermission, Handler scheduler, int flags)
    // raises a warning if the broadcast permission is null
    public void testRegisterReceiver5ArgumentsNullPermission() {
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
                        "\n"+
                        "        BroadcastReceiver br = new BroadcastReceiver() {\n"+
                        "            @Override\n"+
                        "            public void onReceive(Context context, Intent intent) {\n"+
                        "                //do nothing\n"+
                        "            }\n"+
                        "        };\n"+
                        "        IntentFilter filter = new IntentFilter(\"com.example.test.SOME_ACTION\");\n"+
                        "        registerReceiver(br, filter, null, null, 0);\n"+
                        "    }\n"+
                        "}\n"))
                .run()
                .expectCount(1, Severity.WARNING).expectMatches(UnsafeDynamicBroadcastReceiverDetector.EMPTY_PERMISSION_ARGUMENT_MESSAGE);
    }

    // Checks that the call signature
    // registerReceiver(BroadcastReceiver receiver, IntentFilter filter, String broadcastPermission, Handler scheduler)
    // raises no warning if the broadcast permission is set
    public void testRegisterReceiver4ArgumentsPermissionSet() {
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
                        "\n"+
                        "        BroadcastReceiver br = new BroadcastReceiver() {\n"+
                        "            @Override\n"+
                        "            public void onReceive(Context context, Intent intent) {\n"+
                        "                //do nothing\n"+
                        "            }\n"+
                        "        };\n"+
                        "        IntentFilter filter = new IntentFilter(\"com.example.test.SOME_ACTION\");\n"+
                        "        registerReceiver(br, filter, \"com.example.test.SECURE_PERMISSION\", null);\n"+
                        "    }\n"+
                        "}\n"))
                .run()
                .expectCount(0);
    }

    // Checks that the call signature
    // registerReceiver(BroadcastReceiver receiver, IntentFilter filter, String broadcastPermission, Handler scheduler, int flags)
    // raises no warning if the broadcast permission is set
    public void testRegisterReceiver5ArgumentsPermissionSet() {
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
                        "\n"+
                        "        BroadcastReceiver br = new BroadcastReceiver() {\n"+
                        "            @Override\n"+
                        "            public void onReceive(Context context, Intent intent) {\n"+
                        "                //do nothing\n"+
                        "            }\n"+
                        "        };\n"+
                        "        IntentFilter filter = new IntentFilter(\"com.example.test.SOME_ACTION\");\n"+
                        "        registerReceiver(br, filter, \"com.example.test.SECURE_PERMISSION\", null, 0);\n"+
                        "    }\n"+
                        "}\n"))
                .run()
                .expectCount(0);
    }

    @Override
    protected Detector getDetector() {
        return new UnsafeDynamicBroadcastReceiverDetector();
    }

    @Override
    protected List<Issue> getIssues() {
        return Collections.singletonList(UnsafeDynamicBroadcastReceiverDetector.ISSUE);
    }
}
