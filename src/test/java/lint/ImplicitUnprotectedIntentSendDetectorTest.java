/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Pascal Gadient et al. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for the license information.
 *--------------------------------------------------------------------------------------------*/

package lint;

import com.android.tools.lint.checks.infrastructure.LintDetectorTest;
import com.android.tools.lint.detector.api.Detector;
import com.android.tools.lint.detector.api.Issue;
import com.android.tools.lint.detector.api.Severity;

import java.util.Arrays;
import java.util.List;

public class ImplicitUnprotectedIntentSendDetectorTest extends LintDetectorTest {

    public void testSendEmptyIntentInCall() {
        lint().files(
                java("package com.example.test;\n"+
                        "\n"+
                        "import android.content.BroadcastReceiver;\n"+
                        "import android.content.Context;\n"+
                        "import android.content.Intent;\n"+
                        "import android.content.IntentFilter;\n"+
                        "import android.app.Activity;\n"+
                        "import android.os.Bundle;\n"+
                        "import android.app.PendingIntent;\n"+
                        "import android.content.Intent;\n"+
                        "\n"+
                        "public class MainActivity extends Activity {\n"+
                        "\n"+
                        "    @Override\n"+
                        "    protected void onCreate(Bundle savedInstanceState) {\n"+
                        "        sendBroadcast(new Intent());\n"+
                        "    }\n"+
                        "}\n"))
                .run()
                .expectCount(1, Severity.WARNING).expectMatches(ImplicitUnprotectedIntentSendDetector.IMPLICIT_INTENT_MESSAGE);
    }
    
    public void testStartActivity() {
        lint().files(
                java("package com.example.test;\n"+
                        "\n"+
                        "import android.content.BroadcastReceiver;\n"+
                        "import android.content.Context;\n"+
                        "import android.app.Activity;\n"+
                        "import android.content.Intent;\n"+
                        "import android.content.IntentFilter;\n"+
                        "import android.os.Bundle;\n" +
                        "\n"+
                        "public class TestService extends Activity  {\n"+
                        "\n"+
                        "    @Override\n"+
                        "    protected void onCreate(Bundle savedInstanceState) {\n"+
                        "        super.onCreate(savedInstanceState);\n"+
                        "        Intent i = new Intent(\"edu.mit.icc_concat_action_string.ACTION\");\n" +
                        "        i.putExtra(\"Sensitive Data\", \"1234\");\n" +
                        "        startActivity(i);\n" +
                        "    }\n    " +
                        "}\n"))
                .run()
                .expectCount(1, Severity.WARNING).expectMatches(ImplicitUnprotectedIntentSendDetector.IMPLICIT_INTENT_MESSAGE);
    }
    
    public void testStartActivityForResult() {
        lint().files(
                java("package com.example.test;\n"+
                        "\n"+
                        "import android.content.BroadcastReceiver;\n"+
                        "import android.content.Context;\n"+
                        "import android.app.Activity;\n"+
                        "import android.content.Intent;\n"+
                        "import android.content.IntentFilter;\n"+
                        "import android.os.Bundle;\n" +
                        "\n"+
                        "public class TestService extends Activity  {\n"+
                        "\n"+
                        "    @Override\n"+
                        "    protected void onCreate(Bundle savedInstanceState) {\n"+
                        "        super.onCreate(savedInstanceState);\n"+
                        "        Intent i = new Intent(\"edu.mit.icc_concat_action_string.ACTION\");\n" +
                        "        this.startActivityForResult(i, 1);\n" +
                        "    }\n    " +
                        "}\n"))
                .run()
                .expectCount(1, Severity.WARNING).expectMatches(ImplicitUnprotectedIntentSendDetector.IMPLICIT_INTENT_MESSAGE);
    }

    public void testSetResult() {
        lint().files(
                java("package com.example.test;\n"+
                        "\n"+
                        "import android.content.BroadcastReceiver;\n"+
                        "import android.content.Context;\n"+
                        "import android.app.Activity;\n"+
                        "import android.content.Intent;\n"+
                        "import android.content.IntentFilter;\n"+
                        "import android.os.Bundle;\n" +
                        "\n"+
                        "public class TestService extends Activity  {\n"+
                        "\n"+
                        "    @Override\n"+
                        "    protected void onCreate(Bundle savedInstanceState) {\n"+
                        "        super.onCreate(savedInstanceState);\n"+
                        "        Intent i = new Intent(\"edu.mit.icc_concat_action_string.ACTION\");\n" +
                        "        this.setResult(0, i);\n" +
                        "        finish();\n" +
                        "    }\n    " +
                        "}\n"))
                .run()
                .expectCount(1, Severity.WARNING).expectMatches(ImplicitUnprotectedIntentSendDetector.IMPLICIT_INTENT_MESSAGE);
    }

    public void testSendEmptyIntentInCallWithNullPermission() {
        lint().files(
                java("package com.example.test;\n"+
                        "\n"+
                        "import android.content.BroadcastReceiver;\n"+
                        "import android.content.Context;\n"+
                        "import android.content.Intent;\n"+
                        "import android.content.IntentFilter;\n"+
                        "import android.app.Activity;\n"+
                        "import android.os.Bundle;\n"+
                        "import android.app.PendingIntent;\n"+
                        "import android.content.Intent;\n"+
                        "\n"+
                        "public class MainActivity extends Activity {\n"+
                        "\n"+
                        "    @Override\n"+
                        "    protected void onCreate(Bundle savedInstanceState) {\n"+
                        "        sendBroadcast(new Intent(), null);\n"+
                        "    }\n"+
                        "}\n"))
                .run()
                .expectCount(1, Severity.WARNING).expectMatches(ImplicitUnprotectedIntentSendDetector.IMPLICIT_INTENT_MESSAGE);
    }

    public void testExplicitWithSetClassNameInService() {
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
                        "import android.os.Bundle;\n" +
                        "import java.io.File;\n"+
                        "import android.net.Uri;\n"+
                        "\n"+
                        "public class TestService extends Service  {\n"+
                        "\n"+
                        "    @Override\n"+
                        "    public void onCreate() {\n"+
                        "        super.onCreate();\n"+
                        "    }\n    " +
                        "   public static void compressTo(Context c, File compressTo) {\n" +
                        "        Intent i = new Intent(\"compress\");\n" +
                        "        i.setClassName(c, TestService.class.getName());\n" +
                        "        i.setData(Uri.fromFile(compressTo));\n" +
                        "        c.startService(i);\n" +
                        "    }" +
                        "   @Override\n" +
                        "    public IBinder onBind(Intent intent) {\n" +
                        "       return null;\n" +
                        "    }" +
                        "}\n"))
                .run()
                .expectCount(0);
    }

    public void testImplicitInService() {
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
                        "import android.os.Bundle;\n" +
                        "import java.io.File;\n"+
                        "import android.net.Uri;\n"+
                        "\n"+
                        "public class TestService extends Service  {\n"+
                        "\n"+
                        "    @Override\n"+
                        "    public void onCreate() {\n"+
                        "        super.onCreate();\n"+
                        "    }\n    " +
                        "   public static void compressTo(Context c, File compressTo) {\n" +
                        "        Intent i = new Intent(\"compress\");\n" +
                        "        i.setData(Uri.fromFile(compressTo));\n" +
                        "        c.startService(i);\n" +
                        "    }" +
                        "   @Override\n" +
                        "    public IBinder onBind(Intent intent) {\n" +
                        "       return null;\n" +
                        "    }" +
                        "}\n"))
                .run()
                .expectCount(0);
    }

    public void testSendEmptyIntentInCallWithPermission() {
        lint().files(
                java("package com.example.test;\n"+
                        "\n"+
                        "import android.content.BroadcastReceiver;\n"+
                        "import android.content.Context;\n"+
                        "import android.content.Intent;\n"+
                        "import android.content.IntentFilter;\n"+
                        "import android.app.Activity;\n"+
                        "import android.os.Bundle;\n"+
                        "import android.app.PendingIntent;\n"+
                        "import android.content.Intent;\n"+
                        "\n"+
                        "public class MainActivity extends Activity {\n"+
                        "\n"+
                        "    @Override\n"+
                        "    protected void onCreate(Bundle savedInstanceState) {\n"+
                        "        sendBroadcast(new Intent(), \"test.pkg.SECURE_PERMISSION\");\n"+
                        "    }\n"+
                        "}\n"))
                .run()
                .expectCount(0);
    }

    public void testSendExplicitIntentInCall() {
        lint().files(
                java("package com.example.test;\n"+
                        "\n"+
                        "import android.content.BroadcastReceiver;\n"+
                        "import android.content.Context;\n"+
                        "import android.content.Intent;\n"+
                        "import android.content.IntentFilter;\n"+
                        "import android.app.Activity;\n"+
                        "import android.os.Bundle;\n"+
                        "import android.app.PendingIntent;\n"+
                        "import android.content.Intent;\n"+
                        "\n"+
                        "public class MainActivity extends Activity {\n"+
                        "\n"+
                        "    @Override\n"+
                        "    protected void onCreate(Bundle savedInstanceState) {\n"+
                        "        sendBroadcast(new Intent(getApplicationContext(), MainActivity.class));\n"+
                        "    }\n"+
                        "}\n"))
                .run()
                .expectCount(0);
    }

    public void testSendExplicitIntentFromLocaleField() {
        lint().files(
                java("package com.example.test;\n"+
                        "\n"+
                        "import android.content.BroadcastReceiver;\n"+
                        "import android.content.Context;\n"+
                        "import android.content.Intent;\n"+
                        "import android.content.IntentFilter;\n"+
                        "import android.app.Activity;\n"+
                        "import android.os.Bundle;\n"+
                        "import android.app.PendingIntent;\n"+
                        "import android.content.Intent;\n"+
                        "\n"+
                        "public class MainActivity extends Activity {\n"+
                        "\n"+
                        "    @Override\n"+
                        "    protected void onCreate(Bundle savedInstanceState) {\n"+
                        "        Intent i = new Intent(getApplicationContext(), MainActivity.class);\n"+
                        "        sendBroadcast(i);\n"+
                        "    }\n"+
                        "}\n"))
                .run()
                .expectCount(0);
    }

    public void testSendExplicitIntentFromLocaleFieldKotlin() {
        lint().files(
                kotlin("package com.example.test;\n"+
                        "import android.app.Activity\n" +
                        "import android.content.Intent\n" +
                        "import android.os.Bundle\n" +
                        "import android.app.PendingIntent;\n"+
                        "\n" +
                        "class MainActivity : Activity() {\n" +
                        "\n" +
                        "    override fun onCreate(savedInstanceState: Bundle?) {\n" +
                        "        super.onCreate(savedInstanceState)\n" +
                        "            val pauseIntent = Intent(ACTION_PAUSE)\n" +
                        "            pauseIntent.setClass(this, Activity::class.java)\n" +
                        "            val pendingPauseIntent = PendingIntent.getService(\n" +
                        "                    this,\n" +
                        "                    0,\n" +
                        "                    pauseIntent,\n" +
                        "                    0)" +
                        "    }\n"+
                        "}"))
                .run()
                .expectCount(0);
    }

    public void testSendExplicitIntentKotlin() {
        lint().files(
                kotlin("package com.example.test;\n"+
                        "import android.app.Activity\n" +
                        "import android.content.Intent\n" +
                        "import android.os.Bundle\n" +
                        "import android.app.PendingIntent;\n"+
                        "\n" +
                        "class MainActivity : Activity() {\n" +
                        "\n" +
                        "    override fun onCreate(savedInstanceState: Bundle?) {\n" +
                        "        super.onCreate(savedInstanceState)\n" +
                        "            val pendingPauseIntent = PendingIntent.getService(\n" +
                        "                    this,\n" +
                        "                    0,\n" +
                        "                    Intent(this, Activity::class.java),\n" +
                        "                    0)" +
                        "    }\n"+
                        "}"))
                .run()
                .expectCount(0);
    }

    public void testSendIntentMadeExplicitWithSetClassName() {
        lint().files(
                java("package com.example.test;\n"+
                        "\n"+
                        "import android.content.BroadcastReceiver;\n"+
                        "import android.content.Context;\n"+
                        "import android.content.Intent;\n"+
                        "import android.content.IntentFilter;\n"+
                        "import android.app.Activity;\n"+
                        "import android.os.Bundle;\n"+
                        "import android.app.PendingIntent;\n"+
                        "import android.content.Intent;\n"+
                        "\n"+
                        "public class MainActivity extends Activity {\n"+
                        "\n"+
                        "    @Override\n"+
                        "    protected void onCreate(Bundle savedInstanceState) {\n"+
                        "        Intent i = new Intent(\"test.pkg.ACTION\");\n"+
                        "        i.setClassName(\"test.pkg\",\"Receiver\");\n"+
                        "        sendBroadcast(i);\n"+
                        "    }\n"+
                        "}\n"))
                .run()
                .expectCount(0);
    }

    public void testSendIntentMadeExplicitWithSetClass() {
        lint().files(
                java("package com.example.test;\n"+
                        "\n"+
                        "import android.content.BroadcastReceiver;\n"+
                        "import android.content.Context;\n"+
                        "import android.content.Intent;\n"+
                        "import android.content.IntentFilter;\n"+
                        "import android.app.Activity;\n"+
                        "import android.os.Bundle;\n"+
                        "import android.app.PendingIntent;\n"+
                        "import android.content.Intent;\n"+
                        "\n"+
                        "public class MainActivity extends Activity {\n"+
                        "\n"+
                        "    @Override\n"+
                        "    protected void onCreate(Bundle savedInstanceState) {\n"+
                        "        Intent i = new Intent(\"test.pkg.ACTION\");\n"+
                        "        i.setClass(getApplicationContext(),this.getClass());\n"+
                        "        startActivity(i);\n"+
                        "    }\n"+
                        "}\n"))
                .run()
                .expectCount(0);
    }

    public void testSendIntentMadeExplicitWithSetClassNameChained() {
        lint().files(
                java("package com.example.test;\n"+
                        "\n"+
                        "import android.content.BroadcastReceiver;\n"+
                        "import android.content.Context;\n"+
                        "import android.content.Intent;\n"+
                        "import android.content.IntentFilter;\n"+
                        "import android.app.Activity;\n"+
                        "import android.os.Bundle;\n"+
                        "import android.app.PendingIntent;\n"+
                        "import android.content.Intent;\n"+
                        "\n"+
                        "public class MainActivity extends Activity {\n"+
                        "\n"+
                        "    @Override\n"+
                        "    protected void onCreate(Bundle savedInstanceState) {\n"+
                        "        Intent i = new Intent();\n"+
                        "        i.setAction(\"test.pkg.ACTION\").setClassName(\"test.pkg\",\"Receiver\");\n"+
                        "        sendBroadcast(i);\n"+
                        "    }\n"+
                        "}\n"))
                .run()
                .expectCount(0);
    }

    public void testSendImplicitIntentWithUri() {
        lint().files(
                java("package com.example.test;\n"+
                        "\n"+
                        "import android.content.BroadcastReceiver;\n"+
                        "import android.content.Context;\n"+
                        "import android.content.Intent;\n"+
                        "import android.content.IntentFilter;\n"+
                        "import android.app.Activity;\n"+
                        "import android.os.Bundle;\n"+
                        "import android.app.PendingIntent;\n"+
                        "import android.content.Intent;\n"+
                        "import android.net.Uri;\n"+
                        "\n"+
                        "public class MainActivity extends Activity {\n"+
                        "\n"+
                        "    @Override\n"+
                        "    protected void onCreate(Bundle savedInstanceState) {\n"+
                        "        Intent i = new Intent(Intent.ACTION_VIEW, Uri.parse(\"https://developer.android.com/reference/android/net/Uri.html\"));\n"+
                        "        sendBroadcast(i);\n"+
                        "    }\n"+
                        "}\n"))
                .run()
                .expectCount(1, Severity.WARNING).expectMatches(ImplicitUnprotectedIntentSendDetector.IMPLICIT_INTENT_MESSAGE);
    }

    public void testSendIntentExplicitWithNoImmediateClass() {
        lint().files(
                java("package com.example.test;\n"+
                        "\n"+
                        "import android.content.BroadcastReceiver;\n"+
                        "import android.content.Context;\n"+
                        "import android.content.Intent;\n"+
                        "import android.content.IntentFilter;\n"+
                        "import android.app.Activity;\n"+
                        "import android.os.Bundle;\n"+
                        "import android.app.PendingIntent;\n"+
                        "import android.content.Intent;\n"+
                        "\n"+
                        "public class MainActivity extends Activity {\n"+
                        "    protected void sendIntentToClass(Context packageContext, Class<?> cls) {" +
                        "        Intent i = new Intent(packageContext, cls);" +
                        "        sendBroadcast(i);\n"+
                        "    }\n"+
                        "}\n"))
                .run()
                .expectCount(0);
    }

    public void testCreateImplicitPendingIntent() {
        lint().files(
                java("package com.example.test;\n"+
                        "\n"+
                        "import android.content.BroadcastReceiver;\n"+
                        "import android.content.Context;\n"+
                        "import android.content.Intent;\n"+
                        "import android.content.IntentFilter;\n"+
                        "import android.app.Activity;\n"+
                        "import android.os.Bundle;\n"+
                        "import android.app.PendingIntent;\n"+
                        "import android.content.Intent;\n"+
                        "\n"+
                        "public class MainActivity extends Activity {\n"+
                        "\n"+
                        "    @Override\n"+
                        "    protected void onCreate(Bundle savedInstanceState) {\n"+
                        "        Intent i = new Intent(\"test.pkg.ACTION\");\n"+
                        "        PendingIntent pi = PendingIntent.getService(getApplicationContext(),0, i,PendingIntent.FLAG_UPDATE_CURRENT);\n"+
                        "    }\n"+
                        "}\n"))
                .run()
                .expectCount(1, Severity.WARNING).expectMatches(ImplicitUnprotectedIntentSendDetector.IMPLICIT_PENDING_INTENT_MESSAGE);
    }

    public void testCreateExplicitPendingIntent() {
        lint().files(
                java("package com.example.test;\n"+
                        "\n"+
                        "import android.content.BroadcastReceiver;\n"+
                        "import android.content.Context;\n"+
                        "import android.content.Intent;\n"+
                        "import android.content.IntentFilter;\n"+
                        "import android.app.Activity;\n"+
                        "import android.os.Bundle;\n"+
                        "import android.app.PendingIntent;\n"+
                        "import android.content.Intent;\n"+
                        "\n"+
                        "public class MainActivity extends Activity {\n"+
                        "\n"+
                        "    @Override\n"+
                        "    protected void onCreate(Bundle savedInstanceState) {\n"+
                        "        Intent i = new Intent(\"test.pkg.ACTION\");\n"+
                        "        i.setClassName(\"test.pkg\",\"Receiver\");\n"+
                        "        PendingIntent pi = PendingIntent.getService(getApplicationContext(),0, i,PendingIntent.FLAG_UPDATE_CURRENT);\n"+
                        "    }\n"+
                        "}\n"))
                .run()
                .expectCount(0);
    }


    @Override
    protected Detector getDetector() {
        return new ImplicitUnprotectedIntentSendDetector();
    }

    @Override
    protected List<Issue> getIssues() {
        return Arrays.asList(ImplicitUnprotectedIntentSendDetector.IMPLICIT_INTENT_SENDED_UNPROTECTED,
                ImplicitUnprotectedIntentSendDetector.IMPLICIT_PENDING_INTENT);
    }
}
