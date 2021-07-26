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

public class ProceedOnSslErrorDetectorTest extends LintDetectorTest {
    public void testAlwaysProceed() {
        lint().files(
                java("" +
                        "package test.pkg;\n" +
                        "import android.webkit.WebResourceRequest;\n"+
                        "import android.webkit.WebView;\n"+
                        "import android.webkit.WebViewClient;\n"+
                        "import android.net.http.SslError;\n"+
                        "import android.webkit.SslErrorHandler;\n"+
                        "public class TestClass1 extends WebViewClient{\n" +
                        "    @Override\n"+
                        "    public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {\n"+
                        "        return false;\n"+
                        "   }\n"+
                        "\n"+
                        "   @Override\n"+
                        "   public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error){\n"+
                        "       handler.proceed();\n"+
                        "   }\n"+
                        "}"))
                .run()
                .expectCount(1, Severity.WARNING).expectMatches(WebViewClientMethodMisuseDetector.OnReceivedSslErrorVisitor.MESSAGE);
    }

    public void testAlwaysProceedAndLog() {
        lint().files(
                java("" +
                        "package test.pkg;\n" +
                        "import android.webkit.WebResourceRequest;\n"+
                        "import android.webkit.WebView;\n"+
                        "import android.webkit.WebViewClient;\n"+
                        "import android.net.http.SslError;\n"+
                        "import android.webkit.SslErrorHandler;\n"+
                        "public class TestClass1 extends WebViewClient{\n" +
                        "   @Override\n"+
                        "   public void onReceivedSslError(WebView view , SslErrorHandler handler, SslError error){\n"+
                        "       System.out.println(\"I don't care\");\n" +
                        "       handler.proceed();\n"+
                        "   }\n"+
                        "}"))
                .run()
                .expectCount(1, Severity.WARNING).expectMatches(WebViewClientMethodMisuseDetector.OnReceivedSslErrorVisitor.MESSAGE);
    }

    // the default implementation of webviewclient call handler.cancel onReceivedSslError
    // so calling the super method in some path should be fine because it is the same as calling handler.cancel
    public void testCallSuperShouldCountAsCancel() {
        lint().files(
                java("" +
                        "package test.pkg;\n" +
                        "import android.webkit.WebResourceRequest;\n"+
                        "import android.webkit.WebView;\n"+
                        "import android.webkit.WebViewClient;\n"+
                        "import android.net.http.SslError;\n"+
                        "import android.webkit.SslErrorHandler;\n"+
                        "import static android.net.http.SslError.SSL_NOTYETVALID;\n"+
                        "public class TestClass1 extends WebViewClient{\n" +
                        "   @Override\n"+
                        "   public void onReceivedSslError(WebView view , SslErrorHandler handler, SslError error){\n"+
                        "        if(error.getPrimaryError() == SSL_NOTYETVALID){\n"+
                        "           handler.proceed();" +
                        "        } else {\n" +
                        "            super.onReceivedSslError(view, handler, error);\n" +
                        "        }\n"+
                        "   }\n"+
                        "}"))
                .run()
                .expectCount(0);
    }




    public void testNeverProceed() {
        lint().files(
                java("" +
                        "package test.pkg;\n" +
                        "import android.webkit.WebResourceRequest;\n"+
                        "import android.webkit.WebView;\n"+
                        "import android.webkit.WebViewClient;\n"+
                        "import android.net.http.SslError;\n"+
                        "import android.webkit.SslErrorHandler;\n"+
                        "public class TestClass1 extends WebViewClient{\n" +
                        "   @Override\n"+
                        "   public void onReceivedSslError(WebView view , SslErrorHandler handler, SslError error){\n"+
                        "       handler.cancel();\n"+
                        "   }\n"+
                        "}"))
                .run()
                .expectCount(0);
    }

    // Solution from
    // https://stackoverflow.com/questions/36050741/webview-avoid-security-alert-from-google-play-upon-implementation-of-onreceived
    // (altered)
    public void testDecideInMethod() {
        lint().files(
                java("" +
                        "package test.pkg;\n" +
                        "import android.webkit.WebResourceRequest;\n"+
                        "import android.webkit.WebView;\n"+
                        "import android.webkit.WebViewClient;\n"+
                        "import android.net.http.SslError;\n"+
                        "import android.webkit.SslErrorHandler;\n"+
                        "import android.app.AlertDialog;\n"+
                        "import android.content.DialogInterface;\n"+
                        "public class TestClass1 extends WebViewClient{\n" +
                        "    @Override\n"+
                        "    public void onReceivedSslError(WebView view , final SslErrorHandler handler, SslError error){\n"+
                        "        final AlertDialog.Builder builder = new AlertDialog.Builder(view.getContext());\n"+
                        "        builder.setMessage(\"Invalid Certificate\");\n"+
                        "        builder.setPositiveButton(\"continue\", new DialogInterface.OnClickListener() {\n"+
                        "            @Override\n"+
                        "            public void onClick(DialogInterface dialog, int which) {\n"+
                        "                handler.proceed();\n"+
                        "            }\n"+
                        "        });\n"+
                        "        builder.setNegativeButton(\"cancel\", new DialogInterface.OnClickListener() {\n"+
                        "            @Override\n"+
                        "            public void onClick(DialogInterface dialog, int which) {\n"+
                        "                handler.cancel();\n"+
                        "            }\n"+
                        "        });\n"+
                        "        final AlertDialog dialog = builder.create();\n"+
                        "        dialog.show();\n"+
                        "    }\n"+
                        "}"))
                .run()
                .expectCount(0);
    }

    public void testDecideInMethodSimple() {
        lint().files(
                java("" +
                        "package test.pkg;\n" +
                        "import android.webkit.WebResourceRequest;\n"+
                        "import android.webkit.WebView;\n"+
                        "import android.webkit.WebViewClient;\n"+
                        "import android.net.http.SslError;\n"+
                        "import android.webkit.SslErrorHandler;\n"+
                        "import android.app.AlertDialog;\n"+
                        "import android.content.DialogInterface;\n"+
                        "import static android.net.http.SslError.SSL_NOTYETVALID;\n"+
                        "public class TestClass1 extends WebViewClient{\n" +
                        "    @Override\n"+
                        "    public void onReceivedSslError(WebView view , final SslErrorHandler handler, SslError error){\n"+
                        "        if(error.getPrimaryError() == SSL_NOTYETVALID){\n"+
                        "            handler.proceed();\n"+
                        "        }\n"+
                        "        else {\n"+
                        "            handler.cancel();\n"+
                        "        }\n"+
                        "    }\n"+
                        "}"))
                .run()
                .expectCount(0);
    }

    // Solution from https://stackoverflow.com/questions/36050741/webview-avoid-security-alert-from-google-play-upon-implementation-of-onreceiveds
    public void testDecideOutsideMethod() {
        lint().files(
                java("" +
                        "package test.pkg;\n" +
                        "import android.webkit.WebResourceRequest;\n"+
                        "import android.webkit.WebView;\n"+
                        "import android.webkit.WebViewClient;\n"+
                        "import android.net.http.SslError;\n"+
                        "import android.webkit.SslErrorHandler;\n"+
                        "import android.app.AlertDialog;\n"+
                        "import android.content.DialogInterface;\n"+
                        "public class TestClass1 extends WebViewClient{\n" +
                        "    @Override\n"+
                        "    public void onReceivedSslError(WebView view , final SslErrorHandler handler, SslError error){\n"+
                        "        handle(view, handler, error);\n"+
                        "    }\n"+
                        "    private void handle(WebView view , final SslErrorHandler handler, SslError error){\n"+
                        "        final AlertDialog.Builder builder = new AlertDialog.Builder(view.getContext());\n"+
                        "        builder.setMessage(\"Invalid Certificate\");\n"+
                        "        builder.setPositiveButton(\"continue\", new DialogInterface.OnClickListener() {\n"+
                        "            @Override\n"+
                        "            public void onClick(DialogInterface dialog, int which) {\n"+
                        "                handler.proceed();\n"+
                        "            }\n"+
                        "        });\n"+
                        "        builder.setNegativeButton(\"cancel\", new DialogInterface.OnClickListener() {\n"+
                        "            @Override\n"+
                        "            public void onClick(DialogInterface dialog, int which) {\n"+
                        "                handler.cancel();\n"+
                        "            }\n"+
                        "        });\n"+
                        "        final AlertDialog dialog = builder.create();\n"+
                        "        dialog.show();\n"+
                        "    }\n"+
                        "}"))
                .run()
                .expectCount(0);
    }

    public void testDecideInAndOutsideMethod() {
        lint().files(
                java("" +
                        "package test.pkg;\n" +
                        "import android.webkit.WebResourceRequest;\n"+
                        "import android.webkit.WebView;\n"+
                        "import android.webkit.WebViewClient;\n"+
                        "import android.net.http.SslError;\n"+
                        "import android.webkit.SslErrorHandler;\n"+
                        "import android.app.AlertDialog;\n"+
                        "import android.content.DialogInterface;\n"+
                        "import static android.net.http.SslError.SSL_NOTYETVALID;\n"+
                        "public class TestClass1 extends WebViewClient{\n" +
                        "    @Override\n"+
                        "    public void onReceivedSslError(WebView view , final SslErrorHandler handler, SslError error){\n"+
                        "        if(error.getPrimaryError() == SSL_NOTYETVALID)\n"+
                        "            handler.proceed();\n"+
                        "        else\n"+
                        "           handle(view, handler, error);\n"+
                        "    }\n"+
                        "    private void handle(WebView view , final SslErrorHandler handler, SslError error){\n"+
                        "        final AlertDialog.Builder builder = new AlertDialog.Builder(view.getContext());\n"+
                        "        builder.setMessage(\"Invalid Certificate\");\n"+
                        "        builder.setPositiveButton(\"continue\", new DialogInterface.OnClickListener() {\n"+
                        "            @Override\n"+
                        "            public void onClick(DialogInterface dialog, int which) {\n"+
                        "                handler.proceed();\n"+
                        "            }\n"+
                        "        });\n"+
                        "        builder.setNegativeButton(\"cancel\", new DialogInterface.OnClickListener() {\n"+
                        "            @Override\n"+
                        "            public void onClick(DialogInterface dialog, int which) {\n"+
                        "                handler.cancel();\n"+
                        "            }\n"+
                        "        });\n"+
                        "        final AlertDialog dialog = builder.create();\n"+
                        "        dialog.show();\n"+
                        "    }\n"+
                        "}"))
                .run()
                .expectCount(0);
    }


    @Override
    protected Detector getDetector() {
        return new WebViewClientMethodMisuseDetector();
    }

    @Override
    protected List<Issue> getIssues() {
        return Collections.singletonList(WebViewClientMethodMisuseDetector.PROCEED_ON_SSL_ERROR);
    }
}
