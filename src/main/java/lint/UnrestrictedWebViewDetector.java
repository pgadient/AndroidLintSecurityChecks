/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Pascal Gadient et al. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for the license information.
 *--------------------------------------------------------------------------------------------*/

package lint;


import com.android.annotations.NonNull;
import com.android.annotations.VisibleForTesting;
import com.android.tools.lint.client.api.JavaEvaluator;
import com.android.tools.lint.detector.api.Category;
import com.android.tools.lint.detector.api.Detector;
import com.android.tools.lint.detector.api.Implementation;
import com.android.tools.lint.detector.api.Issue;
import com.android.tools.lint.detector.api.JavaContext;
import com.android.tools.lint.detector.api.Scope;
import com.android.tools.lint.detector.api.Severity;
import com.intellij.psi.PsiClass;
import com.intellij.psi.PsiMethod;
import com.intellij.psi.PsiType;
import com.intellij.psi.impl.source.PsiClassReferenceType;
import com.intellij.psi.impl.source.PsiImmediateClassType;

import org.jetbrains.uast.UCallExpression;
import org.jetbrains.uast.UExpression;

import java.util.Collections;
import java.util.List;

/**
 * Searches for WebViews that can access any url
 * By default, a WebView does open clicked links in the browser
 * However, if you set a WebViewClient the default behaviour changes to
 * open all pages within the WebView. The recommended way to overcome this is
 * to override the shouldOverrideUrlLoading
 * This looks for setWebViewClient(WebViewClient client) calls where the client
 * class does not override the shouldOverrideUrlLoading method
 * Note that his does not actually check if the shouldOverrideUrlLoading is overwritten
 * in a meaningful way. This check is done by the WebViewClientMisuseDetector
 * 
 * @author Patrick Frischknecht
 * 
 * University of Bern
 * Software Composition Group
 * 
 */
public class UnrestrictedWebViewDetector extends Detector implements Detector.UastScanner {
    private static final String CLASS_WEB_VIEW = "android.webkit.WebView";
    private static final String SHOULD_OVERRIDE_URL_LOADING = "shouldOverrideUrlLoading";
    private static final String CLASS_WEB_VIEW_CLIENT = "android.webkit.WebViewClient";
    @VisibleForTesting
    public static final String MESSAGE = "The configured WebViewClient will open any page within your WebView " +
            "and thus leave your app vulnerable to a wide range of attacks";

    public static final Issue ISSUE = Issue.create("SlackWebViewClient",
            "SM06: Slack WebViewClient | The default WebViewClient does not perform any restrictions on web pages",
            
            "By default a new WebViewClient loads any clicked link in the users default browser." +
            " However, if the WebViewClient of a WebView is set to a new instance" +
            " that does not override shouldOverrideUrlLoading, every link will open" +
            " within the WebView, so the user is able to access any unauthorised content." +
            " This enables a wide range of attacks, including phishing and cross site scripting." +
            " shouldOverrideUrlLoading should be overridden and a white-list maintained that limits the accessible pages." +
            " Safe browsing should be turned on" +
            " to further protect users (see the web links below).",
            Category.SECURITY,
            6,
            Severity.WARNING,
            new Implementation(
                    UnrestrictedWebViewDetector.class,
                    Scope.JAVA_FILE_SCOPE))
            .addMoreInfo("https://labs.mwrinfosecurity.com/blog/adventures-with-android-webviews/")
            .addMoreInfo("https://developer.android.com/guide/webapps/managing-webview.html#safe-browsing");


    @Override
    public void visitMethod(@NonNull JavaContext context, @NonNull UCallExpression call,
                            @NonNull PsiMethod method) {
        JavaEvaluator evaluator = context.getEvaluator();
        if (!evaluator.isMemberInSubClassOf(method, CLASS_WEB_VIEW, false))
            return;
        List<UExpression> argumentValueList = call.getValueArguments();
        if (argumentValueList.size() != 1)
            return;

        if (isUnrestrictedWebViewClient(argumentValueList.get(0)))
            context.report(ISSUE, call, context.getLocation(call), MESSAGE);
    }

    private boolean isUnrestrictedWebViewClient(UExpression webViewClientArgument) {
        PsiType webViewClientType = webViewClientArgument.getExpressionType();
        PsiClass  webViewClientClass = null;
        // find class referenced by arguments like: "new WebViewClient()" or "new WebViewClient"
        if (webViewClientType instanceof PsiClassReferenceType) {
            webViewClientClass = ((PsiClassReferenceType) webViewClientType).resolve();
        }
        // find anonymous class references, like:
        // new WebViewClient(){*Implementation*}
        if (webViewClientType instanceof PsiImmediateClassType) {
            webViewClientClass = ((PsiImmediateClassType) webViewClientType).resolve();
        }
        if(webViewClientClass == null)
            return false;
        // the default web view client class does allow to load any url
        if (CLASS_WEB_VIEW_CLIENT.equals(webViewClientClass.getQualifiedName()))
            return true;
        // a web view client that does not override "shouldOverrideUrlLoading" allows to load any url
        else if (webViewClientClass.findMethodsByName(SHOULD_OVERRIDE_URL_LOADING, false).length == 0)
            return true;
        return false;
    }

    @Override
    public List<String> getApplicableMethodNames() {
        return Collections.singletonList("setWebViewClient");
    }
}
