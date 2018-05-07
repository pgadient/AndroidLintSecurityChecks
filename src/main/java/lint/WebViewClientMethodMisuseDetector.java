package lint;


import com.android.annotations.NonNull;
import com.android.annotations.VisibleForTesting;
import com.android.tools.lint.detector.api.Category;
import com.android.tools.lint.detector.api.Detector;
import com.android.tools.lint.detector.api.Implementation;
import com.android.tools.lint.detector.api.Issue;
import com.android.tools.lint.detector.api.JavaContext;
import com.android.tools.lint.detector.api.Scope;
import com.android.tools.lint.detector.api.Severity;
import com.intellij.psi.PsiMethod;
import com.intellij.psi.PsiType;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.uast.UCallExpression;
import org.jetbrains.uast.UClass;
import org.jetbrains.uast.UElement;
import org.jetbrains.uast.UExpression;
import org.jetbrains.uast.UMethod;
import org.jetbrains.uast.UReturnExpression;
import org.jetbrains.uast.UastLiteralUtils;
import org.jetbrains.uast.visitor.AbstractUastVisitor;

import java.util.Collections;
import java.util.List;

/**
 * Checks overridden URL handling methods in subclasses of WebViewClient.
 *
 * The current checks extend the inner class WebViewClientMethodVisitor.
 * 
 * @author Patrick Frischknecht
 * 
 * University of Bern
 * Software Composition Group
 * 
 */
public class WebViewClientMethodMisuseDetector extends Detector implements Detector.UastScanner {
    private static final String CLASS_WEB_VIEW_CLIENT = "android.webkit.WebViewClient";

    @Override
    public List<String> applicableSuperClasses() {
        return Collections.singletonList(CLASS_WEB_VIEW_CLIENT);
    }

    @Override
    public void visitClass(@NonNull JavaContext context, @NonNull UClass declaration) {
        for (UMethod method : declaration.getMethods()) {
            new ShouldInterceptRequestVisitor(context).acceptIfMethodMatches(method);
            new ShouldOverrideUrlLoadingVisitor(context).acceptIfMethodMatches(method);
            new OnReceivedSslErrorVisitor(context).acceptIfMethodMatches(method);
        }
    }

    public abstract class WebViewClientMethodVisitor extends AbstractUastVisitor {
        protected JavaContext context;

        public WebViewClientMethodVisitor(@NonNull JavaContext context){
            super();
            this.context = context;
        }

        public void acceptIfMethodMatches(@NonNull UMethod method) {
            if (!method.getName().equals(getMethod())) return;

            method.accept(this);
        }

        protected abstract String getMethod();

        protected abstract String getMessage();

        protected abstract Issue getIssue();

        protected abstract boolean isMethodAcceptable();

        private void report(@NonNull UMethod method) {
            context.report(getIssue(), method, context.getLocation(method), getMessage());
        }

        @Override
        public void afterVisitMethod(@NonNull UMethod method) {
            // ignore inner methods
            if (!method.getName().equals(getMethod())) return;

            if (!isMethodAcceptable())
                report(method);
        }
    }


    public static final Issue UNRESTRICTED_INTERCEPT_REQUEST = Issue.create("SlackWebViewClient", //$NON-NLS-1$
            "SM06: Slack WebViewClient | shouldInterceptRequest allows any content to be loaded",
            
            "WebViewClient.shouldInterceptRequest allows to control which resources are loaded." +
            " Any resources are loaded, if the method always returns null," +
            " consequently, the app becomes vulnerable to spoofing attacks.",
            Category.SECURITY,
            6,
            Severity.WARNING,
            new Implementation(
                    WebViewClientMethodMisuseDetector.class,
                    Scope.JAVA_FILE_SCOPE));

    /**
     * Verification of shouldInterceptRequest if it will not return null.
     */
    @VisibleForTesting
    public class ShouldInterceptRequestVisitor extends WebViewClientMethodVisitor {
        @Override
        protected Issue getIssue() {return UNRESTRICTED_INTERCEPT_REQUEST;}
        @VisibleForTesting
        public final static String MESSAGE = "shouldInterceptRequest which allows any content to be loaded";
        @Override
        protected String getMessage() { return MESSAGE; }
        @Override
        protected String getMethod() {return "shouldInterceptRequest"; }

        public ShouldInterceptRequestVisitor(@NonNull JavaContext context){
            super(context);
        }

        private boolean hasNonNullReturn = false;

        @Override
        public boolean visitReturnExpression(@NonNull UReturnExpression returnStatement){
            if(!UastLiteralUtils.isNullLiteral(returnStatement.getReturnExpression()))
                hasNonNullReturn = true;
            return this.visitElement(returnStatement);
        }

        @Override
        public boolean isMethodAcceptable() {
            return hasNonNullReturn;
        }
    }


    public static final Issue UNRESTRICTED_OVERRIDE_URL_LOADING = Issue.create("SlackWebViewClient", //$NON-NLS-1$
            "SM06: Slack WebViewClient | shouldOverrideUrlLoading always returns false or loads the URL instead",
            
            "shouldOverrideUrlLoading allows to control whetever the WebView or the app will handle the requested URL." +
            " Returning false forces the WebView to load the URL, while returning" +
            " true forwards the request to the default browser." +
            " The default behavior of the WebView displays all requests in its WebView." +
            " However, a custom implementation of shouldOverrideUrlLoading should include web page white listing." +
            " Therefore, a custom implementation that always returns false, or calls loadUrl on the WebView to bypass any checks," +
            " does not restrict the access to dangerous web pages at all." +
            " Consequently, any malicious content could be loaded and executed within the WebView." +
            " Consider URL white listing to protect users from malicious content.",
            Category.SECURITY,
            6,
            Severity.WARNING,
            new Implementation(
                    WebViewClientMethodMisuseDetector.class,
                    Scope.JAVA_FILE_SCOPE));

    /**
     * Verification of shouldOverrideUrlLoading if it will not return false, or
     * if it calls view.loadUrl() on the given URL before returning true.
     */
    @VisibleForTesting
    public class ShouldOverrideUrlLoadingVisitor extends WebViewClientMethodVisitor {
        @Override
        protected Issue getIssue() {return UNRESTRICTED_OVERRIDE_URL_LOADING;}
        @VisibleForTesting
        public final static String MESSAGE = "shouldOverrideUrlLoading which always returns false or always loads the url";
        @Override
        protected String getMessage() { return MESSAGE; }
        @Override
        protected String getMethod() {return "shouldOverrideUrlLoading"; }

        private static final String WEB_VIEW = "android.webkit.WebView";
        private static final String WEB_VIEW_LOAD_URL = "loadUrl";




        public ShouldOverrideUrlLoadingVisitor(@NonNull JavaContext context){
            super(context);
        }


        private boolean hasNonFalseReturn = false;
        private boolean hasUnconditionalLoadUrlCall = false;
        private boolean returnsOnlyTrue = true;


        @Override
        public boolean visitReturnExpression(@NotNull UReturnExpression returnStatement){
            if(!UastLiteralUtils.isFalseLiteral(returnStatement.getReturnExpression()))
                hasNonFalseReturn = true;
            if(!UastLiteralUtils.isTrueLiteral(returnStatement.getReturnExpression()))
                returnsOnlyTrue = false;
            return this.visitElement(returnStatement);
        }

        @Override
        public boolean visitCallExpression(@NonNull UCallExpression methodInvocation){
            PsiMethod psiMethod = methodInvocation.resolve();
            if (psiMethod != null &&
                    context.getEvaluator().isMemberInSubClassOf(psiMethod, WEB_VIEW, false) &&
                    methodInvocation.getMethodName() != null &&
                    methodInvocation.getMethodName().equals(WEB_VIEW_LOAD_URL) &&
                    isUnconditionalMethodCall(methodInvocation))
                hasUnconditionalLoadUrlCall = true;

            return this.visitElement(methodInvocation);
        }

        /**
         * Checks if call expression is unconditional call statement within the method.
         * 
         * For example, it checks if view.loadUrl(url); exists within the method shouldOverrideUrlLoading.
         * 
         * The UAST hierarchy for such calls is structured as:
         * 0: UCallExpression
         * 1: UQualifiedReferenceExpression
         * 2: UBlockExpression
         * 3: UMethod
         * 
         * Therefore we need to check that the third parent is the method to ensure
         * that it is an unconditional call.
         * 
         * @param methodInvocation the call expression for which we want to know if it is unconditional
         * @return true if the call is unconditional, false otherwise
         */
        private boolean isUnconditionalMethodCall(@NonNull UCallExpression methodInvocation)
        {
            UElement parentElement = methodInvocation;
            for(int i = 0; i < 3; i++){
                if(parentElement == null)
                    return false;
                parentElement = parentElement.getUastParent();
            }
            return parentElement instanceof UMethod;
        }


        @Override
        public boolean isMethodAcceptable() {
            return hasNonFalseReturn && !(hasUnconditionalLoadUrlCall && returnsOnlyTrue);
        }

    }


    public static final Issue PROCEED_ON_SSL_ERROR = Issue.create("ProceedOnSslError", //$NON-NLS-1$
            "SM00: Proceed On SSL Error | onReceivedSslError always proceeds",
            
            "The onReceivedSslError method allows the application to control the handling of" +
            " SSL errors. However, calling exclusively handler.proceed() in the" +
            " error handler causes the WebViewClient to ignore all SSL errors," +
            " e.g., errors related to certificate validation." +
            " This leaves the WebView open to man in the middle (MITM) attacks, consequently, the app could" +
            " communicate with any malicious server using insecure certificates.",
            Category.SECURITY,
            6,
            Severity.WARNING,
            new Implementation(
                    WebViewClientMethodMisuseDetector.class,
                    Scope.JAVA_FILE_SCOPE))
            .addMoreInfo("https://bitbucket.org/secure-it-i/android-app-vulnerability-benchmarks/src/978fbc17a087/Web/WebViewIgnoreSSLWarning-MITM-Lean/?at=master");

    
    /**
     * Checks that onReceivedSslError does not call handler.proceed().
     * Instead, handler.cancel() should be called.
     * We also assume that handler.cancel() is called if the handler is passed to any further methods.
     */
    @VisibleForTesting
    public class OnReceivedSslErrorVisitor extends WebViewClientMethodVisitor {
        @Override
        protected Issue getIssue() {return PROCEED_ON_SSL_ERROR;}
        @VisibleForTesting
        public final static String MESSAGE = "onReceivedSslError which always proceeds";
        @Override
        protected String getMessage() { return MESSAGE; }
        @Override
        protected String getMethod() {return "onReceivedSslError"; }

        public OnReceivedSslErrorVisitor(@NonNull JavaContext context){
            super(context);
        }

        private boolean foundProceed = false;
        private boolean foundCancel = false;
        private boolean foundMethodReceivingHandler = false;

        @Override
        public boolean visitCallExpression(@NonNull UCallExpression methodInvocation){
            if(isHandlerCancel(methodInvocation)){
                foundCancel = true;
            }
            if(isHandlerProceed(methodInvocation)){
                foundProceed = true;
            }
            if (receivesHandlerAsArgument(methodInvocation))
                foundMethodReceivingHandler = true;
            return super.visitElement(methodInvocation);
        }


        private final static String SSL_ERROR_HANDLER = "android.webkit.SslErrorHandler";
        private final static String HANDLER_CANCEL = "cancel";
        private final static String HANDLER_PROCEED = "proceed";
        private boolean receivesHandlerAsArgument(@NonNull UCallExpression methodInvocation) {
            List<UExpression> argumentValueList = methodInvocation.getValueArguments();
            for (UExpression argument : argumentValueList) {
                PsiType type = argument.getExpressionType();
                if (type != null && SSL_ERROR_HANDLER.equals(type.getCanonicalText())) {
                    return true;
                }
            }

            return false;
        }


        private boolean isHandlerCancel(@NonNull UCallExpression methodInvocation){
            PsiMethod method = methodInvocation.resolve();
            return method != null &&
                    context.getEvaluator().isMemberInSubClassOf(method, SSL_ERROR_HANDLER, false) &&
                    methodInvocation.getMethodName() != null &&
                    methodInvocation.getMethodName().equals(HANDLER_CANCEL);
        }

        private boolean isHandlerProceed(@NonNull UCallExpression methodInvocation){
            PsiMethod method = methodInvocation.resolve();
            return method != null &&
                    context.getEvaluator().isMemberInSubClassOf(method, SSL_ERROR_HANDLER, false) &&
                    methodInvocation.getMethodName() != null &&
                    methodInvocation.getMethodName().equals(HANDLER_PROCEED);
        }

        @Override
        public boolean isMethodAcceptable() {
            return !foundProceed || foundCancel || foundMethodReceivingHandler;
        }
    }
}
