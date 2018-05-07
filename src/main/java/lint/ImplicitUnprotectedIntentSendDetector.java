package lint;


import com.android.annotations.NonNull;
import com.android.annotations.Nullable;
import com.android.tools.lint.client.api.JavaEvaluator;
import com.android.tools.lint.detector.api.Category;
import com.android.tools.lint.detector.api.Detector;
import com.android.tools.lint.detector.api.Implementation;
import com.android.tools.lint.detector.api.Issue;
import com.android.tools.lint.detector.api.JavaContext;
import com.android.tools.lint.detector.api.Scope;
import com.android.tools.lint.detector.api.Severity;
import com.intellij.psi.PsiElement;
import com.intellij.psi.PsiMethod;
import com.intellij.psi.PsiType;
import com.intellij.psi.PsiVariable;

import org.jetbrains.uast.UCallExpression;
import org.jetbrains.uast.UExpression;
import org.jetbrains.uast.UMethod;
import org.jetbrains.uast.UReferenceExpression;
import org.jetbrains.uast.USimpleNameReferenceExpression;
import org.jetbrains.uast.UastLiteralUtils;
import org.jetbrains.uast.UastUtils;
import org.jetbrains.uast.util.UastExpressionUtils;
import org.jetbrains.uast.visitor.AbstractUastVisitor;

import java.util.Arrays;
import java.util.List;

import static lint.UastHelper.getLastAssignedExpression;
import static lint.UastHelper.hasClassOrSuperClass;
import static lint.UastHelper.methodHasName;

/**
 * This detector checks if an implicit intent is created and sent
 * without any additional protection through a permission specified in the sending method.
 * Important: This detector considers only intra-procedural issues.
 * Intents are implicit as long as their receiver is not defined specifically. Receivers can 
 * be defined specifically by the component (Class or ComponentName) during intent creation 
 * or later. We only consider an implicit intent to be safe if the sending method 
 * (like sendBroadcast) also receives a permission argument.
 * 
 * @author Patrick Frischknecht
 * 
 * University of Bern
 * Software Composition Group
 * 
 */
public class ImplicitUnprotectedIntentSendDetector extends Detector implements Detector.UastScanner {

    private static final String PENDING_INTENT_CLASS = "android.app.PendingIntent";

    private static final String INTENT_CLASS = "android.content.Intent";
    private static final String CONTEXT_CLASS = "android.content.Context";
    private static final String ACTIVITY_CLASS = "android.app.Activity";

    private static final String URI_CLASS= "android.net.Uri";

    public static final String IMPLICIT_INTENT_MESSAGE = "Avoid sending implicit intents if possible";
    public static final Issue IMPLICIT_INTENT_SENDED_UNPROTECTED = Issue.create("UnauthorizedIntent", //$NON-NLS-1$
    		   		"SM04: Unauthorized Intent | Avoid sending implicit intents if possible",
    		   		
            		" Intents can be either implicit or explicit. An intent is implicit" +
                    " as long as the receiver is not completely specified. The receiver can be specified" +
                    " within the intent constructor or later via setClass(), setClassName() or setComponentName()" +
                    "" +
                    " Sending implicit intents is problematic. Any app can register itself to receive any implicit" +
                    " intent. Therefore sensitive information in implicit intents is not protected from leaking " +
                    " to any other app. Always use explicit intents if the receiver is known and do not store" +
                    " sensitive information in implicit intents. Use LocalBroadcastManager for communication" +
                    " within your application if possible. You can also specifiy a permission within your send call" +
                    " that the receiver has to acquire first in order to get access to your intent.",
            Category.SECURITY,
            6,
            Severity.WARNING,
            new Implementation(
                    ImplicitUnprotectedIntentSendDetector.class,
                    Scope.JAVA_FILE_SCOPE))
            .addMoreInfo("https://developer.android.com/training/articles/security-tips.html#IPC");
    public static final String IMPLICIT_PENDING_INTENT_MESSAGE = "Do not use implicit intents for pending intents";
    public static final Issue IMPLICIT_PENDING_INTENT = Issue.create("ImplicitPendingIntent", //$NON-NLS-1$
            		"SM11: Implicit Pending Intent | Using an implicit intent for a pending intent",
            		
            		" Intents can be either implicit or explicit. An intent is implicit" +
                    " as long as the receiver is not completely specified. The receiver can be specified" +
                    " within the intent constructor or later via setClass(), setClassName() or setComponentName()" +
                    "" +
                    " A PendingIntent should always be constructed out of an explicit intent. If the original " +
                    " intent was empty, the resulting PendingIntent could be intercepted by other apps. Malicious apps" +
                    " could then modify the intent or read data contained in the intent.",
            Category.SECURITY,
            6,
            Severity.WARNING,
            new Implementation(
                    ImplicitUnprotectedIntentSendDetector.class,
                    Scope.JAVA_FILE_SCOPE))
            .addMoreInfo("https://developer.android.com/reference/android/app/PendingIntent.html")
            .addMoreInfo("https://bitbucket.org/secure-it-i/android-app-vulnerability-benchmarks/src/978fbc17a087d77b38474bfbe01a00b5e2217ce6/ICC/ImplicitPendingIntent-IntentHijack-Lean/?at=master")
            .addMoreInfo("https://wiki.sei.cmu.edu/confluence/display/android/DRD21-J.+Always+pass+explicit+intents+to+a+PendingIntent");

    @Override
    public void visitMethod(@NonNull JavaContext context, @NonNull UCallExpression call,
                            @NonNull PsiMethod method) {
        boolean isPendingIntent = isPendingIntent(call);
        JavaEvaluator evaluator = context.getEvaluator();

        if(!evaluator.isMemberInSubClassOf(method, CONTEXT_CLASS, false) && !evaluator.isMemberInSubClassOf(method, ACTIVITY_CLASS, false)
            && !evaluator.isMemberInSubClassOf(method, PENDING_INTENT_CLASS, false))
            return;

        // Calls which include a non null permission are ok
        if(checkCallIncludesPermission(call))
            return;
        
        UExpression intentArgument = getIntentArgument(call);
        // calls to these methods without intent argument aren't interesting
        if(intentArgument == null)
            return;

        // Check if the intent argument is directly a constructor
        // for example in the call sendBroadcast(new Intent("test.action"))
        // an implicit intent is directly created and sent, therefore we need to report
        if(UastExpressionUtils.isConstructorCall(intentArgument)){
            if(!isExplicitIntentConstructor(intentArgument)) {
                report(call, isPendingIntent, context);
                return;
            }
            else
                return;
        }
        
        // get the last assingment in case the intent argument is a variable
        UExpression lastAssignment = getLastAssignedExpression(intentArgument, call);
        // return if either:
        // we couldn't find the last assignment (because the intent was a method for example)
        // it wasn't assigned an intent with a constructor but with a method
        // the constructed intent assigned to the variable was an explicit and therefore we don't need
        // to continue checking, as explicit intents can not be made implicit
        if(lastAssignment == null || !UastExpressionUtils.isConstructorCall(lastAssignment) || isExplicitIntentConstructor(lastAssignment))
            return;

        // Starting from here, we know the intent was constructed within the method surrounding this call
        // with an implicit constructor. We still need to determine if intent has been made explicit
        // with the help of a SendIntentMethodVisitor
        if (intentArgument instanceof USimpleNameReferenceExpression) {
            PsiElement e = UastUtils.tryResolve(intentArgument);
            if (e instanceof PsiVariable) {
                UMethod containingMethod = UastUtils.getContainingUMethod(call);
                if(containingMethod == null)
                    return;
                SendIntentMethodVisitor visitor = new SendIntentMethodVisitor((PsiVariable) e);
                containingMethod.accept(visitor);
                if(!visitor.intentWasMadeExplicit())
                    report(call, isPendingIntent, context);
            }
        }

    }

    // check if the method call includes a non null permission argument
    private boolean checkCallIncludesPermission(@NonNull UCallExpression call){
        UExpression permissionArgument = getPermissionArgument(call);
        return permissionArgument != null && !UastLiteralUtils.isNullLiteral(permissionArgument);
    }

    // Explicit Intent constructors are all constructors which require a class and a package name.
    // This includes the following two constructors:
    // Intent(Context packageContext, Class<?> cls)
    // Intent(String action, Uri uri, Context packageContext, Class<?> cls)
    private boolean isExplicitIntentConstructor(@Nullable UExpression expression){
        if(expression == null)
            return false;
        UCallExpression constructorCall = (UCallExpression) expression;
        UReferenceExpression classReference = constructorCall.getClassReference();
        if (classReference == null)
            return false;
        String klass = UastUtils.getQualifiedName(classReference);
        if (INTENT_CLASS.equals(klass)) {
            List<UExpression> valueArgumentList = constructorCall.getValueArguments();
            if (valueArgumentList.size() != 2 && valueArgumentList.size() != 4)
                return false;
            // for all implicit constructors with 2 or 4 arguments, the last argument is a uri
            PsiType lastType = valueArgumentList.get(valueArgumentList.size() - 1).getExpressionType();

            if ( lastType == null )
                return true;
            return !hasClassOrSuperClass(lastType, URI_CLASS);
        }

        return false;
    }

    // tries to find the intent argument of the given UCallExpression
    private UExpression getIntentArgument(@NonNull UCallExpression call){
        List<UExpression> argumentValueList = call.getValueArguments();
        for(UExpression intentArgument : argumentValueList){
            PsiType argumentType = intentArgument.getExpressionType();
            if(hasClassOrSuperClass(argumentType, INTENT_CLASS))
                return intentArgument;
        }
        return null;
    }

    @Nullable
    // tries to find the intent argument of the given UCallExpression; returns null if
    // the call includes no permission argument
    private UExpression getPermissionArgument(@NonNull UCallExpression call){
        String methodName = call.getMethodName();
        if(methodName == null)
            return null;
        List<UExpression> argumentValueList = call.getValueArguments();
        int permissionArgumentIndex = 0;
        switch(call.getMethodName()){
            case "sendBroadcast":
            case "sendOrderedBroadcast":
                permissionArgumentIndex = 1;
                break;
            case "sendBroadcastAsUser":
            case "sendOrderedBroadcastAsUser":
                permissionArgumentIndex = 2;
                break;
            default:
                return null;
        }
        if(argumentValueList.size() > permissionArgumentIndex)
            return argumentValueList.get(permissionArgumentIndex);
        return null;
    }

    // reports the issue; depending on the isPendingIntent it reports a IMPLICIT_PENDING_INTENT
    // or a IMPLICIT_INTENT_SENDED_UNPROTECTED issue
    private void report(@NonNull UCallExpression call, boolean isPendingIntent, @NonNull JavaContext context){
        if(isPendingIntent)
            context.report(IMPLICIT_PENDING_INTENT, call, context.getLocation(call), IMPLICIT_PENDING_INTENT_MESSAGE);
        else
            context.report(IMPLICIT_INTENT_SENDED_UNPROTECTED, call, context.getLocation(call), IMPLICIT_INTENT_MESSAGE);

    }

    // tries to find out if the giving method call calls a method to create a pending intent
    private boolean isPendingIntent(@NonNull UCallExpression call){
        if(call.getMethodName() == null)
            return false;
        switch(call.getMethodName()){
            case "getActivity":
            case "getBroadcast":
            case "getService":
            case "getForegroundService":
                return true;
            default:
                return false;
        }
    }

    @Override
    public List<String> getApplicableMethodNames() {
        return Arrays.asList("sendBroadcast", "sendBroadcastAsUser", "sendOrderedBroadcast",
                "sendOrderedBroadcastAsUser", "sendStickyBroadcast", "sendStickyBroadcastAsUser",
                "sendStickyOrderedBroadcast", "sendStickyOrderedBroadcastAsUser", "startService",
                "getBroadcast", "getService", "getActivity", "getForegroundService", "createPendingResult", "startActivity", "setResult", "startActivityForResult", "getIntent");
    }


    // A visitor which tries to follow the trace of a given intent reference within a method
    // to find out if any method was called to make this intent explicit
    private class SendIntentMethodVisitor extends AbstractUastVisitor {
        private PsiVariable intentVariable;
        private boolean makesIntentExplicit = false;

        private SendIntentMethodVisitor(@NonNull PsiVariable intentVariable) {
            this.intentVariable = intentVariable;
        }

       private void makesIntentExplicit(@NonNull UCallExpression methodInvocation){
            if(isComponentSettingMethod(methodInvocation)) {
                PsiElement e = UastUtils.tryResolve(methodInvocation.getReceiver());
                if (e instanceof PsiVariable) {
                    PsiVariable receivingVariable = (PsiVariable) e;
                    if(receivingVariable.getName() != null &&
                            receivingVariable.getName().equals(intentVariable.getName()))
                        makesIntentExplicit = true;
                }
                // if e is not a variable we just assume that it is the same
                // this can happen, for example, when multiple intent methods are chained
                else
                    makesIntentExplicit = true;

            }
        }

        private boolean isComponentSettingMethod(@NonNull UCallExpression call){
           for(String componentSettingMethods : componentSettingMethods()){
               if(methodHasName(call, componentSettingMethods))
                   return true;
           }
           return false;
        }

        private List<String> componentSettingMethods(){
            return Arrays.asList("setClass","setClassName","setComponentName","setPackage","setComponent");
        }

        @Override
        public boolean visitCallExpression(@NonNull UCallExpression methodInvocation) {
            makesIntentExplicit(methodInvocation);
            return super.visitCallExpression(methodInvocation);
        }

        boolean intentWasMadeExplicit() {
            return makesIntentExplicit;
        }

    }
}
