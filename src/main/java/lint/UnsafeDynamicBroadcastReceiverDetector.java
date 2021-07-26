/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Pascal Gadient et al. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for the license information.
 *--------------------------------------------------------------------------------------------*/

package lint;

import com.android.annotations.NonNull;
import com.android.annotations.Nullable;
import com.android.annotations.VisibleForTesting;
import com.android.tools.lint.client.api.JavaEvaluator;
import com.android.tools.lint.detector.api.Category;
import com.android.tools.lint.detector.api.Detector;
import com.android.tools.lint.detector.api.Implementation;
import com.android.tools.lint.detector.api.Issue;
import com.android.tools.lint.detector.api.JavaContext;
import com.android.tools.lint.detector.api.Scope;
import com.android.tools.lint.detector.api.Severity;
import com.intellij.psi.PsiMethod;

import org.jetbrains.uast.UCallExpression;
import org.jetbrains.uast.UExpression;
import org.jetbrains.uast.UastLiteralUtils;

import java.util.Collections;
import java.util.List;

/**
 * This detector searches for run time registrations of receivers that do not consider any permissions.
 * 
 * Example:
 * Context.registerReceiver(broadcastReceiver, new IntentFilter("package.action.SOME_ACTION"));
 * 
 * @author Patrick Frischknecht
 * 
 * University of Bern
 * Software Composition Group
 * 
 */
public class UnsafeDynamicBroadcastReceiverDetector extends Detector implements Detector.UastScanner {

    private static final String CONTEXT_CLASS = "android.content.Context";
    @VisibleForTesting
    public static final String NO_PERMISSION_ARGUMENT_MESSAGE = "Missing grant revokings can leave an app vulnerable to intent spoofing";
    @VisibleForTesting
    public static final String EMPTY_PERMISSION_ARGUMENT_MESSAGE = "Null objects should not be used as permission arguments";

    public static final Issue ISSUE = Issue.create("UnprotectedBroadcastReceiver", //$NON-NLS-1$
            "SM10: Unprotected Broadcast Receiver | A broadcast receiver is dynamically registered without any permission",
            
            "Broadcast receivers registered via registerReceiver() without any permission argument are available to all other apps," +
            " so every app can receive these intents." +
            " This fosters intent spoofing: A malicious app could craft an intent"  +
            " to call a broadcaster's onReceive method with arbitrary data.\n"+
            " Consider using \"registerReceiver(BroadcastReceiver receiver, IntentFilter filter, String broadcastPermission, Handler scheduler)\"" +
            " and set broadcastPermission to something different than null." +
            " Alternatively, if the broadcast receiver is only intended to be used within an app, consider using" +
            " LocalBroadcastManager.registerReceiver(BroadcastReceiver, IntentFilter) instead.",
            Category.SECURITY,
            6,
            Severity.WARNING,
            new Implementation(
                    UnsafeDynamicBroadcastReceiverDetector.class,
                    Scope.JAVA_FILE_SCOPE));


    @Override
    public void visitMethod(@NonNull JavaContext context, @NonNull UCallExpression call,
                            @NonNull PsiMethod method) {
        JavaEvaluator evaluator = context.getEvaluator();
        if(!evaluator.isMemberInSubClassOf(method, CONTEXT_CLASS, false))
            return;
        Integer argumentCount = call.getValueArgumentCount();
        List<UExpression> argumentValueList = call.getValueArguments();

        if (!registersNonNullReceiver(argumentValueList))
            return;

        if (!isCallWithPermissionArgument(argumentCount)) {
            context.report(ISSUE, call, context.getLocation(call), NO_PERMISSION_ARGUMENT_MESSAGE);
            return;
        }

        if (!nonEmtpyPermissionArgument(argumentValueList)) {
            context.report(ISSUE, call, context.getLocation(call), EMPTY_PERMISSION_ARGUMENT_MESSAGE);
        }
    }

    /**
     * Checks if the call signature used for registerReceiver contains a permission argument,
     * i.e., this returns true if one of the following signatures was used:
     * registerReceiver(BroadcastReceiver receiver, IntentFilter filter, String broadcastPermission, Handler scheduler, int flags)
     * registerReceiver(BroadcastReceiver receiver, IntentFilter filter, String broadcastPermission, Handler scheduler)
     * @param argumentCount the number of arguments the registerReceiver method call receives
     * @return true if the number of arguments is 4 or 5 and thus we know the call contains an argument
     * for the permission
     */
    private boolean isCallWithPermissionArgument(@Nullable Integer argumentCount){
        return !(argumentCount == null || argumentCount != 5 && argumentCount != 4);
    }

    /**
     * Checks if the argument "String broadcastPermission" of the call to registerReceiver is not null
     * 
     * @param argumentValueList the arguments list of the registerReceiver methods invocation
     * @return true if the "String broadcastPermission"argument (third argument) is not null
     */
    private boolean nonEmtpyPermissionArgument(@NonNull List<UExpression> argumentValueList){
        // the permission argument is always at the third place
        UExpression permissionArgument = argumentValueList.get(2);

        return !UastLiteralUtils.isNullLiteral(permissionArgument);
    }

    /**
     * Checks if the argument "BroadcastReceiver receiver" of the call to registerReceiver is not null.
     * In the Android framework a null value stands for "no receiver is registered",  
     * and only active sticky broadcasts will be returned.
     * 
     * @param argumentValueList the arguments list of the registerReceiver methods invocation
     * @return true if the "BroadcastReceiver receiver" argument (first argument) is not null
     */
    private boolean registersNonNullReceiver(@Nullable List<UExpression> argumentValueList){
        // the receiver argument is always at the first place
        UExpression permissionArgument = argumentValueList.get(0);

        return !UastLiteralUtils.isNullLiteral(permissionArgument);
    }

    @Override
    public List<String> getApplicableMethodNames() {
        return Collections.singletonList("registerReceiver");
    }
}
