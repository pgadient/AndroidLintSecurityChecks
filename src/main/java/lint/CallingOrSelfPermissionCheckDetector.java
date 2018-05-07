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
import com.intellij.psi.PsiMethod;

import org.jetbrains.uast.UCallExpression;

import java.util.Arrays;
import java.util.List;

/**
 * Checks for checkSelfOrCallingPermission and enforceSelfOrCallingPermission.
 * These methods should be avoided as they could erroneously provide caller apps the permission of the callee.
 * 
 * @author Patrick Frischknecht
 * 
 * University of Bern
 * Software Composition Group
 * 
 */
public class CallingOrSelfPermissionCheckDetector extends Detector implements Detector.UastScanner {

    private static final String CONTEXT_CLASS = "android.content.Context";
    private static final String PERMISSION_CHECKER_CLASS = "android.support.v4.content.PermissionChecker";
    @VisibleForTesting
    public static final String MESSAGE = " could grant access to malicious apps";

    public static final Issue ISSUE = Issue.create("BrokenServicePermission",
            "SM07: Broken Service Permission | SelfPermission checks could fail",
            "As the name suggests, checkSelfOrCallingPermission and enforceSelfOrCallingPermission" +
            " grant the access if either the caller or the callee app has appropriate permissions." +
            " These methods should not be used with great care as they could erroneously return grants" +
            " to underprivileged apps.",
            Category.SECURITY,
            6,
            Severity.WARNING,
            new Implementation(
                    CallingOrSelfPermissionCheckDetector.class,
                    Scope.JAVA_FILE_SCOPE));

    @Override
    public void visitMethod(@NonNull JavaContext context, @NonNull UCallExpression call,
                            @NonNull PsiMethod method) {
        JavaEvaluator evaluator = context.getEvaluator();
        if(!evaluator.isMemberInSubClassOf(method, CONTEXT_CLASS, false) && !evaluator.isMemberInSubClassOf(method, PERMISSION_CHECKER_CLASS, false))
            return;

        context.report(ISSUE, call, context.getLocation(call), call.getMethodName()+MESSAGE);


    }

    @Override
    public List<String> getApplicableMethodNames() {
        return Arrays.asList("checkCallingOrSelfPermission","enforceCallingOrSelfPermission"
        ,"checkCallingOrSelfUriPermission","enforceCallingOrSelfUriPermission");
    }
}
