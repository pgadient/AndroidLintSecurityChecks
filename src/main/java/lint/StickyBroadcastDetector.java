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
import com.intellij.psi.PsiMethod;

import org.jetbrains.uast.UCallExpression;

import java.util.Arrays;
import java.util.List;

/**
 * Detector for sticky broadcasts. Searches for sticky broadcasts with the Context class:
 * - removeStickyBroadcast (Intent intent)
 * - removeStickyBroadcastAsUser (Intent intent, UserHandle user)
 * - sendStickyBroadcast(Intent intent)
 * - sendStickyBroadcastAsUser (Intent intent, UserHandle user)
 * - sendStickyOrderedBroadcast (Intent intent, BroadcastReceiver resultReceiver, Handler scheduler,
 *                             int initialCode, String initialData, Bundle initialExtras)
 * - sendStickyOrderedBroadcastAsUser(Intent intent, UserHandle user, BroadcastReceiver resultReceiver,
 *                                   Handler scheduler, int initialCode, String initialData, Bundle initialExtras)
 * 
 * Use of sticky broadcast is discouraged because they offer no protection and security.
 * Anyone can access, read and modify them.
 * 
 * @author Patrick Frischknecht
 * 
 * University of Bern
 * Software Composition Group
 * 
 */
public class StickyBroadcastDetector extends Detector implements Detector.UastScanner {

    private static final String CONTEXT_CLASS = "android.content.Context";
    @VisibleForTesting
    public static final String STICKY_BROADCAST_USED = "Sticky broadcasts should not be used as they offer nearly no security or protection";

    public static final Issue ISSUE = Issue.create("StickyBroadcast",
            "SM05: Sticky Broadcast | The usage of sticky broadcasts is strongly discouraged",
            
            "According to the Google developer guidelines," +
            " sticky broadcasts should not be used. They provide no security (anyone can access them)," +
            " no protection (anyone can modify them), and many other problems." +
            " The recommended pattern is to use a non-sticky broadcast to report " +
            " that something has changed, with another mechanism for apps " +
            " to retrieve the current value whenever desired, e.g., with an explicit intent.",
            Category.SECURITY,
            6,
            Severity.WARNING,
            new Implementation(
                    StickyBroadcastDetector.class,
                    Scope.JAVA_FILE_SCOPE))
            .addMoreInfo("https://developer.android.com/reference/android/content/Context.html");


    @Override
    public void visitMethod(@NonNull JavaContext context, @NonNull UCallExpression call,
                            @NonNull PsiMethod method) {
        JavaEvaluator evaluator = context.getEvaluator();
        if(!evaluator.isMemberInSubClassOf(method, CONTEXT_CLASS, false))
            return;

        // Because we set getApplicableMethodNames to all sticky broadcast methods we know
        // by now that one of them was used
        context.report(ISSUE, call, context.getLocation(call), STICKY_BROADCAST_USED);
    }

    @Override
    public List<String> getApplicableMethodNames() {
        return Arrays.asList("removeStickyBroadcast","removeStickyBroadcastAsUser","sendStickyBroadcast",
                            "sendStickyBroadcastAsUser","sendStickyOrderedBroadcast",
                            "sendStickyOrderedBroadcastAsUser");
    }
}
