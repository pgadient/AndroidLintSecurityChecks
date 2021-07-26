/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Pascal Gadient et al. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for the license information.
 *--------------------------------------------------------------------------------------------*/

package lint;

import com.android.tools.lint.client.api.IssueRegistry;
import com.android.tools.lint.detector.api.Issue;

import org.jetbrains.annotations.NotNull;

import java.util.ArrayList;
import java.util.List;

/**
 * The registry class that registers all smell detectors in the Android Lint framework.
 *  
 * @author Patrick Frischknecht
 * 
 * University of Bern
 * Software Composition Group
 * 
 */
public class AndroidLintSecurityRegistry extends IssueRegistry {

    @Override
    public int getApi() {
        return com.android.tools.lint.detector.api.ApiKt.CURRENT_API;
    }

    @Override
    @NotNull
    public List<Issue> getIssues() {
        return new ArrayList<Issue>() {
			private static final long serialVersionUID = 2076839363289760503L;
		{
            add(CustomSchemeChannelDetector.ISSUE);
            
            add(WeakHashFunctionDetector.ISSUE);
            
            add(InsufficientRSAKeySizeDetector.ISSUE);
            
            add(BroadcastStickyPermissionDetector.ISSUE);
            
            add(StickyBroadcastDetector.ISSUE);
            
            add(UnprotectedPermissionDetector.ISSUE);
            
            add(UnsafeDynamicBroadcastReceiverDetector.ISSUE);
            
            add(WebViewClientMethodMisuseDetector.PROCEED_ON_SSL_ERROR);
            add(WebViewClientMethodMisuseDetector.UNRESTRICTED_INTERCEPT_REQUEST);
            add(WebViewClientMethodMisuseDetector.UNRESTRICTED_OVERRIDE_URL_LOADING);
            
            add(CallingOrSelfPermissionCheckDetector.ISSUE);

            add(ImplicitUnprotectedIntentSendDetector.IMPLICIT_INTENT_SENDED_UNPROTECTED);
            add(ImplicitUnprotectedIntentSendDetector.IMPLICIT_PENDING_INTENT);
            
            add(PermissionCheckMisuseDetector.ISSUE);
            
            add(TaskAffinityDetector.ACTIVITY_TASK_AFFINITY_SET);
            add(TaskAffinityDetector.APPLICATION_TASK_AFFINITY_NOT_EMPTY);

            add(UnrevokedUriPermissionDetector.ISSUE);

            add(UnrestrictedWebViewDetector.ISSUE);

            add(WrongPathPermissionPrecedenceDetector.ISSUE);

            add(PathPermissionProblematicUriMatchingDetector.ISSUE);
        }};
    }
}
