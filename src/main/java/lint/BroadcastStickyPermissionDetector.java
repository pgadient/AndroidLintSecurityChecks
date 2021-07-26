/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Pascal Gadient et al. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for the license information.
 *--------------------------------------------------------------------------------------------*/

package lint;

import com.android.annotations.VisibleForTesting;
import com.android.tools.lint.detector.api.Category;
import com.android.tools.lint.detector.api.Detector;
import com.android.tools.lint.detector.api.Implementation;
import com.android.tools.lint.detector.api.Issue;
import com.android.tools.lint.detector.api.Scope;
import com.android.tools.lint.detector.api.Severity;
import com.android.tools.lint.detector.api.XmlContext;

import org.jetbrains.annotations.NotNull;
import org.w3c.dom.Attr;
import org.w3c.dom.Element;

import java.util.Collection;
import java.util.Collections;

import javax.annotation.Nullable;

import static com.android.SdkConstants.ATTR_NAME;
import static com.android.SdkConstants.NS_RESOURCES;
import static com.android.SdkConstants.TAG_USES_PERMISSION;


/**
 * Checks if the "android.permission.BROADCAST_STICKY" is used.
 * Example:
 * <uses-permission android:name="android.permission.BROADCAST_STICKY" />
 * in the manifest file.
 * 
 * @author Patrick Frischknecht
 * 
 * University of Bern
 * Software Composition Group
 * 
 */
public class BroadcastStickyPermissionDetector extends Detector implements Detector.XmlScanner {
    @VisibleForTesting
    public static final String REPORT_MESSAGE = "The usage of sticky broadcasts is discouraged due to its weak security. " +
                                                "Replace usages of sticky broadcasts with alternatives and remove this permission";

    public static final Issue ISSUE = Issue.create("StickyBroadcast", //$NON-NLS-1$
            "SM05: Sticky Broadcast | The usage of sticky broadcasts is discouraged",
            
            "Sticky broadcasts offer no security as anyone can access and modify them." +
            " Note that they are also deprecated as of API Level 21." +
            " The recommended pattern is to use a non-sticky broadcast to report " +
            " that something has changed, with another mechanism for apps " +
            " to retrieve the current value whenever desired, e.g., an explicit intent (see the provided link).",
            Category.SECURITY,
            6,
            Severity.WARNING,
            new Implementation(
                    BroadcastStickyPermissionDetector.class,
                    Scope.MANIFEST_SCOPE))
            .addMoreInfo("https://developer.android.com/reference/android/content/Context.html");


    private static final String BROADCAST_STICKY = "android.permission.BROADCAST_STICKY";

    @Override
    public Collection<String> getApplicableElements() {
        return Collections.singleton(TAG_USES_PERMISSION);
    }

    @Override
    public void visitElement(@NotNull XmlContext context, @NotNull Element usesPermissionElement) {
        Attr permissionAttr = findPermissionNameAttr(usesPermissionElement);
        if (permissionAttr != null && permissionAttr.getValue() != null
                && permissionAttr.getValue().equals(BROADCAST_STICKY)) {
            context.report(ISSUE, usesPermissionElement, context.getLocation(permissionAttr), REPORT_MESSAGE);
        }
    }

    @Nullable
    private Attr findPermissionNameAttr(@NotNull Element usesPermissionElement) {
        Attr nameAttribute = usesPermissionElement.getAttributeNodeNS(NS_RESOURCES, ATTR_NAME);
        if (nameAttribute != null) {
            return nameAttribute;
        }
        return null;
    }

}
