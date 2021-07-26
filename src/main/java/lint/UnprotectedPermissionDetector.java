/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Pascal Gadient et al. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for the license information.
 *--------------------------------------------------------------------------------------------*/

package lint;

import com.android.annotations.NonNull;
import com.android.annotations.VisibleForTesting;
import com.android.tools.lint.detector.api.Category;
import com.android.tools.lint.detector.api.Detector;
import com.android.tools.lint.detector.api.Implementation;
import com.android.tools.lint.detector.api.Issue;
import com.android.tools.lint.detector.api.Scope;
import com.android.tools.lint.detector.api.Severity;
import com.android.tools.lint.detector.api.XmlContext;

import org.w3c.dom.Attr;
import org.w3c.dom.Element;

import java.util.Collection;
import java.util.Collections;

import javax.annotation.Nullable;

import static com.android.SdkConstants.NS_RESOURCES;
import static com.android.SdkConstants.TAG_PERMISSION;

/**
 * Checks that all permissions declared in the manifest have their protectionLevel set explicitly
 * 
 * @author Patrick Frischknecht
 * 
 * University of Bern
 * Software Composition Group
 * 
 */
public class UnprotectedPermissionDetector extends Detector implements Detector.XmlScanner {

    @VisibleForTesting
    public static final String REPORT_MESSAGE = "No explicit \"android:protectionLevel\" set for this permission. The default is normal which is only for low risk features.";

    private static final String ATTR_PROTECTION_LEVEL = "protectionLevel";

    public static final Issue ISSUE = Issue.create("UnprotectedPermission", //$NON-NLS-1$
            "SM03: Incorrect Protection Level | The \"android:protectionLevel\" attribute is missing for a custom permission", 
            
            "Revise your feature carefully and set the protection level accordingly." +
            " The \"android:protectionLevel\" states the risk implied with a permission." +
            " The default value is normal. Potential values are:" +
            " <i>normal</i> protection level for a permission with minimal implied risks. The user won't be asked to" +
            " grant the permission, he can only review it during installation." +
            " <i>dangerous</i> for a higher risk permission that could allow other applications to access private" +
            " user data or provide them control over important device functions. Any dangerous permission" +
            " requested by an application is displayed to the user at least once during run time." +
            " <i>signature</i> is only granted to applications signed with the same certificate." +
            " If the certificate matches the permission it is granted without notifying the user." +
            " We recommend to revise the protection level of your permission carefully. If possible, always use \"signature\" protection level.",
            Category.SECURITY,
            6,
            Severity.WARNING,
            new Implementation(
                    UnprotectedPermissionDetector.class,
                    Scope.MANIFEST_SCOPE))
            .addMoreInfo("https://developer.android.com/guide/topics/manifest/permission-element.html");

    @Override
    public Collection<String> getApplicableElements() {
        return Collections.singleton(TAG_PERMISSION);
    }

    @Override
    public void visitElement(@NonNull XmlContext context, @NonNull Element permissionElement) {
        Attr protectionLevelAttribute = findProtectionLevelAttr(permissionElement);
        if(protectionLevelAttribute == null) {
            context.report(ISSUE, permissionElement, context.getLocation(permissionElement), REPORT_MESSAGE);
        }
    }

    @Nullable
    private Attr findProtectionLevelAttr(@NonNull Element permissionElement) {
        Attr protectionLevelAttribute = permissionElement.getAttributeNodeNS(NS_RESOURCES, ATTR_PROTECTION_LEVEL);
        if (protectionLevelAttribute != null) {
            return protectionLevelAttribute;
        }
        return null;
    }

}
