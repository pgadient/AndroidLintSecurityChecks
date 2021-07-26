/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Pascal Gadient et al. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for the license information.
 *--------------------------------------------------------------------------------------------*/

package lint;

import com.android.annotations.NonNull;
import com.android.annotations.VisibleForTesting;
import com.android.tools.lint.checks.SecurityDetector;
import com.android.tools.lint.detector.api.Category;
import com.android.tools.lint.detector.api.Detector;
import com.android.tools.lint.detector.api.Implementation;
import com.android.tools.lint.detector.api.Issue;
import com.android.tools.lint.detector.api.LintUtils;
import com.android.tools.lint.detector.api.Scope;
import com.android.tools.lint.detector.api.Severity;
import com.android.tools.lint.detector.api.XmlContext;

import org.w3c.dom.Element;

import java.util.Collection;
import java.util.Collections;

import static com.android.SdkConstants.ANDROID_URI;
import static com.android.SdkConstants.ATTR_PATH;
import static com.android.SdkConstants.ATTR_PATH_PATTERN;
import static com.android.SdkConstants.ATTR_PATH_PREFIX;
import static com.android.SdkConstants.ATTR_PERMISSION;
import static com.android.SdkConstants.ATTR_READ_PERMISSION;
import static com.android.SdkConstants.ATTR_WRITE_PERMISSION;
import static com.android.SdkConstants.TAG_PATH_PERMISSION;
import static com.android.SdkConstants.TAG_PROVIDER;

/** 
 * This detector verifies the use of path permissions in a content provider that is already 
 * protected by a permission. The problem is the path permission that should not be used to 
 * further restrict access to specific paths of a permission protected content provider.
 *
 * Note:
 * This detector is not aware of data sensitivity, i.e., it does not know if a permission 
 * is intended to be less or more strict w.r.t. the content provider. We report all path-
 * permissions within protected content providers, except for the path permission 
 * "search_suggest_query". That path permission is commonly used to enable suggestions in 
 * Android's search bars and the corresponding data should not contain any sensitive
 * information as it is publicly available per definition. 
 * 
 * @author Patrick Frischknecht
 * 
 * University of Bern
 * Software Composition Group
 * 
 */
public class WrongPathPermissionPrecedenceDetector extends Detector implements Detector.XmlScanner {

    @VisibleForTesting
    public static final String MESSAGE = "SM09: Broken Path Permission Precedence | Path permissions cannot be used to make certain provider paths more secure, if the provider already defines a permission";

    public static final Issue ISSUE = Issue.create(
            "BrokenPathPermissionPrecedence",
            MESSAGE,
            
            "Path permissions should not be used to introduce permission constraints to certain paths." +
            " The reason is that only provider level permissions are considered for the access right to all paths regardless of" +
            " additional more narrow scoped path permissions.",
            Category.SECURITY,
            5,
            Severity.WARNING,
            new Implementation(
                    WrongPathPermissionPrecedenceDetector.class,
                    Scope.MANIFEST_SCOPE)).addMoreInfo("https://developer.android.com/guide/topics/search/adding-custom-suggestions.html");
    private static final String SEARCH_SUGGEST_QUERY = "search_suggest_query";

    @Override
    public Collection<String> getApplicableElements() {
        return Collections.singleton(TAG_PROVIDER);
    }

    @Override
    public void visitElement(@NonNull XmlContext context, @NonNull Element element) {
        if (!SecurityDetector.getExported(element) || !hasPermission(element))
            return;

        for (Element pathPermissionChild : LintUtils.getChildren(element)) {

            if (TAG_PATH_PERMISSION.equals(pathPermissionChild.getNodeName())) {
                /**
                 * Ignore path permission for search suggest query paths.
                 * These path permissions are unproblematic, since they
                 * intentionally release non-sensitive data.
                 */
                if(protectsASearchSuggestPath(pathPermissionChild))
                    return;
                context.report(ISSUE, pathPermissionChild, context.getLocation(pathPermissionChild), MESSAGE);
            }

        }

    }

    // Checks if the path, pathPattern or PathPrefix protects a path used for a search suggestion
    // (i.e. contains the string "SEARCH_SUGGEST_QUERY")
    private static boolean protectsASearchSuggestPath(Element element) {
        String[] pathAttributeValues = {element.getAttributeNS(ANDROID_URI, ATTR_PATH),
                element.getAttributeNS(ANDROID_URI, ATTR_PATH_PATTERN),
                element.getAttributeNS(ANDROID_URI, ATTR_PATH_PREFIX)};
        for(String pathAttribute : pathAttributeValues) {
            if (pathAttribute != null && pathAttribute.matches(".*"+SEARCH_SUGGEST_QUERY+".*")) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasPermission(Element element) {
        // Used to check whether an activity, service or broadcast receiver is exported.
        String[] permissionAttributeValues = {element.getAttributeNS(ANDROID_URI, ATTR_PERMISSION),
                                              element.getAttributeNS(ANDROID_URI, ATTR_READ_PERMISSION),
                                              element.getAttributeNS(ANDROID_URI, ATTR_WRITE_PERMISSION)};
        for(String permission : permissionAttributeValues) {
            if (permission != null && !permission.isEmpty()) {
                return true;
            }
        }
        return false;
    }
}
