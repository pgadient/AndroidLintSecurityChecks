package lint;

import com.android.annotations.NonNull;
import com.android.annotations.Nullable;
import com.android.annotations.VisibleForTesting;
import com.android.tools.lint.checks.SecurityDetector;
import com.android.tools.lint.detector.api.Category;
import com.android.tools.lint.detector.api.Detector;
import com.android.tools.lint.detector.api.Implementation;
import com.android.tools.lint.detector.api.Issue;
import com.android.tools.lint.detector.api.JavaContext;
import com.android.tools.lint.detector.api.LintUtils;
import com.android.tools.lint.detector.api.Scope;
import com.android.tools.lint.detector.api.Severity;
import com.android.tools.lint.detector.api.XmlContext;
import com.intellij.psi.PsiClass;
import com.intellij.psi.PsiMethod;

import org.jetbrains.uast.UCallExpression;
import org.jetbrains.uast.UastUtils;
import org.w3c.dom.Element;

import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.android.SdkConstants.ANDROID_URI;
import static com.android.SdkConstants.ATTR_NAME;
import static com.android.SdkConstants.TAG_PATH_PERMISSION;
import static com.android.SdkConstants.TAG_PROVIDER;

/**
 * Detector for UriMatchers used in combination with path permissions.
 * 
 * @author Patrick Frischknecht
 * 
 * University of Bern
 * Software Composition Group
 * 
 */
public class PathPermissionProblematicUriMatchingDetector extends Detector implements Detector.UastScanner, Detector.XmlScanner {

    @VisibleForTesting
    public static final String MESSAGE = "SM08: Insecure Path Permission | Avoid using path permission together with UriMatcher in a content provider";

    private XmlContext manifestContext= null;

    // keeps track of all provider classes mentioned in the manifest that contain a path-permission
    // element
    private Map<String, Element> providerClassNameToXmlElement = new HashMap<>();

    public static final Issue ISSUE = Issue.create(
            "InsecurePathPermission",
            MESSAGE,
            "Path permission can be used to protect certain paths of a content provider." +
            " However, the matching of paths in a path permission and" +
            " UriMatcher instance differs. Vulnerability example: An app includes a path permission" +
            " for \"/user/secret\" in the content provider and a UriMatcher matching on the same string in the provider's query method." +
            " Everything works as intended as long as the path used to query the provider is identical," +
            " thus the caller must hold the permission defined in the callee's path permission." +
            " However, an additional backslash (\"//user/secret\") will bypass the path permission checks," +
            " , nevertheless, the string still matches within the UriMatcher that does not differentiate between one and two slashes." +
            " This could lead to the leakage of sensitive data if" +
            " a path permission is used together with a content provider using a UriMatcher."+
            " In the current state we suggest to explicitly use path permissions to make specific content provider paths" +
            " more visible.",
            Category.SECURITY,
            5,
            Severity.WARNING,
            new Implementation(
                    PathPermissionProblematicUriMatchingDetector.class,
                    EnumSet.of(Scope.MANIFEST, Scope.JAVA_FILE)));

    @Override
    public Collection<String> getApplicableElements() {
        return Collections.singleton(TAG_PROVIDER);
    }


    @Override
    @Nullable
    public List<String> getApplicableConstructorTypes() {
        return Collections.singletonList("android.content.UriMatcher");
    }

    @Override
    public void visitConstructor(JavaContext context, UCallExpression node, PsiMethod constructor) {

        PsiClass containingClass = UastUtils.getContainingClass(node);
        if(containingClass == null)
            return;
        String unqualifiedProviderName = containingClass.getName();
        Element providerXmlElement = providerClassNameToXmlElement.get(unqualifiedProviderName);
        if(providerXmlElement == null)
            return;
        if(manifestContext != null)
            manifestContext.report(ISSUE, providerXmlElement, manifestContext.getLocation(providerXmlElement), MESSAGE);
    }

    @Override
    public void visitElement(@NonNull XmlContext context, @NonNull Element element) {

        if (!SecurityDetector.getExported(element))
            return;
        String providerName = element.getAttributeNS(ANDROID_URI, ATTR_NAME);
        manifestContext = context;
        for (Element child : LintUtils.getChildren(element)) {
            if (TAG_PATH_PERMISSION.equals(child.getNodeName())) {
                String providerClassNameParts[] = providerName.split("\\.");
                String unqualifiedProviderClassName = providerClassNameParts[providerClassNameParts.length - 1];
                providerClassNameToXmlElement.put(unqualifiedProviderClassName, element);
                return;
            }

        }

    }

}
