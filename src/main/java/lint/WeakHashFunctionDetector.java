/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Pascal Gadient et al. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for the license information.
 *--------------------------------------------------------------------------------------------*/

package lint;

import com.android.annotations.NonNull;
import com.android.tools.lint.client.api.JavaEvaluator;
import com.android.tools.lint.client.api.UElementHandler;
import com.android.tools.lint.detector.api.Category;
import com.android.tools.lint.detector.api.Detector;
import com.android.tools.lint.detector.api.Detector.UastScanner;
import com.android.tools.lint.detector.api.Implementation;
import com.android.tools.lint.detector.api.Issue;
import com.android.tools.lint.detector.api.JavaContext;
import com.android.tools.lint.detector.api.Scope;
import com.android.tools.lint.detector.api.Severity;

import java.util.Collections;
import java.util.List;

import com.intellij.psi.PsiClass;
import com.intellij.psi.PsiElement;
import com.intellij.psi.PsiMethod;
import com.intellij.psi.tree.IElementType;

import org.jetbrains.uast.UCallExpression;
import org.jetbrains.uast.UElement;
import org.jetbrains.uast.UExpression;
import org.jetbrains.uast.UastLiteralUtils;

/**
 * Checks for the use of weak hash functions. Currently, the only verified weak hash function is MD5.
 * 
 * Insecure example:
 * MessageDigest.getInstance("MD5");
 * 
 * @author Patrick Frischknecht
 * 
 * University of Bern
 * Software Composition Group
 * 
 */
public class WeakHashFunctionDetector extends Detector implements UastScanner {

	private static final String LINT_ID = "WeakHashFunction";
	private static final String LINT_ISSUE = "SM00: Weak Hash Function";
	private static final String LINT_DESC = "A weak hashing function facilitates collision attacks";
	private static final String LINT_MSG = "**MD5** is considered a **weak hash function**.";
	
	private static final Category LINT_CATEGORY = Category.SECURITY;
	private static final int LINT_PRIORITY = 6;
	private static final Severity LINT_SEVERITY = Severity.WARNING;

	private static final String M_GETINSTANCE = "getInstance"; 
    private static final String FQC_MESSAGEDIGEST = "java.security.MessageDigest";
    private static final String L_WEAKHASHALGO = "MD5"; 

    public static final Issue ISSUE = Issue.create(
    		LINT_ID,
    		LINT_ISSUE,
    		LINT_DESC,
    		LINT_CATEGORY,
    		LINT_PRIORITY,
    		LINT_SEVERITY,
            new Implementation(
                    WeakHashFunctionDetector.class,
                    Scope.JAVA_FILE_SCOPE));

    @Override
    public List<Class<? extends UElement>> getApplicableUastTypes() {
        return Collections.singletonList(UCallExpression.class);
    }
    
    @Override
    public UElementHandler createUastHandler(@NonNull JavaContext context) {
        return new UElementHandler() {
        	public void visitCallExpression(UCallExpression uCallExpression) {
        		JavaEvaluator evaluator = context.getEvaluator();
        		
        		String method = uCallExpression.getMethodName();
        		if (method == null || !method.equals(M_GETINSTANCE)) {
        			return;
        		}
        		
        		PsiMethod calledMethod = uCallExpression.resolve();
        		if(calledMethod == null)
        			return;
				PsiClass containingClass= calledMethod.getContainingClass();
				if(containingClass == null)
					return;
				String fullyQualifiedClass = containingClass.getQualifiedName();
        		if (!FQC_MESSAGEDIGEST.equals(fullyQualifiedClass)) {
        			return;
        		}
        		
        		List<UExpression> parameterList = uCallExpression.getValueArguments();
        		for (UExpression ue : parameterList) {
        			// check for inline parameter 
        			String parameterValue = UastLiteralUtils.getValueIfStringLiteral(ue);
	                if (parameterValue != null && parameterValue.toUpperCase().equals(L_WEAKHASHALGO)) {
	                	context.report(ISSUE, ue, context.getLocation(ue), LINT_MSG);
	                	return;
	                }
	                
	                // check for referenced string parameter
	                PsiElement pe = evaluator.resolve(ue.getPsi());
	                if (pe != null) {
	                	PsiElement[] resolvedParameters = pe.getChildren();
                		for (PsiElement parameter : resolvedParameters) {
                			IElementType type = parameter.getNode().getElementType();
                			if (type.toString().equals("LITERAL_EXPRESSION") && parameter.getText().toUpperCase().equals("\"" + L_WEAKHASHALGO + "\"")) {
                				context.report(ISSUE, parameter, context.getLocation(parameter), LINT_MSG);
                				return;
		        			}
                		}
	                }
        		}
            }
        };
    }
}
