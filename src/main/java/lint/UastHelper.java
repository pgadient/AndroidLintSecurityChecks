/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Pascal Gadient et al. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for the license information.
 *--------------------------------------------------------------------------------------------*/

package lint;

import com.android.annotations.NonNull;
import com.android.annotations.Nullable;
import com.android.tools.lint.detector.api.UastLintUtils;
import com.intellij.psi.PsiElement;
import com.intellij.psi.PsiType;
import com.intellij.psi.PsiVariable;

import org.jetbrains.uast.UCallExpression;
import org.jetbrains.uast.UExpression;
import org.jetbrains.uast.USimpleNameReferenceExpression;
import org.jetbrains.uast.UastUtils;

/**
 * Helper class for Uast manipulations.
 * 
 * @author Patrick Frischknecht
 * 
 * University of Bern
 * Software Composition Group
 * 
 */
class UastHelper {

    static boolean methodHasName(@NonNull UCallExpression methodCall, @Nullable String expectedMethodName) {
        String methodName = methodCall.getMethodName();
        return methodName != null && methodName.equals(expectedMethodName);
    }

    static boolean hasClassOrSuperClass(PsiType type, String qualifiedClassName)
    {
        if(type == null)
            return false;
        if(type.getCanonicalText().equals(qualifiedClassName))
            return true;
        PsiType[] superTypes = type.getSuperTypes();
        for(PsiType superType : superTypes){
            if(superType.getCanonicalText().equals(qualifiedClassName))
                return true;
        }
        return false;
    }

    static UExpression getLastAssignedExpression(@Nullable UExpression variable, @Nullable UCallExpression call) {
        if (variable instanceof USimpleNameReferenceExpression) {
            PsiElement e = UastUtils.tryResolve(variable);
            if (e instanceof PsiVariable) {
                UExpression assignedValue = UastLintUtils.findLastAssignment((PsiVariable) e, call);
                if (assignedValue != null)
                    return assignedValue;
            }
        }
        return null;
    }
}
