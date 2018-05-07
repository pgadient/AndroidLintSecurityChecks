package lint;

import com.android.annotations.Nullable;
import com.android.tools.lint.detector.api.ConstantEvaluator;
import com.android.tools.lint.detector.api.JavaContext;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.uast.UExpression;

/**
 * Helper class for evaluating constants.
 * 
 * @author Patrick Frischknecht
 * 
 * University of Bern
 * Software Composition Group
 * 
 */
class ConstantEvaluatorWrapper {

    @Nullable
    static Long resolveAsLong(@Nullable UExpression expression, @NotNull JavaContext context) {
        ConstantEvaluator evaluator = new ConstantEvaluator();
        evaluator.allowFieldInitializers();

        Object value = expression.evaluate();
        if (value instanceof Long) {
            return (Long) value;
        }
        if (value instanceof Integer) {
            return new Long((Integer) value);
        }

        return null;
    }

    @Nullable
    static String resolveAsString(@Nullable UExpression expression, @NotNull JavaContext context) {
        ConstantEvaluator evaluator = new ConstantEvaluator();
        evaluator.allowFieldInitializers();
        Object value = evaluator.evaluate(expression);
        return value instanceof String ? (String)value : null;
    }

}