package lint;


import com.android.annotations.NonNull;
import com.android.annotations.VisibleForTesting;
import com.android.tools.lint.client.api.JavaEvaluator;
import com.android.tools.lint.client.api.UElementHandler;
import com.android.tools.lint.detector.api.Category;
import com.android.tools.lint.detector.api.Detector;
import com.android.tools.lint.detector.api.Implementation;
import com.android.tools.lint.detector.api.Issue;
import com.android.tools.lint.detector.api.JavaContext;
import com.android.tools.lint.detector.api.Scope;
import com.android.tools.lint.detector.api.Severity;
import com.intellij.psi.PsiMethod;

import org.jetbrains.uast.UCallExpression;
import org.jetbrains.uast.UElement;
import org.jetbrains.uast.UExpression;
import org.jetbrains.uast.UMethod;
import org.jetbrains.uast.visitor.AbstractUastVisitor;

import java.util.Collections;
import java.util.List;

import static lint.ConstantEvaluatorWrapper.resolveAsLong;
import static lint.ConstantEvaluatorWrapper.resolveAsString;
import static lint.UastHelper.methodHasName;

//todo
/**
 * Checks for the initialization of a RSA key pair generator with a key size lower than 2048
 * bits.
 *
 * Note that this check is limited to key pair generators created and initialized within the
 * same method.
 * 
 * @author Patrick Frischknecht
 * 
 * University of Bern
 * Software Composition Group
 * 
 */
public class InsufficientRSAKeySizeDetector extends Detector implements Detector.UastScanner {

    private static final String KEY_PAIR_GENERATOR = "java.security.KeyPairGenerator";
    private static final String GET_INSTANCE = "getInstance";
    private static final String INITIALIZE = "initialize";
    private static final int MIN_KEY_SIZE = 2048;
    @VisibleForTesting
    public static final String MESSAGE = "RSA should be initialized with a key size of at least 2048 bits";

    public static final Issue ISSUE = Issue.create("InsufficientRSAKeySize", //$NON-NLS-1$
            "SM00: Insufficient RSA KeySize | Using RSA with a key size lower than " + MIN_KEY_SIZE + " bits",
            
            "It is recommended to use a key size of at least 2048 bits for the RSA algorithm" +
                    " to ensure a minimal level of security.",
            Category.SECURITY,
            6,
            Severity.WARNING,
            new Implementation(
                    InsufficientRSAKeySizeDetector.class,
                    Scope.JAVA_FILE_SCOPE))
            .addMoreInfo("http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57Pt3r1.pdf");

    @Override
    public UElementHandler createUastHandler(JavaContext context) {
        return new VisitorToMethodPasser(context);
    }

    @Override
    public List<Class<? extends UElement>> getApplicableUastTypes() {
        return Collections.singletonList(UMethod.class);
    }

    // Ugly workaround to use a visitor (which can easily visit different elements)
    // instead of a UElementVisitor (which can only visit one element type or the
    // reimplementation of many methods is required).
    // According to UElementHandler this is the proposed approach
    // (creating a handler to create a visitor).
    private class  VisitorToMethodPasser extends UElementHandler{
        private JavaContext context;

        public VisitorToMethodPasser(JavaContext context){
            this.context = context;
        }
        @Override
        public void visitMethod(UMethod uMethod) {
            uMethod.accept(new InsufficientRSAKeySizeVisitor(context));
        }
    }


    private class InsufficientRSAKeySizeVisitor extends AbstractUastVisitor {
        private boolean foundGetInstance = false;
        private UCallExpression lowKeySizeInitializeCall = null;
        private JavaContext context;

        private InsufficientRSAKeySizeVisitor(@NonNull JavaContext context) {
            this.context = context;
        }


        @Override
        public boolean visitCallExpression(@NonNull UCallExpression methodInvocation) {
            checkIsGettingRSAInstance(methodInvocation);
            checkSetsRSAKeySize(methodInvocation);
            return super.visitCallExpression(methodInvocation);
        }

        private void checkIsGettingRSAInstance(@NonNull UCallExpression methodInvocation) {
            PsiMethod resolvedMethod = methodInvocation.resolve();
            JavaEvaluator evaluator = context.getEvaluator();
            if (resolvedMethod == null ||
                    !evaluator.isMemberInSubClassOf(resolvedMethod, KEY_PAIR_GENERATOR, false) ||
                    !methodHasName(methodInvocation, GET_INSTANCE))
                return;
            List<UExpression> argumentList = methodInvocation.getValueArguments();
            if ((argumentList.size() == 1 || argumentList.size() == 2)) {
                UExpression expression = argumentList.get(0);
                String argument = resolveAsString(expression, context);
                if (argument != null && argument.toUpperCase().startsWith("RSA")) {
                    foundGetInstance = true;
                }
            }
        }

        private void checkSetsRSAKeySize(@NonNull UCallExpression methodInvocation) {
            JavaEvaluator evaluator= context.getEvaluator();
            PsiMethod resolvedMethod = methodInvocation.resolve();
            if (resolvedMethod == null ||
                    !evaluator.isMemberInSubClassOf(resolvedMethod, KEY_PAIR_GENERATOR, false) ||
                    !methodHasName(methodInvocation, INITIALIZE))
                return;
            List<UExpression> argumentList = methodInvocation.getValueArguments();
            if (argumentList.size() == 1) {
                UExpression expression = argumentList.get(0);
                Long value = resolveAsLong(expression, context);
                if (value != null && value < MIN_KEY_SIZE) {
                    lowKeySizeInitializeCall = methodInvocation;
                }
            }
        }


        @Override
        public void afterVisitMethod(@NonNull UMethod methodDeclaration) {
            if (foundGetInstance && lowKeySizeInitializeCall != null) {
                context.report(ISSUE, lowKeySizeInitializeCall, context.getLocation(lowKeySizeInitializeCall), MESSAGE);
            }
            foundGetInstance = false;
            lowKeySizeInitializeCall = null;
        }

    }
}
