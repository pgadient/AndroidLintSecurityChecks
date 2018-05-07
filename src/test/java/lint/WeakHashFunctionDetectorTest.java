package lint;

import com.android.tools.lint.checks.infrastructure.LintDetectorTest;
import com.android.tools.lint.detector.api.Detector;
import com.android.tools.lint.detector.api.Issue;
import com.android.tools.lint.detector.api.Severity;
import lint.WeakHashFunctionDetector;

import java.util.Collections;
import java.util.List;

import org.junit.Test;

public class WeakHashFunctionDetectorTest extends LintDetectorTest {
	@Test
    public void testMessageDigestCallWithWeakHashFunction() {
		lint().files(
                java("" +
                        "package test.pkg;\n" +
                        "import java.security.MessageDigest;\n" +
                        "import java.security.NoSuchAlgorithmException;\n" +
                        "public class TestClass1 {\n" +
                            "public static void main(String[] args){\n" +
                                "String password = \"15\";\n" +
                                "MessageDigest md5Digest = null;\n" +
                                "try {\n" +
                                    "md5Digest = MessageDigest.getInstance(\"MD5\");\n" +
                                "} catch (NoSuchAlgorithmException e) {\n" +
                                    "e.printStackTrace();\n" +
                                "}\n" +
                                "md5Digest.update(password.getBytes());\n" +
                                "byte[] hashValue = md5Digest.digest();\n" +
                                "}\n" +
                        "}"))
                .run()
                .expectCount(1, Severity.WARNING).expectMatches("MD5 is considered a weak hash function.");
    }

	@Test
    public void testQualifiedMessageDigestCallWithWeakHashFunction() {
        lint().files(
                java("" +
                        "package test.pkg;\n" +
                        "import java.security.MessageDigest;\n" +
                        "import java.security.NoSuchAlgorithmException;\n" +
                        "public class TestClass1 {\n" +
                        "public static void main(String[] args){\n" +
                        "String password = \"15\";\n" +
                        "java.security.MessageDigest md5Digest = null;\n" +
                        "try {\n" +
                        "md5Digest = java.security.MessageDigest.getInstance(\"MD5\");\n" +
                        "} catch (NoSuchAlgorithmException e) {\n" +
                        "e.printStackTrace();\n" +
                        "}\n" +
                        "md5Digest.update(password.getBytes());\n" +
                        "byte[] hashValue = md5Digest.digest();\n" +
                        "}\n" +
                        "}"))
                .run()
                .expectCount(1, Severity.WARNING).expectMatches("MD5 is considered a weak hash function.");
    }

	@Test
    public void testMessageDigestCallWithStrongHashFunction() {
		lint().files(
            java("" +
                    "package test.pkg;\n" +
                    "import java.security.MessageDigest;\n" +
                    "import java.security.NoSuchAlgorithmException;\n" +
                    "public class TestClass1 {\n" +
                    "public static void main(String[] args){\n" +
                    "String password = \"15\";\n" +
                    "java.security.MessageDigest md5Digest = null;\n" +
                    "try {\n" +
                    "md5Digest = java.security.MessageDigest.getInstance(\"SHA256\");\n" +
                    "} catch (NoSuchAlgorithmException e) {\n" +
                    "e.printStackTrace();\n" +
                    "}\n" +
                    "md5Digest.update(password.getBytes());\n" +
                    "byte[] hashValue = md5Digest.digest();\n" +
                    "}\n" +
                    "}"))
            .run()
            .expectCount(0);
    }

	@Test
    public void testMessageDigestCallWithWeakHashFunctionAsConstant() {
        lint().files(
                java("" +
                        "package test.pkg;\n" +
                        "import java.security.MessageDigest;\n" +
                        "import java.security.NoSuchAlgorithmException;\n" +
                        "public class TestClass1 {\n" +
                        "private static final String MD5 = \"MD5\";" +
                        "public static void main(String[] args){\n" +
                        "String password = \"15\";\n" +
                        "java.security.MessageDigest md5Digest = null;\n" +
                        "try {\n" +
                        "md5Digest = java.security.MessageDigest.getInstance(MD5);\n" +
                        "} catch (NoSuchAlgorithmException e) {\n" +
                        "e.printStackTrace();\n" +
                        "}\n" +
                        "md5Digest.update(password.getBytes());\n" +
                        "byte[] hashValue = md5Digest.digest();\n" +
                        "}\n" +
                        "}"))
                .run()
                .expectCount(1, Severity.WARNING).expectMatches("MD5 is considered a weak hash function.");
        ;
    }

    @Override
    protected Detector getDetector() {
        return new WeakHashFunctionDetector();
    }

    @Override
    protected List<Issue> getIssues() {
        return Collections.singletonList(WeakHashFunctionDetector.ISSUE);
    }
}
