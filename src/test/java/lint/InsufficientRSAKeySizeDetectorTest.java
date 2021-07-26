/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Pascal Gadient et al. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for the license information.
 *--------------------------------------------------------------------------------------------*/

package lint;

import com.android.tools.lint.checks.infrastructure.LintDetectorTest;
import com.android.tools.lint.detector.api.Detector;
import com.android.tools.lint.detector.api.Issue;
import com.android.tools.lint.detector.api.Severity;
import lint.InsufficientRSAKeySizeDetector;

import java.util.Collections;
import java.util.List;

public class InsufficientRSAKeySizeDetectorTest extends LintDetectorTest {
    public void testRSAWithInsufficentBits() {
        lint().files(
                java("" +
                        "package test.pkg;\n" +
                        "import java.security.KeyPair;"+
                        "import java.security.KeyPairGenerator;\n"+
                        "import java.security.NoSuchAlgorithmException;\n"+
                        "import java.security.NoSuchProviderException;\n"+
                        "public class TestClass1 {\n" +
                            "KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {\n" +
                                "KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(\"RSA\", \"BC\");\n" +
                                "keyPairGenerator.initialize(1024);\n" +
                                "return keyPairGenerator.generateKeyPair();\n" +
                            "}\n" +
                        "}"))
                .run()
                .expectCount(1, Severity.WARNING).expectMatches(InsufficientRSAKeySizeDetector.MESSAGE);
    }

    public void testRSAWithEnoughBits() {
        lint().files(
                java("" +
                        "package test.pkg;\n" +
                        "import java.security.KeyPair;"+
                        "import java.security.KeyPairGenerator;\n"+
                        "import java.security.NoSuchAlgorithmException;\n"+
                        "import java.security.NoSuchProviderException;\n"+
                        "public class TestClass1 {\n" +
                            "KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {\n" +
                                "KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(\"RSA\");\n" +
                                "keyPairGenerator.initialize(2048);\n" +
                                "return keyPairGenerator.generateKeyPair();\n" +
                            "}\n" +
                        "}"))
                .run()
                .expectCount(0);
    }

    public void testDifferentAlgorithm() {
        lint().files(
                java("" +
                        "package test.pkg;\n" +
                        "import java.security.KeyPair;"+
                        "import java.security.KeyPairGenerator;\n"+
                        "import java.security.NoSuchAlgorithmException;\n"+
                        "import java.security.NoSuchProviderException;\n"+
                        "public class TestClass1 {\n" +
                            "KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {\n" +
                                "KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(\"DiffieHellman\");\n" +
                                "keyPairGenerator.initialize(1024);\n" +
                                "return keyPairGenerator.generateKeyPair();\n" +
                            "}\n" +
                        "}"))
                .run()
                .expectCount(0);
    }

    public void testRSAWithInsufficentBitsWithConstant() {
        lint().files(
                java("" +
                        "package test.pkg;\n" +
                        "import java.security.KeyPair;"+
                        "import java.security.KeyPairGenerator;\n"+
                        "import java.security.NoSuchAlgorithmException;\n"+
                        "import java.security.NoSuchProviderException;\n"+
                        "public class TestClass1 {\n" +
                            "private static final String RSA = \"RSA\";\n"+
                            "private static final int KEY_SIZE = 1024;\n"+
                            "KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {\n" +
                                "KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA, \"BC\");\n" +
                                "keyPairGenerator.initialize(KEY_SIZE);\n" +
                                "return keyPairGenerator.generateKeyPair();\n" +
                            "}\n" +
                        "}"))
                .run()
                .expectCount(1, Severity.WARNING).expectMatches(InsufficientRSAKeySizeDetector.MESSAGE);
    }

    @Override
    protected Detector getDetector() {
        return new InsufficientRSAKeySizeDetector();
    }

    @Override
    protected List<Issue> getIssues() {
        return Collections.singletonList(InsufficientRSAKeySizeDetector.ISSUE);
    }
}
