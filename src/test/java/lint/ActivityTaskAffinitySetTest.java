package lint;

import com.android.tools.lint.checks.infrastructure.LintDetectorTest;
import com.android.tools.lint.detector.api.Detector;
import com.android.tools.lint.detector.api.Issue;
import com.android.tools.lint.detector.api.Severity;

import java.util.Collections;
import java.util.List;

import static com.android.SdkConstants.FN_ANDROID_MANIFEST_XML;

public class ActivityTaskAffinitySetTest extends LintDetectorTest {
    @Override
    protected Detector getDetector() {
        return new TaskAffinityDetector();
    }

    @Override
    protected List<Issue> getIssues() {
        return Collections.singletonList(TaskAffinityDetector.ACTIVITY_TASK_AFFINITY_SET);
    }

    public void testActivityHasTaskAffinity() {
        lint().files(
                xml(FN_ANDROID_MANIFEST_XML, "" +
                        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" +
                        "<manifest package=\"com.example.test.myapplication\"\n" +
                        "          xmlns:android=\"http://schemas.android.com/apk/res/android\">\n" +
                        "    <application>\n" +
                        "        <activity android:name=\"com.example.android.custom-lint-rules" +
                        ".OtherActivity\">\n" +
                        "        </activity>\n" +
                        "\n" +
                        "        <activity android:name=\"com.example.android.custom-lint-rules" +
                        ".MainActivity\" android:taskAffinity=\"com.android.settings\">\n" +
                        "            <intent-filter>\n" +
                        "                <action android:name=\"android.intent.action.MAIN\"/>\n" +
                        "                <category android:name=\"android.intent.category.LAUNCHER\"/>\n" +
                        "                <data android:scheme=\"myapp\" android:host=\"path\" />\n"+
                        "            </intent-filter>\n" +
                        "        </activity>\n" +
                        "    </application>\n" +
                        "</manifest>"))
                .run()
                .expectCount(2, Severity.WARNING).expectMatches(TaskAffinityDetector.ACTIVITY_TASK_AFFINITY_SET_MESSAGE);
    }

    public void testNoTaskAffinitySet() {
        lint().files(
                xml(FN_ANDROID_MANIFEST_XML, "" +
                        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" +
                        "<manifest package=\"com.example.test.myapplication\"\n" +
                        "          xmlns:android=\"http://schemas.android.com/apk/res/android\">\n" +
                        "    <application>\n" +
                        "        <activity android:name=\"com.example.android.custom-lint-rules" +
                        ".OtherActivity\">\n" +
                        "        </activity>\n" +
                        "\n" +
                        "        <activity android:name=\"com.example.android.custom-lint-rules" +
                        ".MainActivity\">\n" +
                        "            <intent-filter>\n" +
                        "                <action android:name=\"android.intent.action.MAIN\"/>\n" +
                        "                <category android:name=\"android.intent.category.LAUNCHER\"/>\n" +
                        "            </intent-filter>\n" +
                        "        </activity>\n" +
                        "    </application>\n" +
                        "</manifest>"))
                .run()
                .expectCount(1, Severity.WARNING).expectMatches(TaskAffinityDetector.APPLICATION_TASK_AFFINITY_NOT_EMPTY_MESSAGE);
    }
}
