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

import java.util.Arrays;
import java.util.Collection;

import javax.annotation.Nullable;

import static com.android.SdkConstants.NS_RESOURCES;
import static com.android.SdkConstants.TAG_ACTIVITY;
import static com.android.SdkConstants.TAG_APPLICATION;

/**
 * This detector covers taskAffinity issues:
 * - Warnings will be supplied when an activity already has a task affinity set
 * 
 * We recommend to set the task affinity of the application to an empty value,
 * since this can prevent different attacks such as phishing or denial of service.
 *   
 * @author Patrick Frischknecht
 * 
 * University of Bern
 * Software Composition Group
 * 
 */
public class TaskAffinityDetector extends Detector implements Detector.XmlScanner {

    private static final String ATTR_TASK_AFFINITY = "taskAffinity";
    @VisibleForTesting
    public static final String ACTIVITY_TASK_AFFINITY_SET_MESSAGE = "SM12: Common Task Affinity | Do not set taskAffinity";

    public static final Issue ACTIVITY_TASK_AFFINITY_SET = Issue.create(
            "CommonTaskAffinity",
            ACTIVITY_TASK_AFFINITY_SET_MESSAGE,
            
            "The task affinity determines to which task an activity belongs." +
            " By default, the task affinity is set to the package name, such that" +
            " all activities in an app share the same affinity. If the affinity is set explicitly" +
            " the activity preferably joins a task with the given task affinity. While" +
            " this behaviour may be desired for some cases it can be abused by malware." +
            " Furthermore, there is a chance that a custom task affinity may unintentionally" +
            " conflict with the task affinity of another app.",
            Category.SECURITY,
            5,
            Severity.WARNING,
            new Implementation(
                    TaskAffinityDetector.class,
                    Scope.MANIFEST_SCOPE))
            .addMoreInfo("https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-ren-chuangang.pdf")
            .addMoreInfo("https://bitbucket.org/secure-it-i/android-app-vulnerability-benchmarks/wiki/Using%20Task%20Affinity%20to%20launch%20Denial-of-service%20or%20Phishing%20attacks%20in%20Android")
            .addMoreInfo("http://www.jssec.org/dl/android_securecoding_en.pdf");

    @VisibleForTesting
    public static final String APPLICATION_TASK_AFFINITY_NOT_EMPTY_MESSAGE =
            "SM12: Common Task Affinity | Consider setting the task affinity of your app explicitly to an empty value";

    public static final Issue APPLICATION_TASK_AFFINITY_NOT_EMPTY = Issue.create(
            "CommonTaskAffinity",
            APPLICATION_TASK_AFFINITY_NOT_EMPTY_MESSAGE,
            
            "The application's task affinity should be set to an empty value," +
            " because any other application could set its task affinity to any specific value." +
            " Non-empty task affinity values allow malicious apps to start various kinds of phishing and denial of service attacks." +
            " With an empty task affinity the app will get a unique task affinity at run time, " +
            " that is not shared with other apps. This makes it impossible for other apps" +
            " to attach.",
            Category.SECURITY,
            5,
            Severity.WARNING,
            new Implementation(
                    TaskAffinityDetector.class,
                    Scope.MANIFEST_SCOPE))
            .addMoreInfo("https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-ren-chuangang.pdf")
            .addMoreInfo("https://bitbucket.org/secure-it-i/android-app-vulnerability-benchmarks/wiki/Using%20Task%20Affinity%20to%20launch%20Denial-of-service%20or%20Phishing%20attacks%20in%20Android");

    @Override
    public Collection<String> getApplicableElements() {
        return Arrays.asList(TAG_ACTIVITY, TAG_APPLICATION);
    }

    @Override
    public void visitElement(@NonNull XmlContext context, @NonNull Element element) {
        Attr taskAffinityAttr = findTaskAffinityAttr(element);
        if(isApplicationNode(element)){
            if(taskAffinityAttr == null || !taskAffinityAttr.getValue().equals("")) {
                context.report(APPLICATION_TASK_AFFINITY_NOT_EMPTY, element, context.getLocation(element), APPLICATION_TASK_AFFINITY_NOT_EMPTY_MESSAGE);
            }
        }
        else {
            if (taskAffinityAttr != null) {
                context.report(ACTIVITY_TASK_AFFINITY_SET, taskAffinityAttr, context.getLocation(taskAffinityAttr), ACTIVITY_TASK_AFFINITY_SET_MESSAGE);
            }
        }
    }

    private boolean isApplicationNode(@NonNull Element element){
        return element.getTagName().equals(TAG_APPLICATION);
    }

    @Nullable
    private Attr findTaskAffinityAttr(@NonNull Element activityElement) {

        Attr taskAffinityAttribute = activityElement.getAttributeNodeNS(NS_RESOURCES, ATTR_TASK_AFFINITY);
        if (taskAffinityAttribute != null) {
            return taskAffinityAttribute;
        }
        return null;

    }

}
