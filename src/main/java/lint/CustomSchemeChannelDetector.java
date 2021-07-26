/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Pascal Gadient et al. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for the license information.
 *--------------------------------------------------------------------------------------------*/

package lint;

import com.android.annotations.NonNull;
import com.android.annotations.VisibleForTesting;
import com.android.tools.lint.client.api.JavaEvaluator;
import com.android.tools.lint.detector.api.Category;
import com.android.tools.lint.detector.api.Detector;
import com.android.tools.lint.detector.api.Implementation;
import com.android.tools.lint.detector.api.Issue;
import com.android.tools.lint.detector.api.JavaContext;
import com.android.tools.lint.detector.api.LintUtils;
import com.android.tools.lint.detector.api.Scope;
import com.android.tools.lint.detector.api.Severity;
import com.android.tools.lint.detector.api.XmlContext;
import com.intellij.psi.PsiMethod;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.uast.UCallExpression;
import org.jetbrains.uast.UExpression;
import org.w3c.dom.Attr;
import org.w3c.dom.Element;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;

import javax.annotation.Nullable;

import static com.android.SdkConstants.ATTR_SCHEME;
import static com.android.SdkConstants.NS_RESOURCES;
import static com.android.SdkConstants.TAG_DATA;
import static com.android.SdkConstants.TAG_INTENT_FILTER;
import static lint.ConstantEvaluatorWrapper.resolveAsString;
// todo
/**
 * Detector for custom URI scheme intent filters in the manifest or within the code.
 * 
 * Example for manifest based intent filter:
 * <data android:scheme="custom" android:host=\"something" />
 * 
 * Example for code based intent filter:
 * addDataScheme(String scheme)
 * 
 * Scheme channels which are officially registered on the IANA list
 * (https://www.iana.org/assignments/uri-schemes/uri-schemes.xhtml#uri-schemes-1)
 * are ignored
 * 
 * @author Patrick Frischknecht
 * 
 * University of Bern
 * Software Composition Group
 * 
 */
public class CustomSchemeChannelDetector extends Detector implements Detector.UastScanner, Detector.XmlScanner {
    private static final String INTENT_FILTER_CLASS = "android.content.IntentFilter";
    @VisibleForTesting
    public static final String MESSAGE = "SM02: Custom Scheme Channel | Avoid using custom URI schemes";
    public static final Issue ISSUE = Issue.create(
            "CustomSchemeChannel",
            MESSAGE,
            "URI schemes offer a simple way to call your app from a website. " +
            " However any scheme channel can be registered by any app, also by malicious apps. Consequently, new custom URI schemes are" +
            " not mandatory unique, and other apps could use the same scheme as well" +
            " while introducing a conflict. In case of conflicts the user has the choose the intended app." +
            " The apps that provide a custom scheme handler could collect any information encoded in the URL." +
            " Use the intent scheme instead where the receiving app is explicitly" +
            " specified by its package name.",
            Category.SECURITY,
            5,
            Severity.WARNING,
            new Implementation(
                    CustomSchemeChannelDetector.class,
                    EnumSet.of(Scope.MANIFEST, Scope.JAVA_FILE)))
            .addMoreInfo("https://developer.chrome.com/multidevice/android/intents");

    @Override
    public Collection<String> getApplicableElements() {
        return Collections.singleton(TAG_INTENT_FILTER);
    }


    @Override
    // find scheme attributes in the manifest
    public void visitElement(@NotNull XmlContext context, @NotNull Element intentFilterElement) {
        List<Attr> schemaChannelAttrs = findSchemaChannelAttrs(intentFilterElement);
        // report each scheme channel attr in any data element of the intent filter
        for(Attr schemeAttr : schemaChannelAttrs) {
            // ignore schemes which are officially registered
            if (isCustomSchemeChannel(schemeAttr.getValue()))
                context.report(ISSUE, intentFilterElement, context.getLocation(schemeAttr), MESSAGE);
        }
    }

    // checks if the scheme is not on the offical iana list (and therfore custom)
    private boolean isCustomSchemeChannel(@Nullable String scheme){
        return !KNOWN_SCHEMES.contains(scheme);
    }

    @NonNull
    // finds all scheme attributes in all data children of a intent-filter element
    private List<Attr> findSchemaChannelAttrs(@NotNull Element intentFilterElement) {
        List<Attr> schemeAttrs = new ArrayList<>();
        for (Element intentFilterChild : LintUtils.getChildren(intentFilterElement)) {

            if (TAG_DATA.equals(intentFilterChild.getNodeName())) {
                // Always use this approach, a simple getAttributeNode("android:scheme") works in tests and console
                // but not in android studio. This is probably due to how the psi dom is converted to the dom used here
                Attr schemeAttribute = intentFilterChild.getAttributeNodeNS(NS_RESOURCES, ATTR_SCHEME);
                if (schemeAttribute != null) {
                    schemeAttrs.add(schemeAttribute);
                }
            }

        }

        return schemeAttrs;
    }

    @Override
    // find addDataScheme in the source code
    public void visitMethod(@NonNull JavaContext context, @NonNull UCallExpression call,
                            @NonNull PsiMethod method) {
        JavaEvaluator evaluator = context.getEvaluator();
        if(!evaluator.isMemberInSubClassOf(method, INTENT_FILTER_CLASS, false))
            return;

        if(containsCustomSchemeArgument(call.getValueArguments(), context))
            context.report(ISSUE, call, context.getLocation(call), MESSAGE);
    }

    // check if the argument list contains a scheme channel argument and if the scheme channel argument
    // is custom or not
    private boolean containsCustomSchemeArgument(@Nullable List<UExpression> argumentValueList, @NonNull JavaContext context) {
        if(argumentValueList == null || argumentValueList.size() != 1)
            return false;
        UExpression schemeArgument = argumentValueList.get(0);
        String registeredScheme = resolveAsString(schemeArgument, context);
        return registeredScheme != null && isCustomSchemeChannel(registeredScheme);
    }

    @Override
    public List<String> getApplicableMethodNames() {
        return Collections.singletonList("addDataScheme");
    }

    // Officially registered Uniform Resource Identifier (URI) Schemes
    // from the IANA webpage
    // https://www.iana.org/assignments/uri-schemes/uri-schemes.xhtml#uri-schemes-1
    // last updated at 2018-02-11
    private static final HashSet<String> KNOWN_SCHEMES = new HashSet<>(
            Arrays.asList("aaa",
                    "aaas",
                    "about",
                    "acap",
                    "acct",
                    "acr",
                    "adiumxtra",
                    "afp",
                    "afs",
                    "aim",
                    "appdata",
                    "apt",
                    "attachment",
                    "aw",
                    "barion",
                    "beshare",
                    "bitcoin",
                    "blob",
                    "bolo",
                    "browserext",
                    "callto",
                    "cap",
                    "chrome",
                    "chrome-extension",
                    "cid",
                    "coap",
                    "coap+tcp",
                    "coap+ws",
                    "coaps",
                    "coaps+tcp",
                    "coaps+ws",
                    "com-eventbrite-attendee",
                    "content",
                    "conti",
                    "crid",
                    "cvs",
                    "data",
                    "dav",
                    "diaspora",
                    "dict",
                    "dis",
                    "dlna-playcontainer",
                    "dlna-playsingle",
                    "dns",
                    "dntp",
                    "dtn",
                    "dvb",
                    "ed2k",
                    "example",
                    "facetime",
                    "fax",
                    "feed",
                    "feedready",
                    "file",
                    "filesystem",
                    "finger",
                    "fish",
                    "ftp",
                    "geo",
                    "gg",
                    "git",
                    "gizmoproject",
                    "go",
                    "gopher",
                    "graph",
                    "gtalk",
                    "h323",
                    "ham",
                    "hcp",
                    "http",
                    "https",
                    "hxxp",
                    "hxxps",
                    "hydrazone",
                    "iax",
                    "icap",
                    "icon",
                    "im",
                    "imap",
                    "info",
                    "iotdisco",
                    "ipn",
                    "ipp",
                    "ipps",
                    "irc",
                    "irc6",
                    "ircs",
                    "iris",
                    "iris.beep",
                    "iris.lwz",
                    "iris.xpc",
                    "iris.xpcs",
                    "isostore",
                    "itms",
                    "jabber",
                    "jar",
                    "jms",
                    "keyparc",
                    "lastfm",
                    "ldap",
                    "ldaps",
                    "lvlt",
                    "magnet",
                    "mailserver",
                    "mailto",
                    "maps",
                    "market",
                    "message",
                    "mid",
                    "mms",
                    "modem",
                    "mongodb",
                    "moz",
                    "ms-access",
                    "ms-browser-extension",
                    "ms-drive-to",
                    "ms-enrollment",
                    "ms-excel",
                    "ms-gamebarservices",
                    "ms-gamingoverlay",
                    "ms-getoffice",
                    "ms-help",
                    "ms-infopath",
                    "ms-inputapp",
                    "ms-lockscreencomponent-config",
                    "ms-media-stream-id",
                    "ms-mixedrealitycapture",
                    "ms-officeapp",
                    "ms-people",
                    "ms-project",
                    "ms-powerpoint",
                    "ms-publisher",
                    "ms-restoretabcompanion",
                    "ms-search-repair",
                    "ms-secondary-screen-controller",
                    "ms-secondary-screen-setup",
                    "ms-settings",
                    "ms-settings-airplanemode",
                    "ms-settings-bluetooth",
                    "ms-settings-camera",
                    "ms-settings-cellular",
                    "ms-settings-cloudstorage",
                    "ms-settings-connectabledevices",
                    "ms-settings-displays-topology",
                    "ms-settings-emailandaccounts",
                    "ms-settings-language",
                    "ms-settings-location",
                    "ms-settings-lock",
                    "ms-settings-nfctransactions",
                    "ms-settings-notifications",
                    "ms-settings-power",
                    "ms-settings-privacy",
                    "ms-settings-proximity",
                    "ms-settings-screenrotation",
                    "ms-settings-wifi",
                    "ms-settings-workplace",
                    "ms-spd",
                    "ms-sttoverlay",
                    "ms-transit-to",
                    "ms-useractivityset",
                    "ms-virtualtouchpad",
                    "ms-visio",
                    "ms-walk-to",
                    "ms-whiteboard",
                    "ms-whiteboard-cmd",
                    "ms-word",
                    "msnim",
                    "msrp",
                    "msrps",
                    "mtqp",
                    "mumble",
                    "mupdate",
                    "mvn",
                    "news",
                    "nfs",
                    "ni",
                    "nih",
                    "nntp",
                    "notes",
                    "ocf",
                    "oid",
                    "onenote",
                    "onenote-cmd",
                    "opaquelocktoken",
                    "pack",
                    "palm",
                    "paparazzi",
                    "pkcs11",
                    "platform",
                    "pop",
                    "pres",
                    "prospero",
                    "proxy",
                    "pwid",
                    "psyc",
                    "qb",
                    "query",
                    "redis",
                    "rediss",
                    "reload",
                    "res",
                    "resource",
                    "rmi",
                    "rsync",
                    "rtmfp",
                    "rtmp",
                    "rtsp",
                    "rtsps",
                    "rtspu",
                    "secondlife",
                    "service",
                    "session",
                    "sftp",
                    "sgn",
                    "shttp",
                    "sieve",
                    "sip",
                    "sips",
                    "skype",
                    "smb",
                    "sms",
                    "smtp",
                    "snews",
                    "snmp",
                    "soap.beep",
                    "soap.beeps",
                    "soldat",
                    "spotify",
                    "ssh",
                    "steam",
                    "stun",
                    "stuns",
                    "submit",
                    "svn",
                    "tag",
                    "teamspeak",
                    "tel",
                    "teliaeid",
                    "telnet",
                    "tftp",
                    "things",
                    "thismessage",
                    "tip",
                    "tn3270",
                    "tool",
                    "turn",
                    "turns",
                    "tv",
                    "udp",
                    "unreal",
                    "urn",
                    "ut2004",
                    "v-event",
                    "vemmi",
                    "ventrilo",
                    "videotex",
                    "vnc",
                    "view-source",
                    "wais",
                    "webcal",
                    "wpid",
                    "ws",
                    "wss",
                    "wtai",
                    "wyciwyg",
                    "xcon",
                    "xcon-userid",
                    "xfire",
                    "xmlrpc.beep",
                    "xmlrpc.beeps",
                    "xmpp",
                    "xri",
                    "ymsgr",
                    "z39.50",
                    "z39.50r",
                    "z39.50s"));

}
