# AndroidLintSecurityChecks

A lightweight static analysis tool on top of Android Lint that analyzes the code under development and provides *just-in-time* feedback within the **latest** Android Studio IDE about the presence of security smells in the code. Moreover, this tool supports *batch processing* for large scale app analysis.

> This is the accompanying material for our publication titled “Security Code Smells in Android ICC”.

## Build
Import the project in Eclipse Java (untested in other IDEs) and create a run configuration that consists of the Gradle tasks `assemble`and `deploy`. By execution of these tasks the .jar file will get compiled and copied into the appropriate Android Studio directory (if existent). The tool is ready to use after completion.

## Manual Installation
The .jar file (available precompiled in the release folder) has to be copied into a specific folder:
* On *nix operating systems into `~/.android/lint/`
* On Windows Vista or newer into `C:\Users\CurrentUserProfile\.android\lint\`

## Usage
Android Studio will now detect just-in-time the smells in the code and lint them accordingly. A list of issues can be compiled through `Analyze` -> `Inspect Code` in the menu bar. In case of detections, each existent ICC code smell will be reported with its id and name (e.g. SM01: Persisted Dynamic Permission).

## Implemented Checks
The following ICC Security Code Smells are implemented:

Id|ICC Security Code Smell|Brief Description
:-:|:-:|-
SM01|Persisted Dynamic Permission|URI permissions granted through the context class have to be revoked explicitly
SM02|Custom Scheme Channel|Avoid using custom URI schemes
SM03|Incorrect Protection Level|The `android:protectionLevel` attribute is missing for a custom permission
SM04|Unauthorized Intent|Avoid sending implicit intents if possible
SM05|Sticky Broadcast|The usage of sticky broadcasts is strongly discouraged
SM06|Slack WebViewClient|The default `WebViewClient` does not perform any restrictions on web pages
SM07|Broken Service Permission|Self permission checks could fail
SM08|Insecure Path Permission|Avoid using path permission together with UriMatcher in a content provider
SM09|Broken Path Permission Precedence|Path permissions cannot be used to make certain provider paths more secure, if the provider already defines a permission
SM10|Unprotected Broadcast Receiver|A broadcast receiver is dynamically registered without any permission
SM11|Implicit Pending Intent|Using an implicit intent for a pending intent
SM12|Common Task Affinity|Consider setting the task affinity of your app explicitly to an empty value
