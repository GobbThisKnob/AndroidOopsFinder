"""
RQ1: Do applications take input from other apps, and
use it without sanitizing it?
--Q2: Do applications permission protect Services, Re-
ceivers, and Broadcast?
RQ3: Do applications export private data to the Net-
work?
--RQ4: Do apps use HTTPS for network communication?
--RQ5: Do apps verify certificates incorrectly?
--RQ6: Do applications override TrustManagers?
RQ7: Do applications use implicit Intents?
RQ8: Do apps request more permissions than they use?
--RQ9: Do applications call sensitive APIs?
"""
from lxml.etree import tostring
import sys, os, glob
import androguard  #pip -U install androguard
from androguard import misc, core

android = "{http://schemas.android.com/apk/res/android}"
dangerous_permissions = "READ_CALENDAR,WRITE_CALENDAR,CAMERA,READ_CONTACTS,WRITE_CONTACTS,GET_ACCOUNTS,ACCESS_FINE_LOCATION,ACCESS_COARSE_LOCATION,RECORD_AUDIO,READ_PHONE_STATE,READ_PHONE_NUMBERS,CALL_PHONE,ANSWER_PHONE_CALLS,READ_CALL_LOG,WRITE_CALL_LOG,ADD_VOICEMAIL,USE_SIP,PROCESS_OUTGOING_CALLS,BODY_SENSORS,SEND_SMS,RECEIVE_SMS,READ_SMS,RECEIVE_WAP_PUSH,RECEIVE_MMS,ACCESS_WIFI_STATE,CHANGE_NETWORK_STATE,BLUETOOTH,CHANGE_WIFI_STATE,INTERNET".split(',')

def permission_protected_services(a):
    xml = a.get_android_manifest_xml()
    receivers = xml.xpath("//receiver")
    print("receivers not protected:")
    for receiver in receivers:
        if android+"permission" not in receiver.attrib:
            print(receiver)
    
    #this gets the receivers in the manifest. .attrib is a dict with shit like android:permission
    #print(xml.xpath("//receiver")[0].attrib[android+"permission"])

def get_senesitive_api_calls(a):
    app_permissions = a.get_permissions()
    print("dangerous permissions in app:")
    for dangerous_permission in dangerous_permissions:
        if "android.permission."+ dangerous_permission in app_permissions:
            print(dangerous_permission)

# def check_permission_usage():
#     pass

def override_TrustManagers(dx):
    for c in dx.get_classes():
        if c.is_external():
            continue

        if 'Ljavax/net/ssl/X509TrustManager;' in c.orig_class.interfaces:
            print(c.orig_class.get_name())
    # print("Usage of TrustManager")
    # try:
    #     dx.find_classes("Ljavax/net/ssl/X509TrustManager;")
    # except KeyError:
    #     print("No TrustManagers overridden")

def check_for_http(dx):
    print("incorrect usage of http://:")
    try:
        # print(dx.strings["http://"])
        for _, meth in dx.strings["http://"].get_xref_from():
            print("Used in class: {} -- method: {}".format(meth.class_name, meth.name))
    except KeyError:
        print("http:// not used")

# def find_implicit_intents(dx):
#     for c in dx.get_classes():
#         if c.is_external():
#             continue

#         fields = [typ.get_class_name()for typ in c.orig_class.get_fields()]
#         if 'Landroid/content/Intent;' in fields:
#             print("Implicit: ", fields)
def export_data(dx, apk):
    os.system("java -jar soot-infoflow-cmd-2.9.0-jar-with-dependencies.jar --apkfile={} -p {} -s FlowDroid/soot-infoflow-android/SourcesAndSinks.txt".format(apk, str(os.system("echo $HOME")) + "/Android/Sdk/platforms"))

def main():
    # I have my apks in a folder in the same directory as the program
    # We can change how we iterate through the apks if you want
    if not os.path.exists("./FlowDroid"):
        os.system("git clone https://github.com/secure-software-engineering/FlowDroid.git")
    apks = glob.glob(sys.argv[1] + '*.apk')
    for apk in apks:
        a,d,dx = misc.AnalyzeAPK(apk)  # a -> apk object, d -> DalvikVMFormat object, dx -> Analysis object
    
        print(apk)
        check_for_http(dx)
        # override_TrustManagers(dx)
        # find_implicit_intents(dx)
        export_data(dx, apk)
        permission_protected_services(a)
        get_senesitive_api_calls(a)
        print()
    
    """filename = sys.argv[1]
    a,d,dx = misc.AnalyzeAPK(filename)  # a -> apk object, d -> DalvikVMFormat object, dx -> Analysis object
    
    check_for_http(dx)
    permission_protected_services(a)
    get_senesitive_api_calls(a)"""

if __name__ == "__main__":
    main()
