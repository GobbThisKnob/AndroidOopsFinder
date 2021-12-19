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
import sys, os, glob, subprocess, _thread, time
import androguard  #pip -U install androguard
from androguard import misc, core
from lxml import etree


android = "{http://schemas.android.com/apk/res/android}"
dangerous_permissions = "READ_CALENDAR,WRITE_CALENDAR,CAMERA,READ_CONTACTS,WRITE_CONTACTS,GET_ACCOUNTS,ACCESS_FINE_LOCATION,ACCESS_COARSE_LOCATION,RECORD_AUDIO,READ_PHONE_STATE,READ_PHONE_NUMBERS,CALL_PHONE,ANSWER_PHONE_CALLS,READ_CALL_LOG,WRITE_CALL_LOG,ADD_VOICEMAIL,USE_SIP,PROCESS_OUTGOING_CALLS,BODY_SENSORS,SEND_SMS,RECEIVE_SMS,READ_SMS,RECEIVE_WAP_PUSH,RECEIVE_MMS,ACCESS_WIFI_STATE,CHANGE_NETWORK_STATE,BLUETOOTH,CHANGE_WIFI_STATE,INTERNET".split(',')
count = 0

def permission_protected_services(a):
    xml = a.get_android_manifest_xml()
    receivers = xml.xpath("//receiver")
    print("receivers not protected:")
    for receiver in receivers:
        if android+"permission" not in receiver.attrib:
            global count
            count = count + 1
            print(receiver)
    
    #this gets the receivers in the manifest. .attrib is a dict with shit like android:permission
    #print(xml.xpath("//receiver")[0].attrib[android+"permission"])

def get_senesitive_api_calls(a):
    dp = []
    app_permissions = a.get_permissions()
    print("dangerous permissions in app:")
    for dangerous_permission in dangerous_permissions:
        if "android.permission."+ dangerous_permission in app_permissions:
            global count
            count = count + 1
            # print(dangerous_permission)
            dp.append(dangerous_permission)
    return dp

# def check_permission_usage():
#     pass

def override_TrustManagers(dx):
    for c in dx.get_classes():
        if c.is_external():
            continue

        if 'Ljavax/net/ssl/X509TrustManager;' in c.orig_class.interfaces:
            global count
            count = count + 1
            # print(c.orig_class.get_name())
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
            global count
            count = count + 1
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

def export_data(apk):
    home = subprocess.check_output("echo $HOME", shell=True, text=True).strip()
    command = "java -jar soot-infoflow-cmd-2.9.0-jar-with-dependencies.jar --apkfile={} -p {} -s FlowDroid/soot-infoflow-android/SourcesAndSinks.txt".format(apk, home + "/Android/Sdk/platforms")
    # print(command)
    # result = subprocess.run(['java', '-jar', 'soot-infoflow-cmd-2.9.0-jar-with-dependencies.jar', 
    #     '--apkfile={}'.format(apk), '-p', home + '/Android/Sdk/platforms', '-s', 
    #     'FlowDroid/soot-infoflow-android/SourcesAndSinks.txt'], shell=True)
    # return subprocess.check_output(command, shell=True, text=True)   
    # return result.stdout
    subprocess.check_output("sh flowdroid.sh {} {}".format(apk, home + "/Android/Sdk/platforms"), shell=True, text=True)

def main():
    # I have my apks in a folder in the same directory as the program
    # We can change how we iterate through the apks if you want
    http = []
    leaks = []
    receivers = []
    permis = []
    trust = []

    if not os.path.exists("./FlowDroid"):
        os.system("git clone https://github.com/secure-software-engineering/FlowDroid.git")
    apks = glob.glob(sys.argv[1] + '*.apk')
    def analyze(apks, i, j):
        for n in range(i,j):
            export_data(apks[n])
            try:
                with open("./leaks.xml", "r") as xml:
                    tree = etree.fromstring(xml.read().encode('utf-8'))
                    print("Leaks: ", tree.xpath('count(//Result)'))
                    leaks.append(tree.xpath('count(//Result)'))
            except:
                pass
            os.system('rm leaks.xml')
        print("Leaks = ", leaks)

    try:
        _thread.start_new_thread(analyze, (apks, 0, 13))
        _thread.start_new_thread(analyze, (apks,13, 25))
        _thread.start_new_thread(analyze, (apks, 25, 38))
    except:
        print("Thread no worky")

    analyze2(apks, http, leaks, receivers, permis, trust)
    

def analyze2(apks, http, leaks, receivers, permis, trust):
    for apk in apks:
        global count
        count =0
        a,d,dx = misc.AnalyzeAPK(apk)  # a -> apk object, d -> DalvikVMFormat object, dx -> Analysis object

        print(apk)
        check_for_http(dx)
        print("http misuse: ", count)
        http.append(count)
        count=0

        permission_protected_services(a)
        print("Unprotected services: ", count)
        receivers.append(count)
        count=0

        dp = get_senesitive_api_calls(a)
        print("Dangerous permissions: ", count, dp)
        permis.append(count)
        count=0

        override_TrustManagers(dx)
        print("TrustManagers: ", count)
        trust.append(count)
        count =  0
        
        print()
    print("Leaks: ", leaks)
    print("Permissions: ", permis)
    print("Receivers: ", receivers)
    print("http: ", http)
    print("Trust: ", trust)

if __name__ == "__main__":
    main()
