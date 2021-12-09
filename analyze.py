"""
RQ1: Do applications take input from other apps, and
use it without sanitizing it?
RQ2: Do applications permission protect Services, Re-
ceivers, and Broadcast?
RQ3: Do applications export private data to the Net-
work?
RQ4: Do apps use HTTPS for network communication?
RQ5: Do apps verify certificates incorrectly?
RQ6: Do applications override TrustManagers?
RQ7: Do applications use implicit Intents?
RQ8: Do apps request more permissions than they use?
RQ9: Do applications call sensitive APIs?
"""
from lxml.etree import tostring
import sys
import androguard  #pip -U install androguard
from androguard import misc, core

android = "{http://schemas.android.com/apk/res/android}"

def permission_protected_services(a):
    receivers = a.get_receivers()
    xml = a.get_android_manifest_xml()
    receivers = xml.xpath("//receiver")
    for receiver in receivers:
        if android+"permission" not in receiver.attrib:
            print("receiver not permission protected: {}".format(receiver))
    
    #this gets the receivers in the manifest. .attrib is a dict with shit like android:permission
    #print(xml.xpath("//receiver")[0].attrib[android+"permission"])

def get_senesitive_api_calls():
    pass

def check_permission_usage():
    pass

def check_for_http(dx):
    try:
        for _, meth in dx.strings["http://"].get_xref_from():
            print("Used in: {} -- {}".format(meth.class_name, meth.name))
    except KeyError:
        print("http:// not used")

def find_implicit_intents():
    pass

def main():
    filename = sys.argv[1]
    a,d,dx = misc.AnalyzeAPK(filename)  # a -> apk object, d -> DalvikVMFormat object, dx -> Analysis object
    #print(dx.get_classes())
    check_for_http(dx)
    permission_protected_services(a)

if __name__ == "__main__":
    main()
