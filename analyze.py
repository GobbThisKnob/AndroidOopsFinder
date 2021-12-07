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

import sys
import androguard  #pip -U install androguard
from androguard import misc, core

def permission_protected_services():
    pass

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

if __name__ == "__main__":
    main()
