from __future__ import annotations
from collections import defaultdict
import re


def load_set(fpath):
    with open(fpath, "r") as file:
        my_list = [line.strip() for line in file]
    return set(my_list)


def isInCCADB(cert: defaultdict, ccadb:set) -> bool:
    corner_cases = ["Certification Authorities"]
    cert_o = cert.get("O", None)
    cert_cn = cert.get("CN", None)
    cert_ou = cert.get("OU", None)
    
    if cert_cn and "- G1" in cert_cn and cert_o and "\\E8\\A1\\8C\\E6\\94\\BF\\E9\\99\\A2" in cert_o:
        return True

    if cert_o and "Entrust" in cert_o:
        return True
    
    if cert_o and "U.S. Government" in cert_o:
        return True
    
    if cert_cn in corner_cases or cert_ou in corner_cases:
        if type(cert_o)!=str or "US FPKI" not in cert_o or "FPKI" not in cert_o:
            return False    

    if cert_cn in ccadb:
        return True
    if cert_ou in ccadb:
        return True
    return False

def isInTrustStore(cert: defaultdict, truststore:set) -> bool:
    cert_o = cert.get("O", None)
    cert_cn = cert.get("CN", None)
    cert_ou = cert.get("OU", None)

    if cert_cn in truststore:
        return True
    if cert_o in truststore:
        return True
    if cert_ou in truststore:
        return True
    return False

def isInWhitelist(cert: defaultdict, whitelist:set) -> bool:
    cert_o = cert.get("O", None)
    cert_cn = cert.get("CN", None)
    cert_ou = cert.get("OU", None)

    for i in whitelist:
        if cert_cn and (i in cert_cn.lower()):
            return True
        if cert_o and (i in cert_o.lower()):
            return True
        if cert_ou and (i in cert_ou.lower()):
            return True
    return False

def isInterception(cert: defaultdict, interception:set) -> bool:
    cert_o = cert.get("O", None)
    cert_cn = cert.get("CN", None)
    cert_ou = cert.get("OU", None)

    for i in interception:
        if cert_cn and (i in cert_cn.lower()):
            return True
        if cert_o and (i in cert_o.lower()):
            return True
        if cert_ou and (i in cert_ou.lower()):
            return True
    return False

class TrustStores:
    def __init__(self, certStores):
        self.ccadb = certStores["ccadb"]
        self.whitelist = certStores["whitelist"]
        self.truststore = certStores["truststore"]
        self.interception = certStores["interception"]
        self.peerCrossSigned = certStores["peerCrossSigned"]
        self.strictCrossSigned = certStores["strictCrossSigned"]