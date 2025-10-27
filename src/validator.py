from __future__ import annotations  # For forward references in type hints
import re
from collections import defaultdict
import ipaddress
from truststore import *

class CertValidator:
    
    def __init__(self, certStores: TrustStores):
        self.ccadb = certStores.ccadb
        self.whitelist = certStores.whitelist
        self.truststore = certStores.truststore
        self.interception = certStores.interception
        self.peerCrossSigned = certStores.peerCrossSigned
        self.strictCrossSigned = certStores.strictCrossSigned

    @staticmethod
    def isIPAddress(string):
        try:
            ip = ipaddress.ip_address(string)
            return True
        except:
            return False
    
    @staticmethod
    def isFqdn(string):
        # Regular expression for validating an FQDN
        fqdn_regex = re.compile(
            r'^(?:\*\.)?(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+\.?$'
        )
        if fqdn_regex.match(string):
            return True
        else:
            return False

    def isCrossSigned(self, string):
        if string in self.peerCrossSigned or string in self.strictCrossSigned:
            return True
        return False
    
    @staticmethod
    def parseCert(text):
        """Returns the cleaned text."""
        # Use regex to split by commas not preceded by a backslash
        parts = re.split(r'(?<!\\),', text)
       
        res_dict = defaultdict(str)
        for item in parts:
            
            item = item.replace('\\,', ',')
            item = item.strip()
            ## keep hex format \0f
            item = re.sub(r"\\(?![0-9a-fA-F]{2})", "", item)
            
            if "CN=" in item:
                res_dict["CN"] = item.removeprefix("CN=")
                continue
                
            if "O=" in item:
                res_dict["O"] = item.removeprefix("O=")
                continue
            
            if "C=" in item:
                res_dict["C"] = item.removeprefix("C=")
                continue
                
            if "OU=" in item:
                res_dict["OU"] = item.removeprefix("OU=")
                continue
        return res_dict
    
    def validate(self, cert: Cert, debug=False):
        status = defaultdict(str)
        
        issuer = self.parseCert(cert.issuer)
        subject = self.parseCert(cert.subject)
        subject_cn = subject.get("CN")
        
        #interception = CertStores.get("interception")
        #whitelist = CertStores.get("whitelist")
        #ccadb = CertStores.get("ccadb")
        #truststore = CertStores.get("truststore")
        
        #peerCrossSigned = CrossSigned.get("peer")
        #strictCrossSigned = CrossSigned.get("strict")
        
        if cert.issuer == cert.subject:
            status["isSelfSigned"] = True
        
        if subject_cn and (self.isIPAddress(subject_cn) or self.isFqdn(subject_cn)):
            status["isSubjectCNFQDN"]  = True
        
        if isInterception(issuer, self.interception):
            status["isInterception"] = True

        if isInCCADB(issuer, self.ccadb) or isInTrustStore(issuer, self.truststore) or isInWhitelist(issuer, self.whitelist):
            status["isPublic"] = True
        else:
            status["isPublic"] = False
            
        if self.isCrossSigned(cert.issuer):
            status["isIssuerCrossSigned"] = True
            
        if self.isCrossSigned(cert.subject):
            status["isSubjectCrossSigned"] = True
        
        if status.get("isSubjectCNFQDN", None):
            if status.get("isPublic", None):
                status["isPubLeaf"] = True
            else:
                status["isPrivLeaf"] = True
            
        if debug:
            print("Certificate Validation Status:")
            for key, value in status.items():
                print(f"{key}: {value}")
        
        return status
        
class ChainValidator:
    """
    Validator class to validate the chain of certificates.
    Currently just support bottom up, i.e. leaf to root validation. 
    """
    def __init__(self, certValidator:CertValidator):
        self.certValidator = certValidator
    
    def isCrossSignedPairs(self, current_issuer:str, next_subject:str) -> bool:
        if current_issuer in self.certValidator.peerCrossSigned and next_subject in self.certValidator.peerCrossSigned:
            return True
        if current_issuer in self.certValidator.strictCrossSigned and next_subject in self.certValidator.strictCrossSigned:
            return True
        return False
    
    def count_crossSignes(self, chain:Chain) -> int:
        crossSignes = 0
        current = chain.head
        crossSignes_idx = set()
        cnt = 0
        while current and current.next:
            # Check if the current cert's issuer matches the next cert's subject
            if self.isCrossSignedPairs(current.issuer, current.next.subject):
                crossSignes += 1
                crossSignes_idx.add(cnt)
                crossSignes_idx.add(cnt+1)
            current = current.next
            cnt += 1
        return crossSignes, crossSignes_idx
    
    def count_mismatches(self, chain: Chain) -> int:
        """Validate the chain and count mismatched cases."""
        mismatches = 0
        current = chain.head
        
        while current and current.next:
            # Check if the current cert's issuer matches the next cert's subject
            if current.issuer != current.next.subject and not self.isCrossSignedPairs(current.issuer, current.next.subject):
                mismatches += 1
            current = current.next
        return mismatches
    
    def print_mismatches_results(self,chain: Chain) -> None:
        """Print the validation results for the chain."""
        mismatches = self.count_mismatches(chain)
        total_pairs = chain.length - 1 
        print(f"Total certificates: {chain.length}")
        print(f"Total pairs: {total_pairs}")
        print(f"Mismatched pairs: {mismatches}")
        
        if mismatches == 0:
            print("The chain is fully valid!")
        else:
            print(f"The chain has {mismatches} (out of {total_pairs}) mismatched pair(s).")
            
    def get_certstatus_in_chain(self, chain: Chain) -> list:
        """Validate the chain and count mismatched cases."""
        chain_l = chain.to_list()
        
        res = []
        for cert in chain_l:
            status = self.certValidator.validate(cert)
            res.append(dict(status))
        return res
    

    def count_subchains(self, chain: Chain):
        """Count and identify valid subchains."""
        current = chain.head
        valid_subchains = []
        valid_subchain_count = 0
        in_valid_subchain = False
        
        chainidx = 0
        subchain = set()
        
        # till the last pair
        while current and current.next:
            # Check if the current cert's issuer matches the next cert's subject
            if current.issuer == current.next.subject or self.isCrossSignedPairs(current.issuer, current.next.subject):
                ## get valid subchain index
                subchain.add(chainidx) # head
                subchain.add(chainidx + 1) # tail
                
                if not in_valid_subchain:
                    # Start of a new valid subchain
                    in_valid_subchain = True
                    valid_subchain_count += 1
            else:
                # End the current valid subchain
                in_valid_subchain = False
                if len(subchain) > 1:
                    valid_subchains.append(subchain)
                subchain = set()
            current = current.next
            chainidx += 1
        # dealing with the last pair
        if len(subchain) > 1:
            valid_subchains.append(subchain)

        return valid_subchain_count, valid_subchains

    def print_subchains_count(self, chain:Chain):
        """Print the count of valid subchains."""
        count = self.count_subchains(chain)
        print(f"Total valid subchains: {count[0]}, Subchain index: {count[1]}")

        
    def count_leafs(self, chain: Chain, debug=False):
        """Count leaf certificate in subchains."""
        current = chain.head
        pub_idx = set()
        priv_idx = set()
        publeaf_cnt = 0
        privleaf_cnt = 0
        cnt = 0
        # till the last pair
        while current:
            cert_status = self.certValidator.validate(current, debug=debug)
            if cert_status.get("isPubLeaf", None):
                publeaf_cnt += 1
                pub_idx.add(cnt)
            elif cert_status.get("isPrivLeaf", None):
                privleaf_cnt += 1
                priv_idx.add(cnt)
            
            cnt += 1
            current = current.next

        return publeaf_cnt, pub_idx, privleaf_cnt, priv_idx
    
    def print_leaf_count(self, chain:Chain):
        """Print the count of valid subchains."""
        publeaf_cnt, pub_idx, privleaf_cnt, priv_idx = self.count_leafs(chain)
        print(f"Total Public Leaf Certificates: {publeaf_cnt}\nPublic Leaf Certificate index: {pub_idx}\n")
        print(f"Total Private Leaf Certificates: {privleaf_cnt}\nPrivate Leaf Certificate index: {priv_idx}\n")
    
        
    def isOnlySelfSigned(self, chain: Chain, debug=False):
        """Count leaf certificate in subchains."""
        current = chain.head
        cnt = 0
        # till the last pair
        if current and not current.next:
            certstatus = self.certValidator.validate(current, debug=debug)
            return certstatus.get("isSelfSigned", False)
        return False