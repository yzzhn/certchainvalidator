from typing import List
import json


def isCompleteChain(subchain_cnt:int, allcert_matches:bool) -> bool:    
    if subchain_cnt == 1 and allcert_matches:        
        return True
    return False


def correct_leaf_count(isCompleteChain:bool, Leaf_total:int) -> int:
    if isCompleteChain:
        if Leaf_total == 0:
            return 1
        else:
            return Leaf_total
    return Leaf_total

def get_issuer_status(cert_chain_status:str) -> List[str]:
    res = []
    for status in json.loads(cert_chain_status):
        if status["isPublic"]:
            res.append("Pub")
        else:
            res.append("Priv")
    return res

def valid_subchain(subchains_idx, Leaf_idx):
    res = []
    subchain_l = []
    for subchains in subchains_idx:
        for cert in subchains:
            if cert in Leaf_idx:
                subchain_l.append(True)
            else:
                subchain_l.append(False)
        res.append(subchain_l)
        subchain_l=[]
    return res

def count_certs_in_subchains(index_l:List[set]) -> int:
    count = 0
    if index_l:
        for item in index_l:
            for idx in item:
                count += 1
    return count

def containCompleteChain(leaf_in_subchains, subchains_cnt):
    res = []
    if subchains_cnt < 1:
        return -1
    for subchains in leaf_in_subchains:
        filtered_items = [item for item in subchains if item == True]
        res.append(len(filtered_items)==1)
    return len([item for item in res if item == True])

def update_leafs(pub_leaf_idx:int, priv_leaf_idx:int) -> set:
    leaf_idx = set()
    leaf_idx.update(priv_leaf_idx)
    leaf_idx.update(pub_leaf_idx)
    return leaf_idx

def get_chain_category(issuer_pub_l):
    if all([i == "Pub" for i in issuer_pub_l]):
        return "AllPub"
    elif all([i == "Priv" for i in issuer_pub_l]):
        return "AllPriv"
    return "Hybrid"