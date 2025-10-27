from __future__ import annotations
from collections import defaultdict
import re

class Cert:
    """Simple Cert Class that just holds issuer and subject text info"""
    def __init__(self, datadict: defaultdict):
        self.issuer = datadict.get("Issuer", None)  
        self.subject = datadict.get("Subject", None)
        self.next = None  # Default next certificate is None

    def set_issuer(self, datadict):
        """Sets the issuer based on the provided dictionary."""
        self.issuer = datadict.get("Issuer", None)

    def set_subject(self, datadict):
        """Sets the subject based on the provided dictionary."""
        self.subject = datadict.get("Subject", None)
    
    def set_status(self):
        """Sets the next certificate in the chain."""
        if self.issuer == self.subject:
            self.status = "SelfSigned"

    def set_next(self, cert: Cert):
        """Sets the next certificate in the chain."""
        self.next = cert    
    
    def __repr__(self):
        """String representation for debugging."""
        return f"**** Begin Cert****\nIssuer: {self.issuer}\nSubject:{self.subject}\n**** End Cert ****"


class Chain:
    """
    Simple Chain Class represented by a singly linked list. 
    Currently only support bottom up, i.e. push leaf cert first. 
    This is consistent with using openssl to parse chain, leaf is first parsed.
    """
    def __init__(self):
        self.head = None  # Initialize the head of the list
        self.length = 0

    def append(self, data: defaultdict):
        """Add a new cert with the specified data to the end of the list."""
        new_cert = Cert(data)
        if not self.head:
            self.head = new_cert  # If the list is empty, set the head to the new node
            self.length += 1
            return
        current = self.head
        while current.next:  # Traverse to the end of the list
            current = current.next
        current.next = new_cert  # Link the last node to the new node
        self.length += 1

    def display(self, order="fromleaf"):
        """Display the linked list in the specified order."""
        if order == "fromleaf":
            # Print from leaf to root
            current = self.head
            cnt = 0
            while current:
                print(f"Cert # {cnt}: \n Subject: {current.subject} \n Issuer: {current.issuer} \n ", end=" ---> \n")
                current = current.next
                cnt += 1
            print("***End of Chain***")
        elif order == "fromroot":
            # Print from root (end) to head (reverse order)
            nodes = []
            current = self.head
            cnt = 0
            while current:
                nodes.append(current)
                current = current.next
                cnt += 1
            # Traverse the list in reverse order
            for node in reversed(nodes):
                print(f"Cert # {cnt}: \n Issuer: {node.issuer} \n Subject: {node.subject}\n", end=" ---> \n")
                cnt -= 1
            print("***End of Chain***")
        else:
            print("Invalid order specified. Use 'fromleaf' or 'fromroot'.")

    def __iter__(self):
        """Iterator to traverse the chain."""
        current = self.head
        while current:
            yield current
            current = current.next

    def get_length(self) -> int:
        """Calculate the length of the chain."""
        count = 0
        current = self.head
        while current:
            count += 1
            current = current.next
        return count
    
    def to_list(self) -> int:
        """Convert the linked list into an array"""
        current = self.head
        arr = []
        while current:
            arr.append(current)
            current = current.next
        return arr