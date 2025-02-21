"""
CompareLocalSBOMWithRemote.py

This class is meant to use CompareSBOMs to compare remote items

@Author Nicolette Glut
File Created On 2-18-2025
"""

import os
import requests
import json
import sys
from deepdiff import DeepDiff
import copy
import random
from SBOM import SBOM
from CompareSBOMs import CompareSBOMs



class CompareLocalSBOMWithRemote:
    """

    """
    def __init__(self, file):
        self.file= file
        with open(self.file, 'r') as file:
                self.fileContents = json.load(file)
        



    def makeLocalFileRemote(self):
        """
                Finds the remote of the saved local SBOM file
        """

        data=[]
        name=self.fileContents['sbom']['name']
        remotepart=name.split(".")[2]
        return "https://github.com/"+ remotepart
       
    def getFileContents(self):
        """
                Returns the file contents
        """
        return self.fileContents 
   



if __name__ == "__main__":
    if len(sys.argv) <= 1:
         print("No file given")
    test_SBOM = CompareLocalSBOMWithRemote(sys.argv[1])
    repo=test_SBOM.makeLocalFileRemote()
    print(repo)
    compare= CompareSBOMs(repo)
    compare.findTruthSBOMs()
    compare.setNonTruth(test_SBOM.getFileContents())
    compare.compareSBOMs()
