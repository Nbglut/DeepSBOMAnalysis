"""
ToySBOMCompareExample.py

This class simply is a Toy Example of Comparing


@Author Nicolette Glut
File Created On 2-18-2025
"""

import os
import requests
import json
import sys
from SBOM import SBOM
from deepdiff import DeepDiff
import copy



class ToySBOMCompareExample:
    """
    Class to add a media-related bug into a mutated repository.

    """
    def __init__(self, repo):
        self.ToySBOM= SBOM(repo)
        self.SBOMjsonTruth={}
        self.SBOMjsonNonTruth={}




    def findToySBOMs(self):
        """
        Retrieves the media used for the mutation

        Returns:
            self.media: string name of the file
        """
        self.ToySBOM.findJson()
        self.SBOMjsonTruth= self.ToySBOM.getJson()
        self.SBOMjsonNonTruth= copy.deepcopy(self.SBOMjsonTruth)
#placeholder
       #Load SBOMjsonTruth into a map form
        #data = json.loads(self.SBOMjsonNonTruth)
	        #remove some stuff from SBOMjsonTruth here to get "ToySBOM"
      
        packagename="transformers"   #placeholder 

	#delete package with "name"
        self.SBOMjsonNonTruth["sbom"]["packages"] = [pkg for pkg in self.SBOMjsonNonTruth["sbom"]["packages"] if pkg["name"] != packagename]
		#Chance to Remove a random package ([packages])
		#chance to remove the license/change the license
		#Chance to add a package(?)
                
        
    def getTruthSBOM(self):
        """
        Retrieves the media used for the mutation

        Returns:
            self.media: string name of the file
        """
        return self.SBOMjsonTruth


#COMPARE METHOD HERE
#Maybe do Compare FIRST, then add more robust Toy example

    def compareSBOMs(self):
        output=""
        difference = DeepDiff(self.SBOMjsonTruth,self.SBOMjsonNonTruth, ignore_order=True)   
        removed_packages = []
        add_packages = []

        if difference:
             if 'iterable_item_removed' in difference:
                removed_packages = []
                for key, package in difference['iterable_item_removed'].items():
                   # Check if 'name' key exists in the package
                    if 'name' in package:
                      removed_packages.append(package['name'])
                for item in removed_packages:
                    output= output + item + " present in SBOM 1 but not SBOM 2\n"
             if 'iterable_item_added' in difference:
                removed_packages = []
                for key, package in difference['iterable_item_removed'].items():
                   # Check if 'name' key exists in the package
                    if 'name' in package:
                      add_packages.append(package['name'])
                for item in add_packages:
                    output= output + item + " not present in SBOM 1 but present in SBOM 2\n"

          
             print("Differences found:\n")
             print(output)
        else:
           print("No differences found.")
#COMPARE SBOMS, section by section
#COMPARE Licenses (dataLicense)
#Compare packages (missing packages, wrong info in packages, etc)
#Add comparsions (like missing packages, wrong licenses, etc) to output



      


if __name__ == "__main__":
    if len(sys.argv) <= 1:
         print("No repo given")
#https://github.com/microsoft/OmniParser
    test_SBOM = ToySBOMCompareExample(sys.argv[1])
    test_SBOM.findToySBOMs()
    test_SBOM.compareSBOMs()

    #print(test_SBOM.getTruthSBOM())

