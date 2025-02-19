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
        if difference:
           print("Differences found:")
           print(difference)
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

