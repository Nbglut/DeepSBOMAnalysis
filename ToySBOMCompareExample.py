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

		#remove some stuff from SBOMjsonTruth here to get "ToySBOM"

        
    def getTruthSBOM(self):
        """
        Retrieves the media used for the mutation

        Returns:
            self.media: string name of the file
        """
        return self.SBOMjsonTruth


#COMPARE METHOD HERE

#COMPARE SBOMS, section by section
#COMPARE Licenses (dataLicense)
#Compare packages


      


if __name__ == "__main__":
    if len(sys.argv) <= 1:
         print("No repo given")
    test_SBOM = ToySBOMCompareExample(sys.argv[1])
    test_SBOM.findToySBOMs()
    print(test_SBOM.getTruthSBOM())

