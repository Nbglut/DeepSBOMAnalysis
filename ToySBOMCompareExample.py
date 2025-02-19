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
from deepdiff import DeepDiff
import copy
import random
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
        self.SBOMjsonNonTruth= copy.deepcopy(self.SBOMjsonTruth) #copy of truth

            
        packagename_remove="transformers"   #placeholder  for package to remove
        packagename_change="transformers"   #placeholder  for package to change
        numpackages=len(self.SBOMjsonNonTruth['sbom']['packages'])-1
        packagename_remove=self.SBOMjsonNonTruth['sbom']['packages'][random.randint(0, numpackages)]['name']  #random package


        print("\nChanges between Truth and Non Truth:\n")
	
	#random chance to remove  
        if(random.choice([0, 1])):
           self.SBOMjsonNonTruth["sbom"]["packages"] = [pkg for pkg in self.SBOMjsonNonTruth["sbom"]["packages"] if pkg["name"] != packagename_remove]
           print("Removed " +  str(packagename_remove) + "\n")
        
        numpackages=len(self.SBOMjsonNonTruth['sbom']['packages'])-1

        packagename_change=self.SBOMjsonNonTruth['sbom']['packages'][random.randint(0, numpackages)]['name']  #random package


#random chance to change  
        if(random.choice([0, 1])):
           for package in self.SBOMjsonNonTruth['sbom']['packages']:
               if package['name'] == packagename_change:
                   package['filesAnalyzed'] = True  
           print("Changed " +  str(packagename_change) + "\n")

        #Random chance to change  licensing
        if(random.choice([0, 1])):
           self.SBOMjsonNonTruth["sbom"]["dataLicense"]="MIT" 
           print("Changed License\n\n\n\n")
     
        
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
        changed_items=[]
        differences=1
        if difference:
             if 'iterable_item_removed' in difference:
                removed_packages = []
                for key, package in difference['iterable_item_removed'].items():
                   # Check if 'name' key exists in the package
                    if 'name' in package:
                      removed_packages.append(package['name'])
                for item in removed_packages:
                    output= output + str(differences) +". "+ item + " present in SBOM 1 but not SBOM 2\n"
                    differences=differences+1
             if 'iterable_item_added' in difference:
                for key, package in difference['iterable_item_removed'].items():
                   # Check if 'name' key exists in the package
                    if 'name' in package:
                      add_packages.append(package['name'])
                for item in add_packages:
                    output= output + str(differences) + ". " + item + " not present in SBOM 1 but present in SBOM 2\n"
                    differences=differences +1



             if 'values_changed' in difference:
                for key, package in difference['values_changed'].items():
                   # Check if 'package' is part of key
                    if 'packages' in key:                  
                      package_index = int(key.split(']')[2][1:])  # Extract index of the package
                      package_name = self.SBOMjsonTruth['sbom']['packages'][package_index ]['name']  
                      output= output + str(differences)  +  ". The information about package/dependency " + package_name + " is not equal\n"
                      differences=differences+1
                      changed_items.append(package_name)
                    else:
                     key_parts= key.split(']')
                     changed_type= key_parts[1][1:]
                     changed_type=changed_type.replace("'", "")
                     output= output + str(differences)  + ". The " +changed_type + " is " + self.SBOMjsonTruth['sbom'][changed_type]
                     output= output + " in the first SBOM and " +  self.SBOMjsonNonTruth['sbom'][changed_type] 
                     output= output + " in the second SBOM\n"
                     differences=differences +1

                     changed_items.append(changed_type)  
                       





          
             print( str(differences-1)  + " differences found:\n")
             #print(difference)
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

