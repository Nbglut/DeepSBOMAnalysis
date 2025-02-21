"""
CompareSBOMs.py

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




class CompareSBOMs:
    """

    """
    def __init__(self, repo):
        self.TruthSBOM= SBOM(repo)
        self.SBOMjsonTruth={}
        self.SBOMjsonNonTruth={}




    def findTruthSBOMs(self):
        """
                Finds the Truth SBOM and puts it in the  self.SBOMjsonTruth
        """
        self.TruthSBOM.findJson()
        self.SBOMjsonTruth= self.TruthSBOM.getJson()



    def setNonTruth(self, nontruth):
        """
                Sets the self.SBOMjsonNonTruth
        """
        self.SBOMjsonNonTruth=nontruth

    def RandomizeNonTruth(self):
        """
                Makes random changes to  self.SBOMjsonTruth and saves it to self.SBOMjsonNonTruth
        """
        self.findTruthSBOMs()
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
        
        #update numbers just in case packages removed
        numpackages=len(self.SBOMjsonNonTruth['sbom']['packages'])-1
        #if numpackages <=0, packagename_change should be NONE
        if numpackages <=0:
           packagename_change="None"
        else : #else, get random package like normal
           packagename_change=self.SBOMjsonNonTruth['sbom']['packages'][random.randint(0, numpackages)]['name']  #random package

#random chance to change  
        if(random.choice([0, 1]) and packagename_change != "None"):
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
        Retrieves the truth SBOM

        Returns:
            self.media: string name of the file
        """
        return self.SBOMjsonTruth


   
    def compareSBOMs(self):
        """
           Uses the nonTruthSBOmjson and the TruthSBOMjson and compares the two 
        """
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
                     if changed_type=="creationInfo" or changed_type=="documentNamespace":
                        continue
                     output= output + str(differences)  + ". The " +changed_type + " is " + str(self.SBOMjsonTruth['sbom'][changed_type])
                     output= output + " in the first SBOM and " +  str(self.SBOMjsonNonTruth['sbom'][changed_type]) 
                     output= output + " in the second SBOM\n"
                     differences=differences +1

                     changed_items.append(changed_type)  
                       





          
             print( str(differences-1)  + " difference(s) found:\n")
             #print(difference)
             print(output)
        else:
           print("No differences found.")



      


if __name__ == "__main__":
    if len(sys.argv) <= 1:
         print("No repo given")
    test_SBOM = CompareSBOMs(sys.argv[1])
    test_SBOM.findTruthSBOMs()
    test_SBOM.RandomizeNonTruth()

    test_SBOM.compareSBOMs()

    #print(test_SBOM.getTruthSBOM())

