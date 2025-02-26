"""
DeepAnalysis.py

This class is meant to use do a Deep Analysis of an SBOM.
The Analysis goes up the chain of dependencies to check all transient dependencies exist

@Author Nicolette Glut
File Created On 2-25-2025
"""





import os
import requests
import json
import argparse
import sys
from deepdiff import DeepDiff
import copy
import random
import re
from SBOM import SBOM
from CompareSBOMs import CompareSBOMs


def getJsonFromLink(link):
        """
               Gets the Json of a given link
        """
        response = requests.get(link)
        #print(response.status_code) # Print the status code
        return response.json() 

class DeepAnalysis:
    """
      DeepAnalysis is the cass that analyzes the SBOM.
      It is given the SBOM content
    """
    def __init__(self, SBOM1):
        self.SBOMContents= SBOM1
        self.missing_packs={}
    
   
    def getMissingPacks(self):
        """
               Returns the missingpacks
        """
        return self.missing_packs 



    def analyzeTransient(self, pac, present_packs, checked_packages, missing_packs):
               """
                   Recursive function that goes up the chain of a package pac and finds all of the missing packages (recorded in missing_pack) 
                   by checking pacakges against present_packs and avoids checking the same package twice by using checked_packages 
                  
               """
               if pac in checked_packages:
                  return
               pkg_json= getJsonFromLink("https://pypi.org/pypi/" + pac + "/json")
               #if [message] exists in json, the json does not exist and we continue 
               if "message"  not in pkg_json and  pkg_json['info']['requires_dist'] !=None:
               #req_pack=data['info']['requires_dist'] has all required packages 
                   print("Checking Transient Dependencies from  " + pac + "\n")
                   req_packetsunformated=pkg_json['info']['requires_dist']
                   for item in req_packetsunformated:
                    #Format items in req_pack such that it only takes first part of string before the first >, <, or =
                      nextpac=re.split(r"([=<>;])", item)[0]
                    #See if dependencies of the package are in the SBOM
                    #Check if all items in req_packs are in SBOM, if not, put in  missing_pack
                      if nextpac in checked_packages:
                          continue 
                      if nextpac in present_packs:
                         checked_packages.append(pac)        
                         self.analyzeTransient(nextpac, present_packs, checked_packages, missing_packs)

                         continue
                      if nextpac not in missing_packs:
                         missing_packs.append(nextpac)
                         self.analyzeTransient(nextpac, present_packs, checked_packages, missing_packs)

               else:
                 #else if git is in package name, the package is a git package and we can find sbom directly
                  checked_packages_lower = [item.lower() for item in checked_packages] #To overcome any case problems
                  if "com.git" in pac and pac!= self.SBOMContents['sbom']['name'] and (pac not in checked_packages and pac.lower() not in checked_packages_lower) :
                      print("Checking Transient Dependencies from " + pac + "\n")
                      pkg_json=getJsonFromLink("https://api.github.com/repos/" + pac.split(".")[2] +"/dependency-graph/sbom")
                      #if the sbom exists, simply compare the SBOM of the new package and the origoinal SBOM we are deeply analyzing
                      if "message"  not in pkg_json:
                     #for all packages in the SBOM, analyze the packages dependencies
                         for packs in pkg_json['sbom']['packages']:
                         
                             nextpac= packs['name']
                             if nextpac in checked_packages:
                                 continue 
                             if nextpac in present_packs:
                                 checked_packages.append(pac)        
                                 self.analyzeTransient(nextpac, present_packs, checked_packages, missing_packs)
                                 continue
                             if nextpac not in missing_packs:
                                missing_packs.append(nextpac)                             
                                self.analyzeTransient(nextpac, present_packs, checked_packages, missing_packs)

               if pac not in checked_packages:                                  
                  checked_packages.append(pac)        
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    def Analyze(self):
       """
          Function which calls analyzeTransient 
       """
       checked_pks=[]
       req_packs=[]
       present_packs=[]
       missing_packs=[]
       pks=self.SBOMContents["sbom"]["packages"]
       for package in pks:
          present_packs.append(package['name'])
       #print(present_packs)
       print("This may take a minute...")

       for package in pks:
          self.analyzeTransient(package['name'], present_packs, checked_pks, missing_packs)
       self.missing_packs=missing_packs
               
                   
               

              
    
    



#What about restoring??
#Another Python file
#Add to [package] 
#Add to [relationships] 

   
   
   

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Deep Analysis')

    parser.add_argument('--file', default='True', type=str, help='file (True) or remote (False)')
    parser.add_argument('filename')  
    args = parser.parse_args()
         
    if len(sys.argv) <= 1:
         print("No file or remote given")
    fileOrRemote= args.filename
    fileContents=""
    if args.file=="True":
      with open(fileOrRemote, 'r') as file:
                fileContents = json.load(file)
    else:
       SBOM1=SBOM(fileOrRemote)
       fileContents=SBOM1.getJson()
    SBOMAnalysis=DeepAnalysis(fileContents)
    SBOMAnalysis.Analyze()
    missing_packs=SBOMAnalysis.getMissingPacks()
    print(str(len(missing_packs)) + " MISSING TRANSIENT PACKAGES\n")
    missing_packs.sort()
    print(missing_packs)        
    
