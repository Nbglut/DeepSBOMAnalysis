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
import asyncio
import aiohttp


lock = asyncio.Lock()


async def get_json_from_link(link):
        """
               Gets the Json of a given link
        """
        
        async with aiohttp.ClientSession() as session:
            async with session.get(link) as response:  # Non-blocking
               return await response.json()  
       # response = requests.get(link)
        #print(response.status_code) # Print the status code
        #return response.json() 

class DeepAnalysis:
    """
      DeepAnalysis is the cass that analyzes the SBOM.
      It is given the SBOM content
    """
    def __init__(self, SBOM1):
        self.SBOMContents= SBOM1
        self.missing_packs={}
        self.checked_packs={}
    
   
    def getMissingPacks(self):
        """
               Returns the missingpacks
        """
        return self.missing_packs 


    async def add_to_missing_packs(self,pac,missing_packs):
      async with lock:  # Ensures that only one task can modify the list at a time
            missing_packs.add(pac)
            
            
    async def add_to_checked_packs(self,pac,checked_packs):
      async with lock:  # Ensures that only one task can modify the list at a time
            checked_packs.add(pac)
            



    async def analyzeTransient(self, present_packs, checked_packages, missing_packs):
               """
                   Recursive function that goes up the chain of a package pac and finds all of the missing packages (recorded in missing_pack) 
                   by checking pacakges against present_packs and avoids checking the same package twice by using checked_packages 
                  
               """
               tasks=[]
               
               need_to_check= set(present_packs)

               while need_to_check:
                  pac=need_to_check.pop()
                  paclower=pac.lower()
                  if pac not in missing_packs and pac not in present_packs and pac.lower() not in present_packs:
                         #print("\nMissing package "+ pac )
                         await self.add_to_missing_packs(pac)
                  if paclower not in checked_packages:
                      if "com.git" in paclower and pac!= self.SBOMContents['sbom']['name'] and paclower not in checked_packages:
                               tasks.append(get_json_from_link(f"https://api.github.com/repos/" + pac.split(".")[2] +"/dependency-graph/sbom"))
                      
                      else:
                        tasks.append(get_json_from_link(f"https://pypi.org/pypi/{pac}/json"))

                  await self.add_to_checked_packs(paclower,checked_packages)  
               results = await asyncio.gather(*tasks)
              # print(checked_packages)
               #print(tasks)
               missing_packs_lower=[item.lower() for item in missing_packs]
               for pkg_json in results:
               #if [message] exists in json, the json does not exist and we continue 
                  if "message"  not in pkg_json and  "sbom" not in pkg_json and pkg_json['info']['requires_dist'] !=None:
               #req_pack=data['info']['requires_dist'] has all required packages 
                      req_packetsunformated=pkg_json['info']['requires_dist']
                      for item in req_packetsunformated: 
                         nextpac=re.split(r"([=<>; ~)(?!])", item)[0]
                         nextpaclower=nextpac.lower()
                         if nextpaclower not in checked_packages  and nextpac not in need_to_check:
                                  need_to_check.add(nextpac)
                         if (nextpac not in present_packs and nextpaclower not in present_packs ):
                                   #print("\nMissing package "+ nextpac  )
                                   await self.add_to_missing_packs(nextpaclower, missing_packs)
                              #TO ADD-RELATIONSHIP ADDDITION for restoring
                              #pkg_json['info']['name']=pac depends on nextpac
                              
                    
                  else:
                 #else if git is in package name, the package is a git package and we can find sbom directly
                     #for all packages in the SBOM, analyze the packages dependencies\
                        if "sbom" in pkg_json:
                           for packs in pkg_json['sbom']['packages']:
                            # print("GITHUB FOUND")
                             nextpac= packs['name']
                             nextpaclower=nextpac.lower()
                             if nextpaclower not in checked_packages and nextpac not in need_to_check:
                                  need_to_check.add(nextpac)
                             if nextpac not in missing_packs and nextpaclower not in missing_packs:
                                    #print("\nMissing package "+ nextpac  )
                                    await self.add_to_missing_packs(nextpac, missing_packs)
        
                  if len(need_to_check) >0:
                     
                     await self.analyzeTransient(need_to_check, checked_packages, missing_packs)
               #print("\nWe checked " + str(len(checked_packages)))
               return missing_packs

               
                  
    async def Analyze(self):
       """
          Function which calls analyzeTransient 
       """
       checked_pks=set()
       req_packs=[]
       present_packs=[]
       missing_packs=set()
       pks=self.SBOMContents["sbom"]["packages"]
       for package in pks:
          present_packs.append(package['name'])
       #print(present_packs)
       print("This may take a minute...")

       await self.analyzeTransient( set(present_packs), checked_pks, missing_packs)
       
       self.missing_packs=missing_packs
               
                   
               

              
    
    



#What about restoring??
#Another Python file
#Add to [package] 
#Add to [relationships] 

   
async def main():
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
    await SBOMAnalysis.Analyze()
    missing_packs=SBOMAnalysis.getMissingPacks()
    missing_pack_list=list(missing_packs)
    missing_pack_list.sort()
    print(missing_pack_list)     
    print(str(len(missing_packs)) + " MISSING TRANSIENT PACKAGES\n")
   
    

   

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Deep Analysis')

    parser.add_argument('--file', default='True', type=str, help='file (True) or remote (False)')
    parser.add_argument('filename')  
    args = parser.parse_args()
    asyncio.run(main())
     
   