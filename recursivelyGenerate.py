"""
recursivelyGenerate.py

This class is meant to recursively generate SBOMs using SBOM generators. The SBOM generates based off of all present dependecneis in the SBOM. 



@Author Nicolette Glut
File Created 4-2025
"""









from SBOM_generate import SBOM_generate
from DeepAnalysis import DeepAnalysis
from CompareSBOMs import CompareSBOMs
from CompareLocalSBOMWithRemote import CompareLocalSBOMWithRemote
import json
import asyncio
import aiohttp
from SBOM import SBOM
from RestoreSBOM import restoreSBOM
 
 
             
def recursiveGenTransient(SBOM, generator, missing_packs, present_packsrec, present_packs, checked_packs):
       """
          Function which recursively generates SBOMS using given generator by generating SBOMs from found dependencies 
       """
       #print(self.SBOMContents)
       for dep in present_packs:
               if dep in checked_packs:
                   continue
               checked_packs.add(dep)
               print("Attempting to generate SBOM of " + dep)
               if "actions/" in dep or "-plugin" in dep or "%40" in dep:
                  print("Likely a GitHub Runner action, or plugin skipping")
                  continue
               gen=SBOM_generate()
               owner=dep.split("/")[0].split(".")[-1]
               repo=dep.split("/")[-1]
               repo= repo.split("@")[0]
               gen.generate_sbom(owner,repo, generator)
               files=gen.get_SBOMs()
               fileContents=""
               for file in files:
                 with open(file, 'r') as filecont:
                   fileContents = json.load(filecont)
                   if 'sbom' in fileContents:
                    fileContents= fileContents['sbom']
                 #get all missing packs (packs in the new SBOM not in the first SBOM
                 #make sure you skip the name of itself

                   pksdep=SBOM["packages"]
                   for package in pksdep:
                     if package['name'] != SBOM['name']:
                       if 'externalRefs' in package:
                          pac=package['externalRefs']
                          pac=pac[-1]['referenceLocator']
                          pacsplit=pac.split("/")
                          pacGroup=""
                          pacArtificat=""
                          if len(pacsplit)>=3:
                            pacGroup=pacsplit[1]
                            pacArtificat=pacsplit[2]
                          else:
                            pacsplit=pac.split(":")
                            if len(pacsplit) <5:
                                continue
                            pacGroup=pacsplit[3]
                            pacArtificat=pacsplit[4]
                            pacArtificat+="@"+pacsplit[5]

                          if "swid" in pacsplit[0]:
                            pacArtificat=pacsplit[3]
                            pacGroup= "org." +pacGroup
                            continue
                          pac=pacGroup+ "/" +pacArtificat
                          present_packsrec.append(pac)
                   for item in present_packsrec:
                          if item not in present_packs:
                            print("MISSING")
                            missing_packs.add(item)
                       
                   for pack in present_packsrec:
                #throw new SBOM
                        recursiveGenTransient(fileContents, generator, missing_packs, present_packsrec, present_packs,checked_packs)

                                 
def recursivelyGenerate(SBOM, generator, filename):
       """
          Function which recursively generates SBOMS using given generator by generating SBOMs from found dependencies 
       """
       checked_pks=set()
       present_packs=[]
       missing_packs=set()
       present_packsrec=[]
       #print(self.SBOMContents)
       pks=SBOM["packages"]
       python = input("Is this a Python Project? True or False")
       if python=="True":
          for package in pks:
             if package['name'] != SBOM['name']:
            
                present_packs.append(package['name'])
       #Assume maven
       else:
          for package in pks:
             if package['name'] != SBOM['name']:
               if 'externalRefs' in package:
                pac=package['externalRefs']
                pac=pac[-1]['referenceLocator']
                pacsplit=pac.split("/")
                pacGroup=""
                pacArtificat=""
                if len(pacsplit)>=3:
                  pacGroup=pacsplit[1]
                  pacArtificat=pacsplit[2]
            
 #eles if gradle
                else:
                  pacsplit=pac.split(":")
                  pacGroup=pacsplit[3]
                  pacArtificat=pacsplit[4]
                  pacArtificat+="@"+pacsplit[5]
                
                if "swid" in pacsplit[0]:
                    pacArtificat=pacsplit[3]
                    pacGroup= "org." +pacGroup
                    continue
                pac=pacGroup+ "/" +pacArtificat
                present_packs.append(pac)    
       recursiveGenTransient(SBOM, generator, missing_packs, present_packsrec, present_packs, set())
       print(missing_packs)
       newfile=restoreSBOM(SBOM, missing_packs)
       filename=filename.split("json")[0]
       with open(filename+'_restored.json', 'w') as file:
             json.dump(newfile, file, indent=4)
             print("Restored file saved in " + filename+'_restored.json')
       return newfile


if __name__ == "__main__":
        filename = input("Directory to SBOM: ").strip()
        gen= input("Generator: ").strip()
        fileContents=""
        with open(filename, 'r') as file:
                fileContents = json.load(file)
                if 'sbom' in fileContents: 
                  fileContents=fileContents['sbom']
        print("Doing it")
        recursivelyGenerate(fileContents,gen,filename)
