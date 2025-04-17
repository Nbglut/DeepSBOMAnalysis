from SBOM_generate import SBOM_generate
from DeepAnalysis import DeepAnalysis
from CompareSBOMs import CompareSBOMs
from CompareLocalSBOMWithRemote import CompareLocalSBOMWithRemote
import json
import asyncio
import aiohttp
import sys  
import requests
import chardet 
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup

  #@Author Nicolette Glut
  
  
  
"""
Formats license


"""
def FormatLicense(license):
    if license !="NOASSERTION":
       kind=license
       version="3"
       end=""
       if "Apache" in license:
          kind="Apache"
       if "Common Public License" in license:
          kind="CPL"
       if "General Public License" in license or "GPL" in license:
          kind="GPL"
       if "BSD" in license:
         kind="BSD"
         end="Clause"
       if "MIT" in license:
          kind="MIT"
       if "ASF" in license:
          kind="Apache"
       
       if "2.0" in license:
          version="2.0"
       elif "3.0" in license:
          version="3.0"
       elif "3" in license:
          version="3"
       elif "2" in license:
          version="2"
       elif "1.0" in license:
          version="1.0"
       elif "2" in license:
          version="2"
       elif "1.0" in license:
          version="1.0"          
              
         
        
       license=kind + "-" +version
       if end !="":
         license+="-"+end       

    return license



"""
Recursive function that goes up a single chain of dependency ancestors to find the license of the parent, which is the same as the license of the current project

"""
  
def findParentLicense(parent,namespace):
    groupId= parent.find('groupId', namespace).text
    artifactId= parent.find('artifactId', namespace).text

    version= parent.find('version', namespace).text

    license="NOASSERTION"
    link= "https://repo1.maven.org/maven2/" +groupId.replace(".","/") +"/" +artifactId + "/" + version  +"/" +artifactId+"-" + version +".pom"
    #Guess/heuristic
    if "apache" in groupId:
       license="Apache 2.0"
    
    
    
    
    response = requests.get(link)
    if response.status_code==200:
                 raw= response.content
                 detect=chardet.detect(raw)
                 encoding=detect.get('encoding','utf-8')
                 content=raw.decode(encoding,errors='replace')

# Step 3: Convert back to string and parse with ElementTree
                 pkg_xml= ET.fromstring(content)
                 licenses= pkg_xml.find('licenses',namespace)
                 parent= pkg_xml.find('parent',namespace)
                 #if lcicenses does not exist, go to parent if it exists, and then repeat
                 if licenses:
                       licensesec=licenses.find('license',namespace)
                       if licensesec:
                          license=licensesec.find('name',namespace).text
                 
                 elif parent:
                   license=findParentLicense(parent, namespace)

    return license  
  
  
"""
Main function that "restores" SBOMs by adding missing packages, including their name, license, etc.

"""  
  
  
def restoreSBOM(fileContents, missing_packs):
           print("Restoring...")
           
           #For every item in missing_packs, add an entry in SBOM
           for item in missing_packs:
              version= item.split('@')[-1]
              itemlocator= item.split('@')[0]
              itemname=itemlocator.replace("/",".")
              artname=itemlocator.split("/")[-1]
#Get the XML in order to get the license              
              link= "https://repo1.maven.org/maven2/" +itemlocator.replace(".","/") + "/" + version  +"/" +artname+"-" + version +".pom"
              license="NOASSERTION"
              response = requests.get(link)
              if response.status_code==200:
                 raw= response.content
                 detect=chardet.detect(raw)
                 encoding=detect.get('encoding','utf-8')
                 content=raw.decode(encoding,errors='replace')
                 
                 pkg_xml= ET.fromstring(content)
                 
                 namespace = {'': 'http://maven.apache.org/POM/4.0.0'}
                                
                 licenses= pkg_xml.find('licenses',namespace)
                 parent= pkg_xml.find('parent',namespace)
                 #if lcicenses does not exist, go to parent if it exists, and then repeat
                 if licenses:
                       licensesec=licenses.find('license',namespace)
                       if licensesec:
                          license=licensesec.find('name',namespace).text
                 elif parent:
                   license=findParentLicense(parent,namespace)
                 else:
                    namespace=namespace = {'': ''}
                    licenses= pkg_xml.find('licenses',namespace)
                    parent= pkg_xml.find('parent',namespace)
                     #if lcicenses does not exist, go to parent if it exists, and then repeat
                    if licenses:
                       licensesec=licenses.find('license',namespace)
                       if licensesec:
                          license=licensesec.find('name',namespace).text
              license=FormatLicense(license)
              #Add entry to SBOM
              new_package = {
               "SPDXID": "SPDXRef-Package-" + itemlocator.replace(".","") +version,
               "name": itemname,
               "versionInfo": version,
               "packageFileName": itemname.split(".")[-1] + "-" +version +".jar",
               "supplier": "NOASSERTION",
               "downloadLocation": "NOASSERTION",
               "filesAnalyzed": False,
               "checksums": [],
               "homepage": "NOASSERTION",
               "licenseConcluded": license,
               "licenseDeclared": license,
               "copyrightText": "NOASSERTION",
               "externalRefs": [
                   {
                       "referenceCategory": "PACKAGE-MANAGER",
                       "referenceType": "purl",
                       "referenceLocator": "pkg:maven/" + item
                   }
                 ]
               }  
              fileContents["packages"].append(new_package)       
           return fileContents


    






async def main():
          filename=sys.argv[1]

          with open(filename, 'r') as file:
                fileContents = json.load(file)
          if 'sbom' in fileContents:
                fileContents=fileContents['sbom']
          analyzer=DeepAnalysis(fileContents, owner, repo)
          await analyzer.Analyze()
          missing_packs=analyzer.getMissingPacks()         
          print("\nDeep Analysis Results:\n\nThe SBOM was missing " + str(len(missing_packs)) + " transitive dependencies.\n")

          missingdirect = analyzer.getMissingDirectPacks()
          print("\nThe SBOM was missing " + str(len(missingdirect)) + " direct dependencies.\n")

          allmissing_packs=missing_packs+missingdirect
          newfileContents=restoreSBOM(fileContents, allmissing_packs)
     
          filename=filename.split("json")[0]
          with open(filename+'_restored.json', 'w') as file:
             json.dump(newfileContents, file, indent=4)
             print("Restored file saved in " + filename+'_restored.json')

      
       
       
        
if __name__ == "__main__":
        asyncio.run(main())