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
  
  
def FormatLicense(license):
    if license !="NOASSERTION":
       kind=license
       version="1.0"
       end=""
       if "Apache" in license:
          kind="Apache"
       if "Common Public License" in license:
          kind="CPL"
       if "General Public License" in license or "GPL" in license:
          kind="GPL"
       if "BSD" in license:
         kind="BSD"
         end="clause"
       if "MIT" in license:
          kind="MIT"
       
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

  
  
  
  
def restoreSBOM(fileContents, missing_packs):
           for item in missing_packs:
              version= item.split('@')[-1]
              itemlocator= item.split('@')[0]
              itemname=itemlocator.replace("/",".")
#https://repo1.maven.org/maven2/[group_path]/[artifact]/[version]/[artifact]-[version].pom
              artname=itemlocator.split("/")[-1]
              
              link= "https://repo1.maven.org/maven2/" +itemlocator.replace(".","/") + "/" + version  +"/" +artname+"-" + version +".pom"
              license="NOASSERTION"
              response = requests.get(link)
              if response.status_code==200:
                 raw= response.content
                 detect=chardet.detect(raw)
                 encoding=detect.get('encoding','utf-8')
                 content=raw.decode(encoding,errors='replace')

# Step 3: Convert back to string and parse with ElementTree
                 pkg_xml= ET.fromstring(content)
                 namespace = {'': 'http://maven.apache.org/POM/4.0.0'}
                 licenses= pkg_xml.find('licenses',namespace)
                 if licenses:
                       licensesec=licenses.find('license',namespace)
                       if licensesec:
                          license=licensesec.find('name',namespace).text

                 #https://repo1.maven.org/maven2/[group_path]/[artifact]/[version]/[artifact]-[version].pom

              license=FormatLicense(license)
              print(license)
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
          file=sys.argv[1]

          with open(file, 'r') as file:
                fileContents = json.load(file)
          if 'sbom' in fileContents:
                fileContents=fileContents['sbom']
          analyzer=DeepAnalysis(fileContents)
          await analyzer.Analyze()
          missing_packs=analyzer.getMissingPacks()         
          print("\nDeep Analysis Results:\n\nThe SBOM was missing " + str(len(missing_packs)) + " transitive dependencies of dependencies already present in it.\n")
          newfileContents=restoreSBOM(fileContents, missing_packs)
     

          with open('restored.json', 'w') as file:
             json.dump(newfileContents, file, indent=4)

      
       
       
        
if __name__ == "__main__":
        asyncio.run(main())
