"""
SBOM.py

This class simply uses the GitHub API to get the SBOM of a given project and stores the json


@Author Nicolette Glut
File Created On 2-18-2025
"""

import os
import requests
import json
import sys

class SBOM:
    """
    Class to add a media-related bug into a mutated repository.

    """
    def __init__(self, repo):
        self.repo=repo
        self.SBOMjson={}



    def findJson(self):
        """
        Retrieves the media used for the mutation

        Returns:
            self.media: string name of the file
        """
        items= self.repo.split("/")
        if len(items) <5:
           print("Ill-formed repo")
           exit()
        api_request="https://api.github.com/repos/" + items[3] +"/" + items[4]+ "/dependency-graph/sbom"
        print(api_request)
        response = requests.get(api_request)
        #print(response.status_code) # Print the status code
        self.SBOMjson=response.json() 



    def getJson(self):
        """
           Returns the SBOM json
        """
        if self.SBOMjson =={}:
           self.findJson()
        return self.SBOMjson


      


if __name__ == "__main__":
    if len(sys.argv) <= 1:
         print("No repo given")
    test_SBOM = SBOM(sys.argv[1])
    test_SBOM.findJson()

    print(test_SBOM.getJson())

