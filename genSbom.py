import requests
import json
import os
import random

#Function to retrieve the SPDX GitHub SBOM of a given repository, returned as JSON.
def get_spdx_sbom(owner, repo, token):
    url = f"https://api.github.com/repos/{owner}/{repo}/dependency-graph/sbom"
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}"
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json() 
    else:
        print(f"Error: {response.status_code} - {response.text}")
        return None
    
#Function to save given JSON data to a local file.
def save_json(data, filename):
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        print(f"Saved: {filename}")
    except Exception as e:
        print(f"Error saving JSON to {filename}: {e}")

#Function to convert SPDX returned from GitHub into CycloneDX format
def spdx_to_cyclonedx(spdx_data):
    cyclonedx_data = {
        "bom": {
            "xmlns": "http://cyclonedx.org/schema/bom/1.4",
            "components": []
        }
    }

    for package in spdx_data.get('sbom', {}).get('packages', []):
        component = {
            "type": "library",
            "name": package.get('name', ''),
            "version": package.get('versionInfo', ''), 
            "purl": "", 
            "license": {
                "license": package.get('licenseDeclared', '') 
            }
        }
        
        for ref in package.get('externalRefs', []):
            if ref.get('referenceCategory') == 'PACKAGE-MANAGER' and ref.get('referenceType') == 'purl':
                component["purl"] = ref.get('referenceLocator', '')
        
        cyclonedx_data["bom"]["components"].append(component)

    return cyclonedx_data

#Function to introduce mutations into an SBOM file to simulate an incomplete SBOM for the 
# sake of the comparison function. Only tested on SPDX JSON files dircetly from GitHub.
def mutate_sbom(original_file):
    try:
        with open(original_file, 'r', encoding='utf-8') as f:
            sbom_data = json.load(f)
    except Exception as e:
        print(f"Error loading SBOM file: {e}")
        return None

    modified = False  
    if 'sbom' in sbom_data and 'packages' in sbom_data['sbom']:
        packages = sbom_data['sbom']['packages']

        if packages:
            action = random.choice(["remove", "modify"])
            
            if action == "remove" and len(packages) > 1:
                removed_package = random.choice(packages)
                sbom_data['sbom']['packages'].remove(removed_package)
                print(f"Removed package: {removed_package.get('name', 'Unknown')}")
                modified = True

            elif action == "modify":
                package_to_modify = random.choice(packages)
                old_value = package_to_modify.get('versionInfo', 'Unknown')
                package_to_modify['versionInfo'] = "999.999.999"
                print(f"Modified package version: {package_to_modify.get('name', 'Unknown')} from {old_value} → 999.999.999")
                modified = True

    if 'sbom' in sbom_data:
        if 'dataLicense' in sbom_data['sbom']:
            old_license = sbom_data['sbom']['dataLicense']
            sbom_data["sbom"]["dataLicense"] = "MIT"
            print(f"Changed license from {old_license} → MIT")
            modified = True

    if not modified:
        print("Warning: No mutations were applied. Forcing a license change.")
        sbom_data["sbom"]["dataLicense"] = "MIT"

    mutated_file = os.path.splitext(original_file)[0] + "_mutated.json"
    
    try:
        with open(mutated_file, "w", encoding="utf-8") as f:
            json.dump(sbom_data, f, indent=4)
        print(f"Mutated SBOM saved: {mutated_file}")
        return mutated_file
    except Exception as e:
        print(f"Error saving mutated SBOM: {e}")
        return None

#Function to compare two SBOM files, currently only tested with SPDX JSON files dircetly from GitHub api.
def compare_sboms(original_file, mutated_file):
    try:
        with open(original_file, 'r', encoding='utf-8') as f:
            sbom_original = json.load(f)
        with open(mutated_file, 'r', encoding='utf-8') as f:
            sbom_mutated = json.load(f)
    except Exception as e:
        print(f"Error loading SBOM files: {e}")
        return

    differences = []
    original_packages = {pkg['name']: pkg for pkg in sbom_original.get('sbom', {}).get('packages', [])}
    mutated_packages = {pkg['name']: pkg for pkg in sbom_mutated.get('sbom', {}).get('packages', [])}

    removed_packages = set(original_packages.keys()) - set(mutated_packages.keys())
    added_packages = set(mutated_packages.keys()) - set(original_packages.keys())

    for pkg in removed_packages:
        differences.append(f"Package removed: {pkg}")

    for pkg in added_packages:
        differences.append(f"Package added: {pkg}")

    for pkg_name, original_pkg in original_packages.items():
        if pkg_name in mutated_packages:
            mutated_pkg = mutated_packages[pkg_name]
            for key in original_pkg:
                if key in mutated_pkg and original_pkg[key] != mutated_pkg[key]:
                    differences.append(f"Package '{pkg_name}': '{key}' changed from '{original_pkg[key]}' to '{mutated_pkg[key]}'")

    for key in sbom_original.get('sbom', {}):
        if key in sbom_mutated.get('sbom', {}) and sbom_original['sbom'][key] != sbom_mutated['sbom'][key]:
            differences.append(f"Field '{key}' changed from '{sbom_original['sbom'][key]}' to '{sbom_mutated['sbom'][key]}'")

    if differences:
        print("\nDifferences Found:")
        for diff in differences:
            print(f"- {diff}")
    else:
        print("No differences found between the SBOM files.")

#Main
#Updated to convert JSON/SPDX default to CycloneDX *NOT FINISHED*
#Updated to add mutation of saved JSON file. TODO: introduce more mutations and generate false information
if __name__ == "__main__":
    GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
    if not GITHUB_TOKEN:
        print("Error: GitHub token not found. Please set the GITHUB_TOKEN environment variable.")
        exit(1)

    owner = input("Enter GitHub repo owner: ")
    repo = input("Enter GitHub repo name: ")

    sbom_data = get_spdx_sbom(owner, repo, GITHUB_TOKEN)

    if sbom_data:
        spdx_filename = f"{repo}_sbom_spdx.json"
        save_json(sbom_data, spdx_filename)
        mutated_file = mutate_sbom(spdx_filename)
        if mutated_file:
            compare_sboms(spdx_filename, mutated_file)

        #Convert the SPDX SBOM to CycloneDX
        #cyclonedx_data = spdx_to_cyclonedx(sbom_data)
        #cyclonedx_filename = f"{repo}_sbom_cyclonedx.json"
        #save_json(cyclonedx_data, cyclonedx_filename)
