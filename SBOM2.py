import requests
import json
import os
import subprocess
import shutil

# Function to get GitHub sbom, returns in SPDX format
def get_github_sbom(owner, repo, token):
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
        print("Response body:", response.json())  # Added for error information
        return None

# Function to clone repo to local directory if it doesn't exist there already
def clone_repo(owner, repo):
    repo_url = f"https://github.com/{owner}/{repo}.git"
    local_path = f"./{repo}"
    
    if os.path.exists(local_path):
        print(f"Repository {repo} already exists locally. Using existing directory.")
        return local_path
    
    try:
        subprocess.run(["git", "clone", repo_url, local_path], check=True)
        print(f"Cloned repository: {repo_url}")
        return local_path
    except subprocess.CalledProcessError as e:
        print(f"Error cloning repository: {e}")
        return None

# Function to generate Syft sbom, largely useless unless run on images
def generate_syft_sbom(target, output_file, is_image):
    if is_image:
        command = ["syft", "scan", target, "-o", "spdx-json"]
    else:
        command = ["syft", "scan", target, "-o", "spdx-json"]

    try:
        with open(output_file, "w") as f:
            subprocess.run(command, stdout=f, check=True)
        print(f"Syft SBOM saved: {output_file}")
    except FileNotFoundError:
        print("Error: Syft is not installed or not found in PATH.")
    except subprocess.CalledProcessError as e:
        print(f"Error running Syft: {e}")

# Function to generate Trivy sbom, mainly a security scanning tool but also only really useful on an image
def generate_trivy_sbom(target, output_file, is_image):
    command = ["trivy", "sbom", "-f", "spdx-json", "-o", output_file, target] if is_image else ["trivy", "fs", "--format", "spdx-json", "--output", output_file, "--scanners", "vuln", target]
    try:
        subprocess.run(command, check=True)
        print(f"Trivy SBOM saved: {output_file}")
    except FileNotFoundError:
        print("Error: Trivy is not installed or not found in PATH.")
    except subprocess.CalledProcessError as e:
        print(f"Error running Trivy: {e}")

# Function to generate Microsoft SBOM
def generate_microsoft_sbom(owner, repo):
    repo_url = f"https://github.com/{owner}/{repo}.git"
    repo_name = repo
    
    if not os.path.exists(repo_name):
        print(f"Cloning repository: {repo_url}")
        subprocess.run(f"git clone {repo_url}", shell=True, check=True)
    else:
        print(f"Repository '{repo_name}' already exists. Using the existing copy.")
    
    print("Generating Microsoft SBOM...")
    try:
        subprocess.run(f"sbom-tool generate -b {repo_name} -bc {repo_name} -pn {repo_name} -pv 1.0.0 -ps 'GitHub' -nsb 'https://github.com/{owner}/{repo}'", shell=True, check=True)
        print("Microsoft SBOM generation complete.")
    except subprocess.CalledProcessError as e:
        print(f"Error generating Microsoft SBOM: {e}")

# Function to save the JSON to a local file
def save_json(data, filename):
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        print(f"Saved: {filename}")
    except Exception as e:
        print(f"Error saving JSON to {filename}: {e}")

if __name__ == "__main__":
    GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
    if not GITHUB_TOKEN:
        print("Error: GitHub token not found. Please set the GITHUB_TOKEN environment variable.")
        exit(1)

    print("Select SBOM generators (comma-separated):")
    print("  0. All")
    print("  1. GitHub")
    print("  2. Syft")
    print("  3. Trivy")
    print("  4. Microsoft SBOM Tool")
    
    selection = input("Enter your choice: ").strip()
    choices = {"1": "github", "2": "syft", "3": "trivy", "4": "microsoft"}
    selected_generators = set(choices.values()) if "0" in selection else {choices[c] for c in selection.split(",") if c in choices}
    
    owner, repo = None, None
    if "github" in selected_generators:
        owner = input("Enter GitHub repo owner: ")
        repo = input("Enter GitHub repo name: ")
        sbom_data = get_github_sbom(owner, repo, GITHUB_TOKEN)
        if sbom_data:
            save_json(sbom_data, f"{repo}_sbom_spdx_github.json")

    if "syft" in selected_generators or "trivy" in selected_generators:
        scan_type = input("Scan a container image or a GitHub repo? (image/repo): ").strip().lower()
        is_image = scan_type == "image"
        
        if is_image:
            target = input("Enter container image name: ")
        else:
            if not owner or not repo:
                owner = input("Enter GitHub repo owner: ")
                repo = input("Enter GitHub repo name: ")
            target = clone_repo(owner, repo)
        
        if target:
            output_file = f"{repo}_sbom_spdx.json" if not is_image else f"{target.replace(':', '_').replace('/', '_')}_sbom_spdx.json"
            
            if "syft" in selected_generators:
                syft_output_file = output_file.replace(".json", "_syft.json")
                generate_syft_sbom(target, syft_output_file, is_image)
            if "trivy" in selected_generators:
                trivy_output_file = output_file.replace(".json", "_trivy.json")
                generate_trivy_sbom(target, trivy_output_file, is_image)

    if "microsoft" in selected_generators:
        if not owner or not repo:
            owner = input("Enter GitHub repo owner: ")
            repo = input("Enter GitHub repo name: ")
        generate_microsoft_sbom(owner, repo)
