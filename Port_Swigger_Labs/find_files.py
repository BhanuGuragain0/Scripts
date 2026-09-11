import os

# Project root to remove
project_root = "/home/bhanu/Desktop/Final_Production_Version/GANGA_Offensive_Ops_Hacker_ASI"

# File with filenames to find
filename_list_path = "/home/bhanu/Desktop/unique_in_file2.txt"

# Output file
output_path = "/home/bhanu/Desktop/cleaned_paths.txt"

# Read target filenames
with open(filename_list_path, "r") as f:
    target_filenames = set(line.strip() for line in f if line.strip())

matches = []

# Walk and find matching files
for root, dirs, files in os.walk(project_root):
    for file in files:
        if file in target_filenames:
            full_path = os.path.join(root, file)
            relative_path = os.path.relpath(full_path, project_root)
            matches.append(relative_path)

# Write cleaned paths
with open(output_path, "w") as f:
    for path in matches:
        f.write(path + "\n")

print(f"✅ Cleaned paths written to: {output_path}")
