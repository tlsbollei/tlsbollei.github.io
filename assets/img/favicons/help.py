import os

current_dir = os.getcwd()
print(current_dir)
print("Purging fiels in teh dir above")
for filename in os.listdir(current_dir):
    filepath = os.path.join(current_dir, filename)
    if os.path.isfile(filepath) and (filename.startswith("apple") or filename.startswith("android")):
        print(f"Deleting: {filename}")
        os.remove(filepath)

print("Cleanup complete.")
