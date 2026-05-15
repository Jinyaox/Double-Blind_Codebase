from pathlib import Path

#-----------------------------------------The function that helps with the folder and input data processing------------------------------------------------
def get_random_ppm(folder_path):
    """
    Helper function to recursively find all .ppm files in a directory 
    and return a random one.
    """
    path = Path(folder_path)
    # rglob searches recursively. Use glob("*.ppm") if you only want the top level.
    ppm_files = list(path.rglob("*.ppm"))
    
    if not ppm_files:
        raise FileNotFoundError(f"No .ppm files found in directory: {folder_path}")
        
    random_file = random.choice(ppm_files)
    return str(random_file)