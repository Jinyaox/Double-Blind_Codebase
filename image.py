# this script implements the image class that takes in an image 
from PIL import Image as PILImage
import math

class CryptoImage:
    def __init__(self, image_path=None, block_num=None, blocks=None, original_size=None):
        """
        Initializes the Image either from a .ppm file path, or from a subset 
        of existing blocks (used by the crop method).
        """
        # self.blocks will be a dictionary mapping: spatial_index -> integer_value
        self.blocks = {}
        self.original_size = original_size  # (width, height)
        
        # Branch 1: Instantiate from a file path
        if image_path and block_num:
            self._load_and_partition(image_path, block_num)
        # Branch 2: Instantiate from a cropped subset
        elif blocks is not None:
            self.blocks = blocks
        else:
            raise ValueError("Must provide either (image_path and block_num) or (blocks).")

    def _get_grid_dimensions(self, width, height, block_num):
        """
        Smart Partitioning: Finds (cols, rows) that multiply to exactly block_num 
        while keeping the blocks as square as possible based on the image aspect ratio.
        """
        best_c, best_r = block_num, 1
        target_ratio = width / height
        best_diff = float('inf')

        # Find all factor pairs of block_num
        for r in range(1, int(math.sqrt(block_num)) + 1):
            if block_num % r == 0:
                c = block_num // r
                
                # Check how close this grid ratio is to the image aspect ratio
                diff1 = abs((c / r) - target_ratio)
                if diff1 < best_diff:
                    best_diff = diff1
                    best_c, best_r = c, r
                    
                diff2 = abs((r / c) - target_ratio)
                if diff2 < best_diff:
                    best_diff = diff2
                    best_c, best_r = r, c
        
        return best_c, best_r

    def _load_and_partition(self, image_path, block_num):
        """
        Reads the .ppm file, slices it into the smart grid, and converts 
        each block into a single large integer.
        """
        with PILImage.open(image_path) as img:
            # Enforce standard RGB mode so every pixel is strictly 3 bytes
            img = img.convert('RGB')
            width, height = img.size
            self.original_size = (width, height)
            
            cols, rows = self._get_grid_dimensions(width, height, block_num)
            
            block_w = width // cols
            block_h = height // rows
            
            index = 0
            for r in range(rows):
                for c in range(cols):
                    # Define the bounding box for the block (Left, Upper, Right, Lower)
                    left = c * block_w
                    upper = r * block_h
                    
                    # Handle edge boundaries smoothly if division isn't perfect
                    right = width if c == cols - 1 else (c + 1) * block_w
                    lower = height if r == rows - 1 else (r + 1) * block_h
                    
                    # Crop the 2D block
                    box = (left, upper, right, lower)
                    block_img = img.crop(box)
                    
                    # ----- CRYPTOGRAPHIC CONVERSION -----
                    # 1. Get raw RGB bytes from the block
                    block_bytes = block_img.tobytes()
                    # 2. Convert bytes directly to a single large Python Integer
                    block_int = int.from_bytes(block_bytes, byteorder='big')
                    
                    self.blocks[index] = block_int
                    index += 1

    def crop(self, indices):
        """
        Takes a list of spatial indices and returns a new CryptoImage 
        instance containing ONLY those blocks.
        """
        # Validate indices
        invalid_indices = [idx for idx in indices if idx not in self.blocks]
        if invalid_indices:
            raise ValueError(f"Indices not found in image: {invalid_indices}")
            
        # Extract the subset of blocks
        cropped_blocks = {idx: self.blocks[idx] for idx in indices}
        
        # Return a new instance using the alternative initialization branch
        return CryptoImage(blocks=cropped_blocks, original_size=self.original_size)


    # I will be using the overloaded operators to deal with the following
    def __getitem__(self, index):
        """
        Allows retrieving a block using bracket notation: img[index]
        Raises a KeyError if the spatial index doesn't exist, which is 
        standard Python behavior for bracket access.
        """
        return self.blocks[index]

    def __iter__(self):
        """
        Allows iterating directly over the blocks: for idx, block in img: ...
        Yields the (spatial_index, block_integer) pairs.
        """
        return iter(self.blocks.items())

    def __len__(self):
        """Returns the number of blocks currently held in this instance"""
        return len(self.blocks)