import os
import random
import unittest
from bsp import *
from image import *

class TestCryptoImage(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        """
        Creates a temporary 100x100 .ppm image for reliable, reproducible testing 
        without relying on external files.
        """
        cls.test_img_path = "test_dummy.ppm"
        img = PILImage.new('RGB', (100, 100), color='red')
        img.save(cls.test_img_path)

    @classmethod
    def tearDownClass(cls):
        """Cleans up the temporary test image."""
        if os.path.exists(cls.test_img_path):
            os.remove(cls.test_img_path)

    def setUp(self):
        """Initialize a fresh CryptoImage instance before each test."""
        # Requesting 16 blocks from a square image should yield a 4x4 grid
        self.block_num = 16
        self.image = CryptoImage(image_path=self.test_img_path, block_num=self.block_num)

    def test_initialization_and_partitioning(self):
        """Test that the image is loaded and partitioned into the correct number of blocks."""
        self.assertEqual(len(self.image), self.block_num)
        self.assertEqual(self.image.original_size, (100, 100))

    def test_block_type(self):
        """Test that the partitioned blocks are strictly Python integers."""
        block = self.image[0]
        self.assertIsInstance(block, int)
        self.assertGreater(block, 0) # Should be a massive positive integer

    def test_crop_valid_indices(self):
        """Test that cropping returns a new instance with the correct subset."""
        target_indices = [0, 5, 15]
        subset = self.image.crop(target_indices)
        
        self.assertEqual(len(subset), 3)
        self.assertIsInstance(subset, CryptoImage)
        
        # Verify the integer values were perfectly copied over
        for idx in target_indices:
            self.assertEqual(subset[idx], self.image[idx])

    def test_crop_invalid_indices(self):
        """Test that cropping with non-existent indices raises an error."""
        bad_indices = [0, 999] # 999 does not exist in a 16-block image
        with self.assertRaises(ValueError):
            self.image.crop(bad_indices)

    def test_magic_getitem(self):
        """Test the bracket [] access notation."""
        # Should succeed
        val = self.image[5]
        self.assertIsNotNone(val)
        
        # Should raise KeyError for missing blocks
        with self.assertRaises(KeyError):
            _ = self.image[99]

    def test_magic_iter(self):
        """Test that the instance can be iterated over cleanly."""
        iterations = 0
        for j, m_j in self.image:
            self.assertIsInstance(j, int)
            self.assertIsInstance(m_j, int)
            iterations += 1
            
        self.assertEqual(iterations, self.block_num)

if __name__ == '__main__':
    unittest.main()