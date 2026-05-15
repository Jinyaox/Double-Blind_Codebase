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


    def test_oprf_payload_structure(self):
        """Test that the payload correctly concatenates the 4-byte index and the block integer."""
        target_index = 5
        block_int = self.image[target_index]
        payload = self.image.get_oprf_payload(target_index)
        
        self.assertIsInstance(payload, bytes)
        self.assertTrue(len(payload) > 4) # 4 bytes for index + at least 1 byte for data
        
        # Unpack the payload to verify strict boundaries
        extracted_index = int.from_bytes(payload[:4], byteorder='big')
        extracted_block = int.from_bytes(payload[4:], byteorder='big')
        
        self.assertEqual(extracted_index, target_index, "The 4-byte index header was malformed.")
        self.assertEqual(extracted_block, block_int, "The block data was corrupted during byte conversion.")

    def test_crop_preserves_absolute_payload(self):
        """Test that cropping does not alter the OPRF payload for a given absolute index."""
        target_indices = [5, 10, 15]
        subset = self.image.crop(target_indices)
        
        for idx in target_indices:
            original_payload = self.image.get_oprf_payload(idx)
            subset_payload = subset.get_oprf_payload(idx)
            
            # This is the most critical test for your OPRF verification!
            self.assertEqual(
                original_payload, 
                subset_payload, 
                f"Payload mismatch at index {idx} after cropping!"
            )

    def test_oprf_payload_invalid_index(self):
        """Test that requesting a payload for a missing index raises a KeyError."""
        bad_index = 999
        with self.assertRaises(KeyError):
            self.image.get_oprf_payload(bad_index)
            
        # Also ensure cropped images reject indices they shouldn't have
        subset = self.image.crop([0, 1, 2])
        with self.assertRaises(KeyError):
            subset.get_oprf_payload(15)

if __name__ == '__main__':
    unittest.main()