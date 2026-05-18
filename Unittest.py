import os
import random
import unittest
from bsp import *
from image import *
from crypto_ops import *
from py_ecc.optimized_bls12_381 import normalize
from oprf import OPRFServer, OPRFClient
from KZGpoly import TrustedSetup, KeyedKZGServer, KeyedKZGClient

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


class TestPairingCrypto(unittest.TestCase):
    
    def setUp(self):
        """Initialize the crypto wrapper and some dummy byte payloads for testing."""
        # Assuming you named the class PairingCrypto and imported it
        self.crypto = PairingCrypto() 
        self.test_payload_A = b"test_image_block_index_0_data_xyz"
        self.test_payload_B = b"test_image_block_index_1_data_abc"

    def test_hash_to_field(self):
        """Test that hashing to Z_p returns a valid, deterministic scalar."""
        scalar1 = self.crypto.hash_to_field(self.test_payload_A)
        scalar2 = self.crypto.hash_to_field(self.test_payload_A)
        
        self.assertIsInstance(scalar1, int)
        self.assertTrue(0 <= scalar1 < self.crypto.order, "Scalar is outside the field Z_p")
        self.assertEqual(scalar1, scalar2, "Hash to field is not deterministic")

    def test_hash_to_curve_G1(self):
        """Test that hashing to G1 returns a valid, deterministic curve point."""
        pt1 = self.crypto.hash_to_curve_G1(self.test_payload_A)
        pt2 = self.crypto.hash_to_curve_G1(self.test_payload_A)
        
        self.assertEqual(len(pt1), 3, "Point is not in projective coordinates (X, Y, Z)")
        self.assertEqual(pt1, pt2, "Hash to curve is not deterministic")

    def test_scalar_multiplication_and_addition(self):
        """
        Verify the homomorphic properties of the curve: 
        (a * M) + (b * M) == (a + b) * M
        """
        M = self.crypto.hash_to_curve_G1(self.test_payload_A)
        scalar_a = 15
        scalar_b = 27
        
        # Calculate left side: (a * M) + (b * M)
        pt_a = self.crypto.scalar_mult_G1(M, scalar_a)
        pt_b = self.crypto.scalar_mult_G1(M, scalar_b)
        sum_pt = self.crypto.add_G1(pt_a, pt_b)
        
        # Calculate right side: (a + b) * M
        expected_pt = self.crypto.scalar_mult_G1(M, scalar_a + scalar_b)
        
        # FIX: Normalize both points to Z=1 before asserting equality
        self.assertEqual(normalize(sum_pt), normalize(expected_pt), "Curve addition/multiplication algebra failed")

    def test_bilinear_pairing(self):
        """
        Verify the fundamental bilinearity property:
        e(a * P, b * Q) == e(ab * P, Q) == e(P, ab * Q)
        """
        a = 5
        b = 7
        
        P = self.crypto.G1
        Q = self.crypto.G2
        
        # e(a * P, b * Q)
        aP = self.crypto.scalar_mult_G1(P, a)
        bQ = self.crypto.scalar_mult_G2(Q, b)
        pairing_1 = self.crypto.evaluate_pairing(aP, bQ)
        
        # e(ab * P, Q)
        abP = self.crypto.scalar_mult_G1(P, a * b)
        pairing_2 = self.crypto.evaluate_pairing(abP, Q)
        
        self.assertEqual(pairing_1, pairing_2, "Bilinear pairing property failed!")
        
class TestDoubleBlindProtocol(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        """Initialize the core cryptography engine and generate mock dataset payloads."""
        cls.crypto = PairingCrypto()
        cls.num_blocks = 16
        
        # Simulate the output of CryptoImage.get_oprf_payload(j)
        # We use strict byte boundaries: 4 bytes for index j, plus dummy data
        cls.mock_payloads = {
            j: j.to_bytes(4, 'big') + f"_dummy_image_data_block_{j}".encode() 
            for j in range(cls.num_blocks)
        }

    def setUp(self):
        """Run the Trusted Setup and Offline Server Registration before each test."""
        # 1. TRUSTED SETUP
        self.srs = TrustedSetup(crypto=self.crypto, max_degree=self.num_blocks + 1)
        
        # 2. SERVER INITIALIZATION
        self.oprf_server = OPRFServer(self.crypto)
        self.kzg_server = KeyedKZGServer(self.crypto, self.srs)
        
        # 3. OFFLINE REGISTRATION PHASE
        self.indices = list(range(self.num_blocks))
        all_payloads = [self.mock_payloads[j] for j in self.indices]
        
        # Generate authentic tags
        self.authentic_tags = self.oprf_server.register_dataset(all_payloads)
        
        # Commit to the dataset
        self.C_sk = self.kzg_server.register_and_commit(self.indices, self.authentic_tags)

    def test_protocol_completeness(self):
        """
        Tests the honest execution of the protocol. 
        Proves Theorem 1 (Completeness).
        """
        # --- 1. CLIENT PREPARATION ---
        subset_indices = [2, 7, 14]
        subset_payloads = {j: self.mock_payloads[j] for j in subset_indices}
        
        oprf_client = OPRFClient(self.crypto)
        
        # Client blinds and shuffles their subset
        blinded_queries, unblinding_context = oprf_client.blind_subset(subset_payloads)
        
        # --- 2. ONLINE OPRF PHASE ---
        # Server blindly evaluates the queries
        server_responses = oprf_client.interact_with_server(self.oprf_server, blinded_queries)
        
        # Client unblinds the responses to recover the tags
        client_tags_dict = oprf_client.unblind_responses(server_responses, unblinding_context)
        
        # Verify OPRF Correctness: Client's tags must perfectly match Server's offline tags
        for j in subset_indices:
            self.assertEqual(
                client_tags_dict[j], 
                self.authentic_tags[j], 
                f"OPRF tag mismatch at index {j}!"
            )
            
        # --- 3. KEYED KZG VERIFICATION PHASE ---
        # Server provides the proofs for the requested subset
        proofs = [self.kzg_server.generate_keyed_proof(j, self.authentic_tags[j]) for j in subset_indices]
        
        # Client strictly orders their recovered tags to match the indices list
        client_tags_list = [client_tags_dict[j] for j in subset_indices]
        
        kzg_client = KeyedKZGClient(self.crypto, self.srs.srs_G2, self.kzg_server.pk)
        
        # Execute the batched folding verification
        is_valid = kzg_client.batch_verify(self.C_sk, subset_indices, client_tags_list, proofs)
        
        # The protocol should accept the honest proofs
        self.assertTrue(is_valid, "Batch verification failed on valid proofs.")

    def test_forgery_rejection_game_GFAB(self):
        """
        Tests the Data Forgery security game.
        If the Client maliciously alters a block (yielding a forged tag), 
        the Keyed KZG equation must reject it.
        """
        subset_indices = [3, 9]
        
        # Client attempts to verify an honest tag and a forged tag
        honest_tag = self.authentic_tags[3]
        forged_tag = (self.authentic_tags[9] + 1) % self.crypto.order # Simulating a modified block payload
        
        client_tags_list = [honest_tag, forged_tag]
        
        # Server provides valid proofs for the authentic indices
        proofs = [self.kzg_server.generate_keyed_proof(j, self.authentic_tags[j]) for j in subset_indices]
        
        kzg_client = KeyedKZGClient(self.crypto, self.srs.srs_G2, self.kzg_server.pk)
        
        # Execute the batched folding verification
        is_valid = kzg_client.batch_verify(self.C_sk, subset_indices, client_tags_list, proofs)
        
        # The protocol MUST reject the batch due to the forged tag
        self.assertFalse(is_valid, "Security Failure: Batch verification accepted a forged block tag!")

if __name__ == '__main__':
    unittest.main()