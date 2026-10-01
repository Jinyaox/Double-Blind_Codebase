from crypto_ops import PairingCrypto
from oprf import OPRFServer, OPRFClient
from KZGpoly import TrustedSetup, KeyedKZGServer, KeyedKZGClient
# Assuming CryptoImage is in crypto_image.py
from image import CryptoImage

# ==========================================
# ALGORITHM 1: SETUP
# ==========================================

def Setup(max_image_blocks: int):
    """
    Executes the Trusted Setup phase.
    Returns the global parameters (pp) including the crypto engine and SRS.
    """
    crypto = PairingCrypto()
    # The SRS must be large enough to hold the maximum degree polynomial (number of blocks)
    srs = TrustedSetup(crypto, max_degree=max_image_blocks + 1)
    
    pp = {
        'crypto': crypto,
        'srs': srs
    }
    return pp


# ==========================================
# THE SERVER (Holds raw Dataset & Secret Keys)
# ==========================================

class ProtocolServer:
    def __init__(self, pp: dict):
        self.crypto = pp['crypto']
        self.srs = pp['srs']
        self.oprf_server = OPRFServer(self.crypto)
        self.kzg_server = KeyedKZGServer(self.crypto, self.srs)
        self.pk = self.kzg_server.pk
        
        self.dataset_image = None
        self.authentic_tags = {}
        self.public_proof_ledger = {} # NEW: Simulates a public bulletin board

    def Register(self, dataset: CryptoImage) -> tuple:
        """
        ALGORITHM 2: Registration
        Precomputes EVERYTHING offline.
        """
        self.dataset_image = dataset
        indices = []
        payloads = []
        
        for j, _ in dataset:
            indices.append(j)
            payloads.append(dataset.get_oprf_payload(j))
            
        tags_list = self.oprf_server.register_dataset(payloads)
        self.authentic_tags = {j: tag for j, tag in zip(indices, tags_list)}
        
        C_sk = self.kzg_server.register_and_commit(indices, tags_list)
        
        # FIX: Precompute all N proofs OFFLINE and publish to the ledger
        self.public_proof_ledger = {
            j: self.kzg_server.generate_keyed_proof(j, tag) 
            for j, tag in self.authentic_tags.items()
        }
        
        # Returns the commitment and the public proof array
        return C_sk, self.public_proof_ledger

    # --- Interactive Verification Endpoints ---

    def evaluate_oprf_queries(self, blinded_queries: list) -> list:
        """Endpoint 1: Obliviously evaluates the Client's blinded points."""
        return self.oprf_server.evaluate_blinded_batch(blinded_queries)


# ==========================================
# THE CLIENT (Holds subset, C_sk, & pk)
# ==========================================

class ProtocolClient:
    def __init__(self, pp: dict, pk: tuple):
        """Initializes the Client with public parameters and the hardware public key."""
        self.crypto = pp['crypto']
        self.pk = pk
        
        # Extract the G2 elements of the SRS for verification
        self.srs_G2 = pp['srs'].srs_G2
        
        # Initialize the underlying crypto clients
        self.oprf_client = OPRFClient(self.crypto)
        self.kzg_client = KeyedKZGClient(self.crypto, self.srs_G2, self.pk)

    # Change the Verify signature to accept the public_proofs from the ledger
    def Verify(self, subset: CryptoImage, C_sk: tuple, public_proofs: dict, server: ProtocolServer, total_image_blocks: int, pad_to_size: int) -> int:
        import os
        import random
        
        real_indices = [j for j, _ in subset]
        num_real = len(real_indices)
        
        if num_real > pad_to_size:
            raise ValueError(f"Subset size exceeds padding size.")
            
        padded_indices = list(real_indices)
        dummy_mask = [False] * num_real
        
        while len(padded_indices) < pad_to_size:
            random_j = random.randint(0, total_image_blocks - 1)
            if random_j not in padded_indices:
                padded_indices.append(random_j)
                dummy_mask.append(True)
                
        subset_payloads = {}
        for i, j in enumerate(padded_indices):
            if not dummy_mask[i]:
                subset_payloads[j] = subset.get_oprf_payload(j)
            else:
                random_pt = self.crypto.hash_to_curve_G1(os.urandom(32))
                subset_payloads[j] = self.crypto.serialize_G1(random_pt)
        
        blinded_queries, unblinding_context = self.oprf_client.blind_subset(subset_payloads)
        
        # Network Interaction: ONLY the OPRF evaluation happens online now
        server_responses = server.evaluate_oprf_queries(blinded_queries)
        
        recovered_tags_dict = self.oprf_client.unblind_responses(server_responses, unblinding_context)
        tags_list = [recovered_tags_dict[j] for j in padded_indices]
        
        # FIX: Client locally fetches proofs from the offline ledger, preserving privacy
        proofs = [public_proofs[j] for j in padded_indices]
        
        is_valid = self.kzg_client.batch_verify(
            C_sk, padded_indices, tags_list, proofs, dummy_mask=dummy_mask
        )
        
        return 1 if is_valid else 0