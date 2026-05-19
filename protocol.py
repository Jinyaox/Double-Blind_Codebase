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
        """Initializes the Server with the public parameters and generates secret keys."""
        self.crypto = pp['crypto']
        self.srs = pp['srs']
        
        # Initialize the underlying crypto servers (which generate K_oprf and sk)
        self.oprf_server = OPRFServer(self.crypto)
        self.kzg_server = KeyedKZGServer(self.crypto, self.srs)
        
        # The public key to be shared with the Client
        self.pk = self.kzg_server.pk
        
        # Internal state to hold the dataset mapping and tags after registration
        self.dataset_image = None
        self.authentic_tags = {}

    def Register(self, dataset: CryptoImage) -> tuple:
        """
        ALGORITHM 2: Registration
        The Server processes the full dataset, computes the authentic tags, 
        and generates the public ledger commitment C_sk.
        """
        self.dataset_image = dataset
        indices = []
        payloads = []
        
        # 1. Extract payloads from the full image
        for j, _ in dataset:
            indices.append(j)
            payloads.append(dataset.get_oprf_payload(j))
            
        # 2. Generate authentic tags using the OPRF master key
        tags_list = self.oprf_server.register_dataset(payloads)
        
        # Store tags internally for later proof generation
        self.authentic_tags = {j: tag for j, tag in zip(indices, tags_list)}
        
        # 3. Generate the Keyed KZG Commitment (Anchored to the public ledger)
        C_sk = self.kzg_server.register_and_commit(indices, tags_list)
        
        return C_sk

    # --- Interactive Verification Endpoints ---

    def evaluate_oprf_queries(self, blinded_queries: list) -> list:
        """Endpoint 1: Obliviously evaluates the Client's blinded points."""
        return self.oprf_server.evaluate_blinded_batch(blinded_queries)

    def request_proofs(self, requested_indices: list) -> list:
        """Endpoint 2: Generates Keyed KZG proofs for the requested indices."""
        # The Server assumes honesty during proof generation; the math will 
        # naturally fail on the Client's side if the Server lies here.
        return [
            self.kzg_server.generate_keyed_proof(j, self.authentic_tags[j]) 
            for j in requested_indices
        ]


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

    def Verify(self, subset: CryptoImage, C_sk: tuple, server: ProtocolServer, total_image_blocks: int, pad_to_size: int) -> int:
        """
        ALGORITHM 3: Interactive Subset Verification (with Side-Channel Protection)
        Executes the padded double-blind protocol against the Server instance.
        """
        import os
        import random
        
        real_indices = [j for j, _ in subset]
        num_real = len(real_indices)
        
        # --- 1. QUERY PADDING (Side-Channel Protection) ---
        if num_real > pad_to_size:
            raise ValueError(f"Subset size ({num_real}) exceeds padding size ({pad_to_size}).")
            
        padded_indices = list(real_indices)
        dummy_mask = [False] * num_real
        
        # Pad with random, unrequested indices to obscure the crop size
        while len(padded_indices) < pad_to_size:
            random_j = random.randint(0, total_image_blocks - 1)
            # Ensure we don't accidentally duplicate an index in the batch
            if random_j not in padded_indices:
                padded_indices.append(random_j)
                dummy_mask.append(True)
                
        # 2. Extract real payloads and generate fake ones
        subset_payloads = {}
        for i, j in enumerate(padded_indices):
            if not dummy_mask[i]:
                # Authentic block
                subset_payloads[j] = subset.get_oprf_payload(j)
            else:
                # Dummy block: Hash random bytes to the curve to create a mathematically valid fake point
                random_pt = self.crypto.hash_to_curve_G1(os.urandom(32))
                subset_payloads[j] = self.crypto.serialize_G1(random_pt)
        
        # 3. OPRF Blinding Phase (This automatically shuffles the real and dummy queries together!)
        blinded_queries, unblinding_context = self.oprf_client.blind_subset(subset_payloads)
        
        # 4. Network Interaction 1: Send to Server
        server_responses = server.evaluate_oprf_queries(blinded_queries)
        
        # 5. OPRF Unblinding Phase 
        recovered_tags_dict = self.oprf_client.unblind_responses(server_responses, unblinding_context)
        
        # 6. Network Interaction 2: Request KZG Proofs
        proofs = server.request_proofs(padded_indices)
        
        # Align tags and proofs with the padded order
        tags_list = [recovered_tags_dict[j] for j in padded_indices]
        
        # 7. Keyed KZG Batched Verification (Zero-Weighting the dummies)
        is_valid = self.kzg_client.batch_verify(
            C_sk, padded_indices, tags_list, proofs, dummy_mask=dummy_mask
        )
        
        return 1 if is_valid else 0