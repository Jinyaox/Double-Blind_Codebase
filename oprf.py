import os
import random
from crypto_ops import PairingCrypto

class OPRFServer:
    def __init__(self, crypto: PairingCrypto, k_oprf: int = None):
        """
        Initializes the OPRF Server.
        If no master key is provided, it securely generates a new one.
        """
        self.crypto = crypto
        
        if k_oprf is None:
            # Generate a secure, 256-bit random scalar for the master key
            # and ensure it falls within the prime field Z_p
            raw_key = int.from_bytes(os.urandom(32), byteorder='big')
            self.k_oprf = raw_key % self.crypto.order
            
            # Highly improbable, but cryptographically rigorous
            if self.k_oprf == 0:
                self.k_oprf = 1
        else:
            self.k_oprf = k_oprf

    # ==========================================
    # OFFLINE PHASE: DATASET REGISTRATION
    # ==========================================

    def generate_authentic_tag(self, payload_bytes: bytes) -> int:
        """
        Computes the definitive KZG polynomial tag (T_j) for a known data block.
        This is used by the Server during Setup to commit to the dataset.
        
        Math: T_j = H_field( K_oprf * H_curve(j || m_j) )
        """
        # 1. Map the raw bytes to a base point on G1
        M_j = self.crypto.hash_to_curve_G1(payload_bytes)
        
        # 2. Evaluate using the master key
        V_j = self.crypto.scalar_mult_G1(M_j, self.k_oprf)
        
        # 3. Serialize the evaluated point and hash it down to a Z_p scalar
        V_j_bytes = self.crypto.serialize_G1(V_j)
        T_j = self.crypto.hash_to_field(V_j_bytes)
        
        return T_j

    def register_dataset(self, image_payloads: list[bytes]) -> list[int]:
        """
        Helper method to generate the complete set of tags {T_j} for an entire image.
        """
        return [self.generate_authentic_tag(payload) for payload in image_payloads]

    # ==========================================
    # ONLINE PHASE: INTERACTIVE VERIFICATION
    # ==========================================

    def evaluate_blinded_point(self, blinded_X_bytes: bytes) -> bytes:
        """
        The 2DH OPRF Server Evaluation step.
        Receives a blinded point X from the Client, evaluates it, and returns Y.
        
        Math: Y_j = K_oprf * X_j
        """
        # 1. Deserialize the network payload back into a mathematical G1 point
        X_pt = self.crypto.deserialize_G1(blinded_X_bytes)
        
        # 2. Perform the oblivious evaluation
        Y_pt = self.crypto.scalar_mult_G1(X_pt, self.k_oprf)
        
        # 3. Serialize the result back to bytes for network transmission
        return self.crypto.serialize_G1(Y_pt)

    def evaluate_blinded_batch(self, blinded_queries: list[bytes]) -> list[bytes]:
        """
        Helper method to process an entire array of blinded queries from the Client.
        """
        return [self.evaluate_blinded_point(x_bytes) for x_bytes in blinded_queries]
    

class OPRFClient:
    def __init__(self, crypto: PairingCrypto):
        """Initializes the OPRF Client."""
        self.crypto = crypto

    def blind_subset(self, subset_payloads: dict) -> tuple:
        """
        Takes a dictionary of {spatial_index: payload_bytes}.
        Returns the shuffled network payload and the local unblinding context.
        """
        blinded_queries = []
        unblinding_context = []
        
        # 1. Blind each payload
        for j, payload_bytes in subset_payloads.items():
            # Hash to the curve: M_j = H_curve(j || m_j)
            M_j = self.crypto.hash_to_curve_G1(payload_bytes)
            
            # Sample a random blinding scalar r_j from Z_p
            r_j = int.from_bytes(os.urandom(32), byteorder='big') % self.crypto.order
            if r_j == 0: r_j = 1
            
            # Blind the point: X_j = r_j * M_j
            X_j = self.crypto.scalar_mult_G1(M_j, r_j)
            
            # Serialize for network transmission
            X_j_bytes = self.crypto.serialize_G1(X_j)
            
            blinded_queries.append(X_j_bytes)
            # Store the context so we know how to unblind the response
            unblinding_context.append((j, r_j))
            
        # 2. SHUFFLE THE ARRAYS: this is a very important step
        # We must shuffle them together so the unblinding context matches the new network order.
        # This explicitly enforces the Index Privacy (Game 1) proof.
        combined = list(zip(blinded_queries, unblinding_context))
        random.shuffle(combined)
        
        shuffled_queries, shuffled_context = zip(*combined)
        
        return list(shuffled_queries), list(shuffled_context)

    def interact_with_server(self, server:OPRFServer, blinded_queries: list[bytes]) -> list[bytes]:
        """
        Simulates the network transmission to the Server.
        In a real deployment, this would be an HTTP POST or gRPC call.
        """
        # The server evaluates the batch and returns it in the exact same order
        return server.evaluate_blinded_batch(blinded_queries)

    def unblind_responses(self, server_responses: list[bytes], unblinding_context: list) -> dict:
        """
        Removes the blinding scalar and computes the final Z_p tags.
        Returns a dictionary mapping the original spatial index to the final tag: {j: T_j}
        """
        final_tags = {}
        
        for i, Y_j_bytes in enumerate(server_responses):
            # Retrieve the correct original index and blinding scalar for this array slot
            j, r_j = unblinding_context[i]
            
            # 1. Deserialize the Server's response Y_j
            Y_j = self.crypto.deserialize_G1(Y_j_bytes)
            
            # 2. Compute the modular inverse of the blinding factor: r^(-1) mod p
            # Python 3.8+ supports negative exponents in pow() for modular inversion!
            r_inv = pow(r_j, -1, self.crypto.order)
            
            # 3. Unblind the point: V_j = r^(-1) * Y_j
            V_j = self.crypto.scalar_mult_G1(Y_j, r_inv)
            
            # 4. Serialize and hash down to the scalar field: T_j = H_field(V_j)
            V_j_bytes = self.crypto.serialize_G1(V_j)
            T_j = self.crypto.hash_to_field(V_j_bytes)
            
            final_tags[j] = T_j
            
        return final_tags


# Example usage for the actual evaluation 
# # --- ONLINE PROTOCOL ---
# client = OPRFClient(crypto)

# # 1. Client blinds and shuffles the queries
# blinded_queries, context = client.blind_subset(payloads)

# # 2. Network transmission (Server evaluates oblivious of what the data is)
# server_responses = client.interact_with_server(server, blinded_queries)

# # 3. Client unblinds the responses to get the final KZG tags
# client_tags = client.unblind_responses(server_responses, context)