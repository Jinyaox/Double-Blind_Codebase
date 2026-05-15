import hashlib
# UPDATE THIS IMPORT: Change 'bls12_381' to 'optimized_bls12_381'
from py_ecc.optimized_bls12_381 import (
    G1, G2, Z1, Z2, 
    multiply, add, pairing, curve_order, 
    is_on_curve, b, field_modulus, FQ 
)

class PairingCrypto:
    def __init__(self):
        # The prime order of the scalar field (Z_p)
        self.order = curve_order
        
        # The generators for G1 and G2
        self.G1 = G1
        self.G2 = G2
        
        # The identity points (point at infinity) for G1 and G2
        self.Z1 = Z1
        self.Z2 = Z2

    # ==========================================
    # SCALAR FIELD OPERATIONS (Z_p)
    # ==========================================
    
    def hash_to_field(self, data_bytes: bytes) -> int:
        """
        Implements H_field. Hashes arbitrary bytes to a uniformly 
        distributed scalar in Z_p.
        """
        # Using SHA-256 (or SHA-512 for larger curves)
        h = hashlib.sha256(data_bytes).digest()
        scalar = int.from_bytes(h, byteorder='big')
        return scalar % self.order

    # ==========================================
    # ELLIPTIC CURVE OPERATIONS (G1)
    # ==========================================

    def scalar_mult_G1(self, pt, scalar: int):
        """Multiplies a point in G1 by a scalar (e.g., r * M_j)."""
        # py_ecc handles scalar reduction internally, but good practice to modulo
        return multiply(pt, scalar % self.order)

    def add_G1(self, pt1, pt2):
        """Adds two points in G1."""
        return add(pt1, pt2)

    def hash_to_curve_G1(self, payload_bytes: bytes):
        """
        Implements H_curve. Maps arbitrary bytes to a valid point in the G1 subgroup.
        Uses Try-and-Increment followed by Cofactor Clearing.
        """
        counter = 0
        while True:
            # 1. Hash the payload with a counter to get an x-coordinate candidate
            attempt = payload_bytes + counter.to_bytes(4, 'big')
            x_candidate = int.from_bytes(hashlib.sha256(attempt).digest(), 'big') % field_modulus
            
            # 2. Evaluate the curve equation y^2 = x^3 + 4
            x_fq = FQ(x_candidate)
            y_squared = (x_fq ** 3) + FQ(b)
            
            # 3. Check if y_squared is a quadratic residue (Euler's criterion)
            euler = y_squared ** ((field_modulus - 1) // 2)
            
            if euler == FQ(1):
                # Found a valid x! Calculate the exact square root for y.
                y_candidate = y_squared ** ((field_modulus + 1) // 4)
                
                # Construct the projective point (X, Y, Z=1)
                pt = (x_fq, y_candidate, FQ(1))
                
                # 4. COFACTOR CLEARING
                # Map the point strictly into the G1 prime-order subgroup.
                # This is the known effective cofactor for BLS12-381 G1.
                h_eff = 0x396c8c005555e1568c00aaab0000aaab
                
                safe_g1_pt = multiply(pt, h_eff)
                
                return safe_g1_pt
            
            counter += 1

    # ==========================================
    # BILINEAR PAIRING OPERATIONS (G1 x G2 -> GT)
    # ==========================================

    def scalar_mult_G2(self, pt, scalar: int):
        """Multiplies a point in G2 by a scalar (e.g., sk * G2 for public key)."""
        return multiply(pt, scalar % self.order)

    def evaluate_pairing(self, point_G1, point_G2):
        """
        Computes the optimal Ate pairing e(G1, G2) -> GT.
        Note: py_ecc's pairing function takes (G2, G1) as arguments!
        """
        # py_ecc syntax is pairing(Q, P) where Q is in G2, P is in G1
        return pairing(point_G2, point_G1)