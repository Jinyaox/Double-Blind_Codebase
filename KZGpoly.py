import os
import random
from crypto_ops import PairingCrypto

# ==========================================
# HELPER: FINITE FIELD POLYNOMIALS
# ==========================================

class PrimeFieldPoly:
    """Helper class to handle polynomial arithmetic over Z_p"""
    @staticmethod
    def lagrange_interpolate(x_coords: list, y_coords: list, p: int) -> list:
        """
        Interpolates points into a polynomial represented by a list of coefficients 
        [a_0, a_1, ..., a_d] where P(x) = a_0 + a_1*x + ... + a_d*x^d
        """
        k = len(x_coords)
        coeffs = [0] * k

        for j in range(k):
            # Compute the j-th Lagrange basis polynomial
            basis = [1]
            denominator = 1
            for m in range(k):
                if m != j:
                    # Multiply basis by (x - x_m)
                    new_basis = [0] * (len(basis) + 1)
                    for i in range(len(basis)):
                        new_basis[i + 1] = (new_basis[i + 1] + basis[i]) % p
                        new_basis[i] = (new_basis[i] - basis[i] * x_coords[m]) % p
                    basis = new_basis
                    
                    # Compute denominator scalar
                    denominator = (denominator * (x_coords[j] - x_coords[m])) % p

            # Multiply basis by y_j / denominator
            inv_denom = pow(denominator, -1, p)
            scalar = (y_coords[j] * inv_denom) % p
            
            for i in range(len(basis)):
                coeffs[i] = (coeffs[i] + basis[i] * scalar) % p

        # Trim trailing zeros
        while len(coeffs) > 1 and coeffs[-1] == 0:
            coeffs.pop()
        return coeffs

    @staticmethod
    def synthetic_division(poly: list, root: int, p: int) -> list:
        """
        Divides poly(x) by (x - root) using Ruffini's rule / synthetic division.
        Assumes root is a perfect root (remainder = 0).
        Returns the quotient polynomial coefficients.
        """
        d = len(poly) - 1
        q = [0] * d
        q[d - 1] = poly[d]
        for i in range(d - 2, -1, -1):
            q[i] = (poly[i + 1] + root * q[i + 1]) % p
        return q


# ==========================================
# 1. TRUSTED SETUP (GLOBAL PARAMETERS)
# ==========================================

### IMPORTANT note that this is only modeling the trusted setup -> NOT do it in production

class TrustedSetup:
    def __init__(self, crypto: PairingCrypto, max_degree: int):
        self.crypto = crypto
        
        # Sample the "toxic waste" secret s
        s_raw = int.from_bytes(os.urandom(32), byteorder='big')
        self.s = s_raw % self.crypto.order
        
        # Generate the Structured Reference String (SRS)
        self.srs_G1 = [self.crypto.G1]
        current_s = self.s
        for _ in range(max_degree):
            self.srs_G1.append(self.crypto.scalar_mult_G1(self.crypto.G1, current_s))
            current_s = (current_s * self.s) % self.crypto.order
            
        # We only need G2 and s*G2 for the verifier
        self.srs_G2 = [
            self.crypto.G2,
            self.crypto.scalar_mult_G2(self.crypto.G2, self.s)
        ]


# ==========================================
# 2. THE SERVER (PROVER) 
# ==========================================

class KeyedKZGServer:
    def __init__(self, crypto: PairingCrypto, srs: TrustedSetup):
        self.crypto = crypto
        self.srs = srs
        
        # Secret Key
        sk_raw = int.from_bytes(os.urandom(32), byteorder='big')
        self.sk = sk_raw % self.crypto.order
        
        # Public Key
        self.pk = self.crypto.scalar_mult_G2(self.crypto.G2, self.sk)
        
    def _evaluate_poly_on_srs(self, coeffs: list) -> tuple:
        """Computes the G1 commitment for a given polynomial using the SRS"""
        if len(coeffs) > len(self.srs.srs_G1):
            raise ValueError("Polynomial degree exceeds SRS capacity")
            
        # Start with the point at infinity
        result = self.crypto.Z1 
        for i, coeff in enumerate(coeffs):
            if coeff != 0:
                term = self.crypto.scalar_mult_G1(self.srs.srs_G1[i], coeff)
                result = self.crypto.add_G1(result, term)
        return result

    def register_and_commit(self, indices: list, tags: list) -> tuple:
        """
        Interpolates the dataset into P(x), computes the unkeyed C, 
        and returns the Keyed Commitment C_sk and the polynomial coefficients.
        """
        # 1. Interpolate P(x) such that P(j) = T_j
        self.P_coeffs = PrimeFieldPoly.lagrange_interpolate(indices, tags, self.crypto.order)
        
        # 2. Compute unkeyed standard KZG commitment: C = P(s)*G1
        self.C = self._evaluate_poly_on_srs(self.P_coeffs)
        
        # 3. Apply the hardware secret key: C_sk = sk * C
        C_sk = self.crypto.scalar_mult_G1(self.C, self.sk)
        return C_sk

    def generate_keyed_proof(self, index_j: int, tag_j: int) -> tuple:
        """
        Generates the Keyed KZG witness proof for a specific point.
        """
        # 1. Compute quotient polynomial Q_j(x) = (P(x) - T_j) / (x - j)
        P_minus_T = list(self.P_coeffs)
        P_minus_T[0] = (P_minus_T[0] - tag_j) % self.crypto.order
        
        Q_coeffs = PrimeFieldPoly.synthetic_division(P_minus_T, index_j, self.crypto.order)
        
        # 2. Evaluate unkeyed witness: W_j = Q_j(s)*G1
        W_j = self._evaluate_poly_on_srs(Q_coeffs)
        
        # 3. Apply the hardware secret key: \pi_{sk, j} = sk * W_j
        pi_sk_j = self.crypto.scalar_mult_G1(W_j, self.sk)
        return pi_sk_j


# ==========================================
# 3. THE CLIENT (VERIFIER)
# ==========================================

class KeyedKZGClient:
    def __init__(self, crypto: PairingCrypto, srs_G2: list, pk: tuple):
        self.crypto = crypto
        self.srs_G2 = srs_G2
        self.pk = pk

    def batch_verify(self, C_sk: tuple, indices: list, tags: list, proofs: list) -> bool:
        """
        Executes the highly optimized batched folding verification.
        Validates multiple proofs with exactly two pairings.
        """
        k = len(indices)
        
        # 1. Sample random scalars \gamma_j for folding
        gammas = [int.from_bytes(os.urandom(16), 'big') % self.crypto.order for _ in range(k)]
        
        # Initialize accumulators
        C_agg = self.crypto.Z1
        P_tag_agg = self.crypto.Z1
        W_agg = self.crypto.Z1
        
        # 2. Compute the aggregations (Algorithm 2 in your paper)
        for i in range(k):
            j = indices[i]
            T_j = tags[i]
            pi_sk_j = proofs[i]
            gamma_j = gammas[i]
            
            # --- C_agg Accumulation ---
            # gamma_j * C_sk
            term1 = self.crypto.scalar_mult_G1(C_sk, gamma_j)
            # (gamma_j * j) * pi_{sk, j}
            term2 = self.crypto.scalar_mult_G1(pi_sk_j, (gamma_j * j) % self.crypto.order)
            C_agg = self.crypto.add_G1(C_agg, self.crypto.add_G1(term1, term2))
            
            # --- P_tag_agg Accumulation ---
            # (gamma_j * T_j) * G1
            tag_term = self.crypto.scalar_mult_G1(self.crypto.G1, (gamma_j * T_j) % self.crypto.order)
            P_tag_agg = self.crypto.add_G1(P_tag_agg, tag_term)
            
            # --- W_agg Accumulation ---
            # gamma_j * pi_{sk, j}
            w_term = self.crypto.scalar_mult_G1(pi_sk_j, gamma_j)
            W_agg = self.crypto.add_G1(W_agg, w_term)

        # 3. The Bilinear Pairing Check
        # e(C_agg, G2) == e(P_tag_agg, pk) * e(W_agg, [s]_2)
        
        # Left Side
        lhs = self.crypto.evaluate_pairing(C_agg, self.srs_G2[0])
        
        # Right Side (Multiply the resulting FQ12 pairing elements)
        pair1 = self.crypto.evaluate_pairing(P_tag_agg, self.pk)
        pair2 = self.crypto.evaluate_pairing(W_agg, self.srs_G2[1])
        rhs = pair1 * pair2  # py_ecc overloads the * operator for FQ12 multiplication!
        
        return lhs == rhs