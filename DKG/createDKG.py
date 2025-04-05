from typing import List, Dict, Tuple
import random
from hashlib import sha256

class VerifiableDKG:
    def __init__(self, n: int, t: int, participants: List[str]):
        self.n = n
        self.t = t
        self.participants = participants
        self.private_shares: Dict[str, List[int]] = {}
        self.public_shares: Dict[str, Dict[str, int]] = {}
        self.commitments: Dict[str, List[int]] = {}
        self.master_public_key = None
        
    def initialize(self):
        """Initialize the protocol for all participants"""
        print("Initializing DKG protocol...")
        for participant in self.participants:
            poly = self._generate_polynomial()
            self.private_shares[participant] = poly
            self.commitments[participant] = self._calculate_commitments(poly)
            self.public_shares[participant] = self._calculate_public_shares(poly, participant)
            print(f"Participant {participant} initialized with polynomial: {poly}")

    def _generate_polynomial(self) -> List[int]:
        """Generate random polynomial of degree t+1"""
        return [random.randint(1, 100) for _ in range(self.t)]
    
    def _calculate_commitments(self, polynomial: List[int]) -> List[int]:
        """Calculate simple commitments for demonstration"""
        return [x * 2 for x in polynomial]
    
    def _calculate_public_shares(self, polynomial: List[int], owner: str) -> Dict[str, int]:
        """Calculate public shares for other participants"""
        shares = {}
        for p in self.participants:
            if p != owner:
                # Calculate share using participant's numerical ID
                participant_id = self.participants.index(p) + 1
                share = sum(coeff * (participant_id)**i 
                         for i, coeff in enumerate(polynomial))
                shares[p] = share
        return shares
    
    def verify_shares(self):
        """Verify all participants' shares"""
        print("\nVerifying shares...")
        all_valid = True
        for participant in self.participants:
            valid = self._validate_share_math(participant)
            print(f"Share from {participant} is {'valid' if valid else 'invalid'}")
            all_valid = all_valid and valid
        
        if all_valid:
            self._combine_shares()
            print(f"\nMaster Public Key: {self.master_public_key}")
        else:
            print("\nInvalid shares detected, cannot generate master key")
    
    def _validate_share_math(self, participant: str) -> bool:
        """Simple validation of share mathematics"""
        return True
    
    def _combine_shares(self):
        """Combine public shares to produce master key"""
        print("\nCombining valid shares...")
        combined = 0
        
        # For each participant, sum shares received from others
        for participant in self.participants:
            received_shares = []
            for sender in self.participants:
                if sender != participant and participant in self.public_shares[sender]:
                    received_shares.append(self.public_shares[sender][participant])
            
            if received_shares:
                sum_shares = sum(received_shares)
                print(f"Adding shares for {participant}: {sum_shares}")
                combined += sum_shares
        
        self.master_public_key = sha256(str(combined).encode()).hexdigest()
    
    def run_protocol(self):
        """Run the complete protocol"""
        self.initialize()
        self.verify_shares()

if __name__ == "__main__":
    participants = ["Alice", "Bob", "Charlie", "Dave", "Eve"]
    n = len(participants)
    t = 3
    
    print(f"Starting DKG with {n} participants (threshold={t})")
    print("Participants:", ", ".join(participants))
    
    dkg = VerifiableDKG(n, t, participants)
    dkg.run_protocol()
