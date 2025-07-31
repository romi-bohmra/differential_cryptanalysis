Implemented a differential cryptanalysis attack on a SPN blick-cipher. 

The implementation includes creating a SPN cipher, generating a Differential Distribution Table and performing the differential attack on the cipher. 

Differential Cryptanalysis is a chosen-plaintext attack. In this implentation, a random plaintext is selected using the rand() function and the input/output difference is taken from a reference paper. 

The success of a differential cryptanalysis attack often depends on finding characteristics with a high probability of occurring. 

A characteristic is a sequence of input and output differences that are expected to occur with a certain probability. 

In differential cryptanalysis, we don’t need full decryption — just enough to test whether our expected output difference appears and therefore we perform partial decryption. 

The implementation of the attack is as follows:

Plaintext pairing: we choose random P₁, form P₂ = P₁ ⊕ ΔP, where ΔP (input difference) is taken from the reference paper. 
Ciphertexts: compute C₁ = E(P₁), C₂ = E(P₂) - Encryption using the SPN cipher created.
Filter: only keep cases where C₁ ⊕ C₂ has no “unexpected” bits (outside the two nibbles we target).
Key guesses: for each 8-bit candidate of the final subkey, partially decrypt C₁ and C₂ back to the input of the last S-box (partial decryption)

If the difference matches the expected ΔU₄ in those two nibbles, increment that guess’s counter.

Analysis: over many trials, the correct guess for those 8 bits will stand out with the highest count.
