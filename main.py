from pycipher import SimpleSubstitution
from breaking.substitution import SubstitutionBreak

from util.transforms import Masker
from data.en import load_ngrams
from score.ngram import NgramScorer
import random

def break_substitution(plaintext, masker):
    # key1 = ['L', 'C', 'N', 'D', 'T', 'H', 'E', 'W', 'Z', 'S', 'A', 'R', 'X',
    #       'V', 'O', 'J', 'B', 'P', 'F', 'U', 'I', 'Q', 'M', 'K', 'G', 'Y']
    # key1 = ['Y', 'B', 'X', 'O', 'N', 'G', 'S', 'W', 'K', 'C', 'P', 'Z', 'F',
    #        'M', 'T', 'D', 'H', 'R', 'Q', 'U', 'J', 'V', 'E', 'L', 'I', 'A']

    # key1 = ['J', 'E', 'K', 'P', 'H', 'X', 'G', 'L', 'S', 'Z', 'R', 'T', 'C',
    #        'Y', 'W', 'A', 'D', 'B', 'F', 'M', 'Q', 'I', 'U', 'V', 'N', 'O']
    key1 = list('ABCDEFGHIJKLMNOPQRSTUVWXYZ')
    random.shuffle(key1)
    # print(key1)
    ciphertext = SimpleSubstitution(key1).encipher(plaintext)

    print("\nCiphertext:")
    print(masker.extend(ciphertext))
    #print("---\n")

    print("\nProcessing...\n")
    scorer = NgramScorer(load_ngrams(1))
    # breaker = SubstitutionBreak(scorer,seed = 42)
    breaker = SubstitutionBreak(scorer)


    # breaker.optimise(ciphertext, n=10) # for text
    # breaker.optimise(ciphertext, n=30) # for text
    breaker.optimise(ciphertext, n=3) # generate n local optima and choose the best
    decryption, score, key = breaker.guess(ciphertext)[0] # get the best local optima
    print("Substitution decryption (key={}, score={}):\n---\nPlaintext:\n{}".format(key, score, masker.extend(decryption)))


if __name__ == "__main__":
    with open("examples/text.txt", "r") as f:
        plaintext, masker = Masker.from_text(f.read())
    break_substitution(plaintext, masker)
