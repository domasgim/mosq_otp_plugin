from pypuf.simulation import XORArbiterPUF
from pypuf.io import random_inputs

puf = XORArbiterPUF(n=8, k=2, seed=3)
challenges = random_inputs(n=8, N=2, seed=2)
resp = puf.eval(challenges)
print(challenges)
print(resp)