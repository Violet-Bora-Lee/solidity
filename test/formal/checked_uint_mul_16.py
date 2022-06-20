from opcodes import AND, ISZERO, GT, DIV, MUL
from rule import Rule
from util import BVUnsignedUpCast, BVUnsignedMax
from z3 import BitVec, Not, BVMulNoOverflow

"""
Overflow checked unsigned integer multiplication.
"""

# Approximation with 16-bit base types.
n_bits = 16

for type_bits in [4, 8, 12, 16]:

	rule = Rule()

	# Input vars
	X_short = BitVec('X', type_bits)
	Y_short = BitVec('Y', type_bits)

	# Z3's overflow condition
	actual_overflow = Not(BVMulNoOverflow(X_short, Y_short, False))

	# cast to full n_bits values
	X = BVUnsignedUpCast(X_short, n_bits)
	Y = BVUnsignedUpCast(Y_short, n_bits)
	product = MUL(X, Y)

	# Constants
	maxValue = BVUnsignedMax(type_bits, n_bits)

	# Overflow check in YulUtilFunction::overflowCheckedIntMulFunctions
	if type_bits > n_bits / 2:
		overflow_check = AND(ISZERO(ISZERO(X)), GT(Y, DIV(maxValue, X)))
	else:
		overflow_check = GT(product, maxValue)
	rule.check(overflow_check != 0, actual_overflow)
