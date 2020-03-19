/* **************************************************************************************
 * working in Galois Field (2^8) 	      						*
 * operates within the Rijndaels finite field 						*
 * Used for AES encryption		      						*		      
 * This class is used like the Random class, where nothing is kept within the Object    *
 * ************************************************************************************ */

public class GaloisFieldOperations {
	//used to find the inverse within GF(2^8)     						*(1)*
	private final int MOD = 283;
	//round
	private final int[] rcon = new int[] {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6c, 0xd8, 0xab, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xef, 0xc5};
	
	// See http://mathforum.org/library/drmath/view/51675.html for more info on the inverse
	// top / bottom is the basic concept
	public int getInverse(int input) {
		//it is impossible to find the inverse of 0 so I made a catch case
		if(input == 0) {
			return 0;
		}
		

		//sets up the auxillary column
		int[] aux = new int[1 << 5];
		aux[1] = 1;

		//sets up the remainder column; the max possible number of quotients is 8
		//remainder[i] = remainder[i-2] % remainder[i-1]; basically the idea
		int[] remainder = new int[1 << 5];
		remainder[0] = MOD;
		remainder[1] = input;

		//quotient[i] = (remainder[i-2] / remainder[i-1]) iff i >= 2
		int[] quotient = new int[1 << 5];
		
		int index = 2;
		while(remainder[index-1] != 1) {
			//for the long division
			remainder[index] = remainder[index-2];

			//divides remainder[index-2] by remainder[index-1]
			do {
				//diffOfBitLengths = 2 ^ (bitLength(remainder[index-2]) - bitLength(remainder[index-1]))
				int diffOfBitLengths = Integer.highestOneBit(remainder[index]) / Integer.highestOneBit(remainder[index-1]);

				//numShift = how much to shift remainder[index-1] so the bit length is the same as remainder[index-2]
				int numShift = Integer.numberOfTrailingZeros(diffOfBitLengths);

				//sets remainder[index] to the remainder at the current step of the long division
				remainder[index] = remainder[index] ^ (remainder[index-1] << numShift);
				
				//sets quotient[index] to the quotient at the current step of the long division
				quotient[index] = quotient[index] ^ (1 << numShift);

			} while(remainder[index-1] < remainder[index]);

			//sets the current auxillary						*(2)*
			aux[index] = multiply(quotient[index], aux[index-1]) ^ aux[index-2];
			
			index++;
		}
		return aux[index-1];
	}
	
	//divides top by bottom
	public int divide(int top, int bottom) {
		int quotient = 0;
		do {
			//diffOfBitLengths = 2 ^ (bitLength(top) - bitLength(bottom))
			int diffOfBitLengths = Integer.highestOneBit(top) / Integer.highestOneBit(bottom);

			//numShift = how much to shift bottom so the bit length is the same as top
			int numShift = Integer.numberOfTrailingZeros(diffOfBitLengths);

			//subtraction in GF(2^8) = xor
			top ^= (bottom << numShift);

			//set quotient at the current step of the long division
			quotient ^= (1 << numShift);

		} while(bottom < top);

		return quotient;
	}

	//gets the remainder instead of quotient (see divide())
	public int mod(int top, int bottom) {
		if(top < bottom)
			return top;

		do {
			//diffOfBitLengths = 2 ^ (bitLength(top) - bitLength(bottom))
			int diffOfBitLengths = Integer.highestOneBit(top) / Integer.highestOneBit(bottom);

			//numShift = how much to shift bottom so the bit length is the same as top
			int numShift = Integer.numberOfTrailingZeros(diffOfBitLengths);

			top ^= (bottom << numShift);
		} while(bottom <= top);
		return top;
	}

	/* **********************************************************************
	 * multiplication in GF(2^8) is bit-wise not actual multiplication	*
	 * 	a * b = p							*
	 * 	p = p ^ (a << index of each bit in b)				*
	 * ******************************************************************** */
	public int multiply(int a, int b) {
		int product = 0;

		int getBits = b;
		while(getBits != 0) {
			int currentBit = Integer.lowestOneBit(getBits);
			
			product = product ^ (a << Integer.numberOfTrailingZeros(currentBit));
			
			getBits = getBits ^ currentBit;
		}
		
		if(Integer.highestOneBit(product) >= 256) {
			if(product > 283) {
				return mod(product, 283);
			}
			return mod(283, product);
		}
		return product;
	}

	public int add(int a, int b) {
		return a ^ b;
	}

	//used for the subBytes step; it is basically an arbitrary transformation of the bits to make it harder to crack
	public int affineEncrypt(int toEncrypt) {
		//arbitrary num to xor for proper affineTransformation
		int constant = 99;
		int result = toEncrypt;
		for(int i = 1; i <= 4; i++) {
			//left circular shift by 1
			toEncrypt = toEncrypt << 1;
			//check if highest bit is higher than 10000000
			if(Integer.highestOneBit(toEncrypt) > 128) {
				//the actual circular shifting part
				toEncrypt ^= 257;
			}
			result ^= toEncrypt;
		}
		return result ^ constant;
	}

	//used for the invSubBytes step; no, I cannot just do the opposite of the previous method. Don't ask why, it's complicated
	public int affineDecrypt(int toDecrypt) {
		//the formula is essentially (s <<< 1) + (s <<< 3) + (s <<< 6) + 5, where <<< is circular shift, + is basically xor
		int constant = 5;
		int result = 0;
		for(int i = 1, step = 1; step <= 6; i++, step += i) {
			int currentStep = leftCircularShift(toDecrypt, step);
			result ^= currentStep;
		}
		return result ^ constant;
	}	

	//used for the affine transformations in the subBytes and invSubBytes steps
	public int leftCircularShift(int num, int numShift) {
		int result = num;
		for(int i = 0; i < numShift; i++) {
			result = result << 1;
			if(Integer.highestOneBit(result) > 128) {
				//xors it by 1000000001, basically bringing the highest power to the beginning
				result ^= 257;
			}
		}
		return result;
	}

	//see https://en.wikipedia.org/wiki/Rijndael_key_schedule#Round_constants for more info
	//it is an arbitrary thing used only for AES encryption
	//rcon is actually a 1x4 matrix buuuuuuuut we don't need to worry about that, because the rest of the matrix is filled with 0s
	public int roundConstant(int round) {
		return rcon[round-1];
//		int rcon = 1 << (round-1);
//		
//		if(Integer.highestOneBit(rcon) >= 256) {
//			if(rcon < MOD) {
//				return mod(MOD, rcon);
//			}
//			else
//				return mod(rcon, MOD);
//		}
//		return rcon;
	}
}

/* **************************************************************
 * Footnotes:							*
 * (1) - 283 is an arbitrary number Rijndael made for AES steps	*
 * (2) - aux[i] = (quotient[i] * aux[i-1]) ^ aux[i-2]		*
 * ************************************************************ */
