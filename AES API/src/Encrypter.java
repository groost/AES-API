
//some parts of the AES encryption is too complicated to explain in comments, so I will explain as much as possible. if you google aes encryption, you will find the exact things i am referencing and learn there
/*
 * THIS IS AN AES_128 OCB ENCRYPTION
 * This class processes the array key to xor with the state
 * This class encrypts the IV each time to create the next iteration
 */

public class Encrypter {
	// number of rounds for AES_128 encryption
	private final int NUM_ROUNDS_128 = 15;

	// my own class for the finite field operations
	private final GaloisFieldOperations g = new GaloisFieldOperations();

	// used for the mix_columns method
	private final int[] MIXCOLUMN_MULTIPLIER = new int[] { 2, 3, 1, 1 };

	// used for the output
	public StringBuilder res = new StringBuilder("");

	// hardcoded sbox-lookup table
	private final int[] sbox = new int[] { 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe,
			0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72,
			0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04,
			0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c,
			0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20,
			0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33,
			0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc,
			0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e,
			0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde,
			0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4,
			0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba,
			0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5,
			0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69,
			0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42,
			0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

	// all contain ascii values
	private int[][] key;
	private int[][] expandedKey;
	private int[][] state;

	public Encrypter(String key, String IV) {
		this.key = new int[4][4];
		this.state = new int[4][4];
		this.expandedKey = new int[NUM_ROUNDS_128 * 4][4];

		int index = 0;
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4 && index < key.length(); j++, index += 2) {
				this.key[i][j] = Integer.parseInt(key.substring(index, index + 2), 16);
			}
		}

		keyExpansion();
		
		index = 0;
		this.state = new int[4][4];
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4 && index < IV.length() - 1; j++, index += 2) {
				this.state[j][i] = Integer.parseInt(IV.substring(index, index + 2), 16);
			}
		}
	}

	// combines the state with the ith set of 4 rows in the expanded key
	private void addRoundKey(int round) {
		int index = round;
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				state[j][i] ^= expandedKey[(index * 4) + i][j];
			}
		}
	}

	// does the rounds of the encryption
	public void runEncryption() {
		res = new StringBuilder();

		// combining the initial key with the input
		addRoundKey(0);

		// rounds 1-9
		for (int round = 1; round <= NUM_ROUNDS_128 - 1; round++) {
			shiftRows();
			mixColumns();
			addRoundKey(round);
		}

		// round 10 AKA final round
		// don't ask me why we don't mixColumns in the last round, because I don't know
		shiftRows();
		addRoundKey(14);

		res.append(getEncrypt());
	}

	// google it, i can't explain it in words (without visuals)
	// it is arbitrary matrix multiplication modulo 283
	private void mixColumns() {
		for (int mainColumn = 0; mainColumn < 4; mainColumn++) {
			int[] multiplier = MIXCOLUMN_MULTIPLIER;
			int[] newColumn = new int[4];
			for (int col = 0; col < 4; col++) {
				for (int row = 0; row < 4; row++) {
					newColumn[col] ^= g.multiply(state[row][mainColumn], multiplier[row]);
				}
				multiplier = rightShift(multiplier);
			}
			for (int row = 0; row < 4; row++) {
				state[row][mainColumn] = newColumn[row];
			}
		}
	}

	// right circular shifts the array by 1
	private int[] rightShift(int[] arr) {
		int[] result = new int[arr.length];
		result[0] = arr[arr.length - 1];
		for (int i = 1; i < arr.length; i++) {
			result[i] = arr[i - 1];
		}
		return result;
	}

	// left circular shifts each row of the state by i
	private void shiftRows() {
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < i; j++) {
				state[i] = rotWord(state[i]);
			}
		}
	}

	// left circular shifts the array by 1
	public int[] rotWord(int[] arr) {
		int[] result = new int[arr.length];
		result[arr.length - 1] = sbox[arr[0]];
		for (int i = 0; i < arr.length - 1; i++) {
			result[i] = sbox[arr[i + 1]];
		}
		return result;
	}

	/*
	 * *****************************************************************************
	 * Expanding the key works as follows: 
	 * expandedKey[i] = {
	 * key[i] if i < 4
	 * expandedKey[i-4] + RotWord(SubWord(expandedKey[i-1])) + GaloisFieldOperations.roundConstant(i/4) if i >= 4 and (i % 4) == 0
	 * expandedKey[i-4] + expandedKey[i-1] otherwise 
	 * };
	 * *****************************************************************************
	 */
	private void keyExpansion() {

		for (int i = 0; i < 4; i++)
			expandedKey[i] = key[i];

		for (int i = 4; i < expandedKey.length; i++) {
			int[] curr = expandedKey[i - 1];
			if (i % 4 == 0) {
				curr = rotWord(curr);
				curr[0] ^= g.roundConstant(i / 4);
			}

			for (int j = 0; j < 4; j++) {
				expandedKey[i][j] = expandedKey[i - 4][j] ^ curr[j];
			}

		}

	}

	//tansfers the array to a parsable string
	public String getEncrypt() {
		String line = "";
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				String hex = Integer.toHexString(state[j][i]);
				if (hex.length() == 1) {
					hex = "0" + hex;
				}
				line += hex;
			}
		}
		return line;
	}
}
