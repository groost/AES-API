import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Random;

public class AESCipher {
	private ArrayList<String> encryptionIterations;
	private Encrypter encrypt;
	private String key;
	private String iv;
	private HashMap<Integer, Integer> hexConversion = new HashMap<Integer, Integer>();
	private String tempDirectory;
	private PrintWriter out;
	private final char[] HEX_ARR = "0123456789ABCDEF".toCharArray();

	public AESCipher() {
		this.key = generateHexKey();
		this.iv = generateHexKey();

		this.encrypt = new Encrypter(key, iv);
		this.encryptionIterations = new ArrayList<String>();

		tempDirectory = System.getProperty("user.dir");
		initializeHashMap();
	}

	public String getKey() {
		return key;
	}

	public String getIV() {
		return iv;
	}

	public String generateHexKey() {
		String ret = "";
		Random r = new Random();

		for (int i = 0; i < 32; i++) {
			ret += HEX_ARR[r.nextInt(16)];
		}

		return ret;
	}

	public AESCipher(String key, String iv) {
		this.key = key;
		this.iv = iv;
		this.encrypt = new Encrypter(key, iv);
		this.encryptionIterations = new ArrayList<String>();
		tempDirectory = System.getProperty("user.dir");
		initializeHashMap();
	}

	public void initializeHashMap() {
		for (int i = 48; i < 58; i++) {
			hexConversion.put(i, i - 48);
		}

		for (int i = 97; i < 103; i++) {
			hexConversion.put(i, i - 97);
		}
	}

	public File decryptFile(File inputFile) {
		StringBuilder decryptedText = new StringBuilder();
		try {
			BufferedReader sc = new BufferedReader(new FileReader(inputFile));

			ArrayList<int[]> list = new ArrayList<int[]>();

			int index = 0;
			inputLoop: while (sc.ready()) {
				int[] arr = new int[16];
				String encryptionLine = null;
				if (encryptionIterations.size() > index) {
					encryptionLine = encryptionIterations.get(index);
				} else {
					encrypt.runEncryption();
					encryptionLine = encrypt.res.toString();
					encryptionIterations.add(encryptionLine);
				}

				for (int i = 0; i < 16 && sc.ready(); i++) {
					char[] inputArr = new char[2];
					sc.read(inputArr);

					if (!Character.isLetterOrDigit(inputArr[0])) {
						break inputLoop;
					}

					String combine = inputArr[0] + "" + inputArr[1];
					arr[i] = Integer.parseInt(combine, 16);
				}

				for (int i = 0; i < 16; i++) {
					arr[i] ^= Integer.parseInt(encryptionLine.substring(i * 2, i * 2 + 2), 16);
					if (arr[i] == 0) {
						continue;
					}
					decryptedText.append((char) arr[i]);
				}
				list.add(arr);
				index++;
			}

			BufferedWriter out = new BufferedWriter(new FileWriter(inputFile));
			out.write(decryptedText.toString());
			out.flush();
			out.close();

			return inputFile;
		} catch (FileNotFoundException file) {
			return null;
		} catch (IOException io) {
			return null;
		}
	}

	public String decryptString(String input) {

		// used for time efficiency
		char[] inputArray = input.toCharArray();

		// used for time efficiency as well
		StringBuilder output = new StringBuilder();

		// used for the encryption
		int[] state = new int[16];

		int index = 0;
		int stateIndex = 0;
		int encryptionIndex = 0;

		for (stateIndex = 0; index < inputArray.length; index += 2, stateIndex++) {
			state[stateIndex] = Integer.parseInt(inputArray[index] + "" + inputArray[index + 1], 16);

			if (stateIndex == 15) {
				String encryptionLine = null;
				if (encryptionIterations.size() > encryptionIndex) {
					encryptionLine = encryptionIterations.get(encryptionIndex);
				} else {
					encrypt.runEncryption();
					encryptionLine = encrypt.res.toString();
					encryptionIterations.add(encryptionLine);
				}

				for (int i = 0; i < 16; i++) {
					state[i] ^= Integer.parseInt(encryptionLine.substring(i * 2, i * 2 + 2), 16);
					if (state[i] == 0)
						continue;

					output.append((char) state[i] + "");
				}

				stateIndex = -1;
				state = new int[16];
				encryptionIndex++;
			}

		}

		if (stateIndex > 0) {
			encrypt.runEncryption();
			StringBuilder encryptLine = encrypt.res;
			for (int i = 0; i < 16; i++) {
				state[i] ^= Integer.parseInt(encryptLine.substring(i * 2, i * 2 + 2), 16);

				if (state[i] == 0)
					continue;

				output.append((char) state[i] + "");
			}
		}

		return output.toString();
	}

	public void encryptFile(File inputFile) throws IOException, FileNotFoundException {
		BufferedReader sc = new BufferedReader(new FileReader(inputFile));

		// I use this instead of just printing it directly to a file because I replace
		// the inputFile with its encrypted counterpart
		StringBuilder encryptedText = new StringBuilder("");

		int index = 0;
		while (sc.ready()) {
			int[] state = new int[16];
			String encryptionLine = null;

			// checks if the current required encryption iteration has already been
			// processed before
			if (encryptionIterations.size() > index) {
				encryptionLine = encryptionIterations.get(index);
			} else {
				encrypt.runEncryption();
				encryptionLine = encrypt.res.toString();
				encryptionIterations.add(encryptionLine);
			}

			for (int i = 0; i < 16 && sc.ready(); i++) {
				state[i] = sc.read();
			}

			// i separated this for loop and the one just above this because it needs to
			// encrypt the whole arr array regardless of whether or not there are enough
			// characters to fill it
			for (int i = 0; i < 16; i++) {
				// xors the input state and the encryption iteration to get the encrypted text
				state[i] ^= Integer.parseInt(encryptionLine.substring(i * 2, i * 2 + 2), 16);

				// converts the int state at the current index to a hex string
				String toHex = Integer.toHexString(state[i]);

				// makes sure the length of the hex value is 2
				if (toHex.length() == 1) {
					toHex = "0" + toHex;
				}

				encryptedText.append(toHex);
			}

			index++;
		}

		sc.close();

		// overwrites the input file and replaces it with its encrypted counterpart
		out = new PrintWriter(new FileWriter(inputFile));
		out.print(encryptedText.toString());

		out.flush();
		out.close();

	}

	public String encryptString(String input) {
		// used for time efficiency
		char[] inputArray = Arrays.copyOf(input.toCharArray(),
				input.length() + (input.length() + (16 - (input.length() % 16))));
		for (int index = input.length(); index < inputArray.length; index++) {
			inputArray[index] = ' ';
		}

		// used for time efficiency as well
		StringBuilder output = new StringBuilder();

		// used for the encryption
		int[] state = new int[16];

		// the first index links to the input, stateIndex links to the state array,
		// encryptionIndex links to the encryption key list
		int index = 0;
		int stateIndex = 0;
		int encryptionIndex = 0;

		// loops through the input
		for (stateIndex = 0; index < inputArray.length; index++, stateIndex++) {
			state[stateIndex] = (int) inputArray[index];

			// checks to see if the state array is full of input values
			if (stateIndex == 15) {
				String encryptionLine = null;

				// checks to see if the current iteration of the encryption has already been
				// processed before
				// if not, it creates the iteration and stores it for later use
				if (encryptionIterations.size() > encryptionIndex) {
					encryptionLine = encryptionIterations.get(encryptionIndex);
				} else {
					encrypt.runEncryption();
					encryptionLine = encrypt.res.toString();
					encryptionIterations.add(encryptionLine);
				}

				// xors the input values with the encryption iteration to encrypt the input
				for (int i = 0; i < 16; i++) {
					state[i] ^= Integer.parseInt(encryptionLine.substring(i * 2, i * 2 + 2), 16);

					// converts the int value to a hexadecimal string
					String toHex = Integer.toHexString(state[i]);

					// makes sure that the length is 2
					if (toHex.length() == 1) {
						toHex = "0" + toHex;
					}

					output.append(toHex);
				}

				stateIndex = -1;
				state = new int[16];
				encryptionIndex++;
			}
		}

		// checks to see if there are any stragglers meaning that the input is not a
		// multiple of 16
		if (stateIndex > 0) {
			encrypt.runEncryption();
			encryptionIterations.add(encrypt.res.toString());

			StringBuilder encryptLine = encrypt.res;

			// functions same as above
			for (int i = 0; i < 16; i++) {
				state[i] ^= Integer.parseInt(encryptLine.substring(i * 2, i * 2 + 2), 16);
				String toHex = Integer.toHexString(state[i]);
				if (toHex.length() == 1) {
					toHex = "0" + toHex;
				}
				output.append(toHex);
			}
		}

		return output.toString().trim();
	}

	public void finalizeEncryptionFile() {
		out.flush();
		out.close();
	}
}
