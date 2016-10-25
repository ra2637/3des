package encryption.block;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import utils.ByteHelper;
import utils.HexBinary;

public class Blocks {
	public static byte[] ECBMode(String[] keys, byte[] inputText, boolean isEncrypt) {
		byte[] source = inputText;
		boolean isInternalEncrypt = isEncrypt;
		byte[] result = null;

		for (int k = 0; k < 3; k++) {
			byte[] key = HexBinary.decode(keys[k]);
			result = null;
			for (int i = 0; i < source.length; i += 8) {
				byte[] block = ByteHelper.subByte(source, i, 8);

				block = runBlock(key, block, isInternalEncrypt);
				result = ByteHelper.concatByte(result, block);
			}
			source = result;
			isInternalEncrypt = !isInternalEncrypt;
		}
		return result;
	}

	public static byte[] CBCMode(String[] keys, byte[] inputText, boolean isEncrypt) {
		if (isEncrypt) {
			byte[] initIV = generateInitialVector(8);
			byte[] source = inputText;
			source = CBCEncrypt(HexBinary.decode(keys[0]), source, initIV);
			source = CBCDecrypt(HexBinary.decode(keys[1]), source, initIV);
			source = CBCEncrypt(HexBinary.decode(keys[2]), source, initIV);
			byte[] result = ByteHelper.concatByte(source, initIV);
			return result;
		} else {
			byte[] initIV = ByteHelper.subByte(inputText, inputText.length - 8, 8);
			byte[] source = ByteHelper.subByte(inputText, 0, inputText.length - 8);
			source = CBCDecrypt(HexBinary.decode(keys[0]), source, initIV);
			source = CBCEncrypt(HexBinary.decode(keys[1]), source, initIV);
			source = CBCDecrypt(HexBinary.decode(keys[2]), source, initIV);
			return source;
		}
	}

	private static byte[] CBCEncrypt(byte[] key, byte[] inputText, byte[] initIV) {
		byte[] result = new byte[inputText.length];

		for (int i = 0; i < inputText.length; i += 8) {
			byte[] block = new byte[8];
			for (int j = 0; j < block.length; j++) {
				block[j] = (byte) (inputText[i + j] ^ initIV[j]);
			}
			block = runBlock(key, block, true);
			for (int j = 0; j < block.length; j++) {
				result[i+j] = block[j];
			}
			initIV = block;
		}
		return result;
	}

	private static byte[] CBCDecrypt(byte[] key, byte[] inputText, byte[] initIV) {
		byte[] result = new byte[inputText.length];

		for (int i = 0; i < result.length; i += 8) {
			byte[] block = ByteHelper.subByte(inputText, i, 8);
			byte[] roundBlock = runBlock(key, block, false);
			for (int j = 0; j < block.length; j++) {
				result[i + j] = (byte) (roundBlock[j] ^ initIV[j]);
			}
			initIV = block;
		}
		return result;
	}

	public static byte[] CTRMode(String[] keys, byte[] inputText, boolean isEncrypt) {
		if (isEncrypt) {
			byte[] initIV = generateInitialVector(4);
			byte[] source = inputText;
			source = CTREncrypt(HexBinary.decode(keys[0]), source, initIV);
			source = CTRDecrypt(HexBinary.decode(keys[1]), source, initIV);
			source = CTREncrypt(HexBinary.decode(keys[2]), source, initIV);
			byte[] result = ByteHelper.concatByte(source, initIV);
			return result;
		} else {
			byte[] initIV = ByteHelper.subByte(inputText, inputText.length - 4, 4);
			byte[] source = ByteHelper.subByte(inputText, 0, inputText.length - 4);
			source = CTRDecrypt(HexBinary.decode(keys[0]), source, initIV);
			source = CTREncrypt(HexBinary.decode(keys[1]), source, initIV);
			source = CTRDecrypt(HexBinary.decode(keys[2]), source, initIV);
			return source;
		}
	}

	private static byte[] CTREncrypt(byte[] key, byte[] inputText, byte[] initIV) {
		byte[] result = new byte[inputText.length];
		Integer count = new Integer(0);
		for (int i = 0; i < result.length; i += 8) {
			byte[] plainText = ByteHelper.subByte(inputText, i, 8);
			byte[] realIV = ByteHelper.concatByte(initIV, ByteBuffer.allocate(4).putInt(count).array());
			byte[] roundBlock = Blocks.runBlock(key, realIV, true);
			for (int j = 0; j < roundBlock.length; j++) {
				result[i + j] = (byte) (roundBlock[j] ^ plainText[j]);
			}
			count++;
		}
		return result;
	}

	private static byte[] CTRDecrypt(byte[] key, byte[] inputText, byte[] initIV) {
		return CTREncrypt(key, inputText, initIV);
	}

	private static byte[] generateInitialVector(int nBytes) {
		SecureRandom random = null;
		try {
			random = SecureRandom.getInstance("SHA1PRNG");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		byte iv[] = new byte[nBytes];
		random.nextBytes(iv);
		return iv;
	}

	public static byte[] blockPadding(byte[] plainText) {
		int extraByte = plainText.length % 8;
		int count = plainText.length / 8;
	
		if (extraByte == 0) {
			byte[] result = new byte[(count + 1) * 8];
			byte padding = ByteHelper.intToByte(8);
			for (int i = 0; i < result.length; i++) {
				if (i < plainText.length) {
					result[i] = plainText[i];
				} else {
					result[i] = padding;
				}
			}
			return result;
		}

		int paddingCount = (count + 1) * 8 - plainText.length;
		byte paddingByte = ByteHelper.intToByte(paddingCount);
		byte[] result = new byte[(count + 1) * 8];
		for (int i = 0; i < result.length; i++) {
			if (i < plainText.length) {
				result[i] = plainText[i];
			} else {
				result[i] = paddingByte;
			}
		}
		return result;
	}

	public static byte[] runBlock(byte[] originalKey, byte[] msgBlock, boolean isEncrypt) {
		try {
			// get 16 round key first
			byte[][] roundKeys = KeyGenerator.createRoundKey(originalKey);
			byte[] result = Round.initialPermutation(msgBlock);

			byte[] right = null;

			for (int i = 0; i < 16; i++) {
				byte[] L = Round.getHalfBlock(result, true);
				byte[] R = Round.getHalfBlock(result, false);
				byte[] key = null;
				if (isEncrypt) {
					key = roundKeys[i];
				} else {
					key = roundKeys[16 - 1 - i];
				}
				right = Round.sInversePermutation(Round.sBox(Round.roundKeyAddition(Round.eBox(R), key)));
				for (int j = 0; j < right.length; j++) {
					result[j] = R[j];
					result[j + 4] = (byte) (right[j] ^ L[j]);
				}
			}

			byte[] L = Round.getHalfBlock(result, true);
			byte[] R = Round.getHalfBlock(result, false);
			for (int j = 0; j < L.length; j++) {
				result[j] = R[j];
				result[j + 4] = L[j];
			}

			return Round.finalInvert(result);

		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}
		return null;
	}
}