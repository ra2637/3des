package encryption.block;

import java.security.InvalidAlgorithmParameterException;

import utils.BitHelper;

public class KeyGenerator {
	private final static int [] PC1Table = {
		57, 49, 41, 33, 25, 17,  9, 
	     1, 58, 50, 42, 34, 26, 18, 
	    10,  2, 59, 51, 43, 35, 27, 
	    19, 11,  3, 60, 52, 44, 36, 
	    63, 55, 47, 39, 31, 23, 15, 
	     7, 62, 54, 46, 38, 30, 22, 
	    14,  6, 61, 53, 45, 37, 29, 
	    21, 13,  5, 28, 20, 12,  4
	 };
	
	public final static int [] PC2Table = {
		14, 17, 11, 24,  1,  5,
	     3, 28, 15,  6, 21, 10,
	    23, 19, 12,  4, 26,  8,
	    16,  7, 27, 20, 13,  2, 
	    41, 52, 31, 37, 47, 55, 
	    30, 40, 51, 45, 33, 48, 
	    44, 49, 39, 56, 34, 53,
	    46, 42, 50, 36, 29, 32
	};
	
	public final static int [] IPTable = {
		1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
	};
	
	public static byte[] executePC1(byte[] keyBytes) throws InvalidAlgorithmParameterException {
		if(keyBytes.length != 8) {
			throw new InvalidAlgorithmParameterException("oringinal key length should be 64 bits but "
					+ "get: "+keyBytes.length*8);
		}
		
		byte[] result = new byte[7];
		for (int i = 0; i < PC1Table.length; i++) {
//			System.out.printf("i: %d, PCtable: %d, in keyBytes: %s\n", i, PC1Table[i], BitHelper.getBit(keyBytes, PC1Table[i]));
			if(BitHelper.getBit(keyBytes, PC1Table[i]-1)){
				BitHelper.setBit(result, i);
			}
		}
		return result;
	}
	
	public static byte[] executePC2(byte[] keyBytes) throws InvalidAlgorithmParameterException {
		if(keyBytes.length != 7) {
			throw new InvalidAlgorithmParameterException("oringinal key length should be 64 bits but "
					+ "get: "+keyBytes.length*8);
		}
		
		byte[] result = new byte[6];
		for (int i = 0; i < PC2Table.length; i++) {
			if(BitHelper.getBit(keyBytes, PC2Table[i]-1)){
				BitHelper.setBit(result, i);
			}
		}
		return result;
	}
	
	public static byte[][] roundKeys(byte[] originalKey) throws InvalidAlgorithmParameterException {
		if(originalKey.length != 7) {
			throw new InvalidAlgorithmParameterException("oringinal key length should be 56 bits but "
					+ "get: "+originalKey.length*8);
		}
		
		byte[][] roundKeys = new byte[16][7];
		for (int i = 0; i < roundKeys.length; i++) {
			byte[] roundKey = new byte[7];
			byte[] C, D;
			if (i == 0) {
				C = getLeftKey(originalKey);
				D = getRightKey(originalKey);
			}else {
				C = getLeftKey(roundKeys[i-1]);
				D = getRightKey(roundKeys[i-1]);
			}
			
			int bitsToShift = IPTable[i];
			C = rotateBytes(bitsToShift, C);
			D = rotateBytes(bitsToShift, D);
			
			int roundKeyBits = roundKey.length*8;
			for (int j = 0; j < roundKeyBits; j++) {
				if(j < 28 && BitHelper.getBit(C, j)){
					BitHelper.setBit(roundKey, j);
				}else if(j >= 28 && BitHelper.getBit(D, j-28)){
					BitHelper.setBit(roundKey, j);
				}
			}
			roundKeys[i] = roundKey;
		}
		
		return roundKeys;
	}
	
	/**
	 * 
	 * @param originalKey
	 * @return 4 bytes
	 * @throws InvalidAlgorithmParameterException
	 */
	public static byte[] getLeftKey(byte[] originalKey) throws InvalidAlgorithmParameterException{
		if(originalKey.length != 7) {
			throw new InvalidAlgorithmParameterException("oringinal key length should be 56 bits but "
					+ "get: "+originalKey.length*8);
		}
		return new byte[] {
				(byte) (originalKey[0] & 0xFF),
				(byte) (originalKey[1] & 0xFF),
				(byte) (originalKey[2] & 0xFF),
				(byte) (originalKey[3] & 0xF0)
		};
		
	}
	
	/**
	 * 
	 * @param originalKey
	 * @return 4 bytes
	 * @throws InvalidAlgorithmParameterException
	 */
	public static byte[] getRightKey(byte[] originalKey) throws InvalidAlgorithmParameterException{
		if(originalKey.length != 7) {
			throw new InvalidAlgorithmParameterException("oringinal key length should be 56 bits but "
					+ "get: "+originalKey.length*8);
		}
		
		byte[] rightBytes = new byte[] {
				originalKey[3],
				originalKey[4],
				originalKey[5],
				originalKey[6]
		};
		rightBytes = BitHelper.leftShiftBit(rightBytes, 4); // remove the first four bits
		return rightBytes;
	}
	
	public static byte[] rotateBytes(int bitsToShift, byte[] bytes) throws InvalidAlgorithmParameterException {
		if(bytes.length != 4) {
			throw new InvalidAlgorithmParameterException("oringinal key length should be 32 bits but "
					+ "get: "+bytes.length*8);
		}
		byte[] result = new byte[bytes.length];
		boolean[] first2Bits = {BitHelper.getBit(bytes, 0), BitHelper.getBit(bytes, 1)};
		result = BitHelper.leftShiftBit(bytes, bitsToShift);
		
		for (int j = 0; j < bitsToShift; j++) {
			if (first2Bits[j]) {
				BitHelper.setBit(result, (bytes.length*8-4)-bitsToShift+j);
			}
		}
		
		return result;
	}
	
	/**
	 * Generate 16 round keys
	 * @param originalKey
	 * @return array of round keys
	 * @throws InvalidAlgorithmParameterException
	 */
	public static byte[][] createRoundKey(byte[] originalKey) throws InvalidAlgorithmParameterException {
		byte[][] roundKeys = new byte[16][6];
		
		// Run PC-1
		byte[] pc1Key = KeyGenerator.executePC1(originalKey);
		// Gen 16 keys
		byte[][] tmpRoundKeys = KeyGenerator.roundKeys(pc1Key);
		// Run PC-2
		for (int i = 0; i < tmpRoundKeys.length; i++) {
			roundKeys[i] = KeyGenerator.executePC2(tmpRoundKeys[i]);
		}
		return roundKeys;
	}
}
