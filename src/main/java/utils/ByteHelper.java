package utils;

public class ByteHelper {
	/**
	 * Take 1 byte to int
	 * 
	 * @param bytes
	 * @return
	 * @throws InvalidAlgorithmParameterException
	 */
	public static int byteToInt(byte b) {
		return (b & 0xFF);
	}

	public static byte intToByte(int a) {
		 return (byte) (a & 0xFF);
	}
	
	public static byte[] subByte(byte[] b, int beginingIndex, int length) {
		byte[] result = new byte[length];
		for (int i = 0; i < length; i++) {
			result[i] = b[beginingIndex+i]; 
		}
		return result;
	}
	
	public static byte[] concatByte(byte[] originB, byte[] addB){
		if (originB == null) {
			return addB.clone();
		}
		
		byte[] result = new byte[originB.length+addB.length];
		for (int i = 0; i < result.length; i++) {
			if (i < originB.length) {
				result[i] = originB[i];	
			} else {
				result[i] = addB[i-originB.length];
			}
		}
		return result;
	}

}
