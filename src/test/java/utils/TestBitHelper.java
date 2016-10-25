package utils;

import static org.junit.Assert.*;

import org.junit.Test;

public class TestBitHelper {
	public static byte[] setBitArray(int[] intArr){
		int byteLength = intArr.length/8;
		byte[] result = new byte[byteLength];
		for (int i = 0; i < intArr.length; i++) {
			if (intArr[i] == 1) {
				BitHelper.setBit(result, i);
			}
		}
		return result;
	};
	
	static byte[] byteArray = {(byte) 0xF0, (byte) 0x21};

	
	@Test
	public void testGetBit() { 
		boolean[] expected = {true, true, true, true, false, false, false, false,
							  false, false, true, false, false, false, false, true};
		boolean[] result = new boolean[8*2];
		
		for(int i=0; i<result.length; i++) {
			result[i] = BitHelper.getBit(byteArray, i);
		}
		
		for(int i=0; i<expected.length; i++) {
			if(result[i] != expected[i]){
				fail("at i:"+i+", Expexted: "+expected[i]+", get: "+result[i]);
			}
		}
		
	}
	
	@Test
	public void testSetBit() {
		// set to 0xF1, 0x22
		boolean[] expected = {true, true, true, true, false, false, false, false,
				  false, false, true, false, false, false, false, true};
		
		byte[] initResult = {0x00, 0x00};
		
		for(int i=0; i<expected.length; i++) {
			if(expected[i]){
				BitHelper.setBit(initResult, i);
			}
		}
		assertArrayEquals(byteArray, initResult);
	}
	
	@Test
	public void testLeftShiftBit() {
		byte[] originalKey = {(byte)0xAF, (byte)0xD4, (byte)0xCC, (byte)0xE8};
		byte[] expected = {(byte)0xFD, (byte)0x4C, (byte)0xCE, (byte)0x80};
		
		assertArrayEquals(expected, BitHelper.leftShiftBit(originalKey, 4));
	}
	
//	@Test
//	public void testByteToInt() {
//		byte[] bytes= { 0x00, 0x00, 0x00, (byte) 0x11};
//		int expected = 17;
//		try {
//			assertEquals(expected, BitHelper.byteToInt(bytes));
//		} catch (InvalidAlgorithmParameterException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//	}
//	
//	@Test
//	public void testIntShift(){
//		int i = 17;
//		i = i << 1;
//		int expected = 34;
//		assertEquals(expected, i);
//	}
//	
//	@Test
//	public void testIntToByte() {
//		int result= 17;
//		byte[] expected= { 0x00, 0x00, 0x00, (byte) 0x11};
//		assertArrayEquals(expected, BitHelper.intToByte(result, 4));
//	}
}
