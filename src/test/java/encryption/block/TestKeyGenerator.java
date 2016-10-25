package encryption.block;

import static org.junit.Assert.*;

import java.security.InvalidAlgorithmParameterException;

import org.junit.Before;
import org.junit.Test;

import utils.BitHelper;

public class TestKeyGenerator {

	private static int[] tempKey = {0,0,0,1,0,0,1,1,0,0,1,1,0,1,0,0,0,1,0,1,0,1,1,1,0,1,1,1,1,0,0,1,1,0,0,1,1,0,1,1,1,0,1,1,1,1,0,0,1,1,0,1,1,1,1,1,1,1,1,1,0,0,0,1};
	private static int[] tempPc1Result = {1,1,1,1,0,0,0,0,1,1,0,0,1,1,0,0,1,0,1,0,1,0,1,0,1,1,1,1,0,1,0,1,0,1,0,1,0,1,1,0,0,1,1,0,0,1,1,1,1,0,0,0,1,1,1,1};
	private static byte[] originalKey;
	private static byte[] pc1Result;
	
	@Before
	public void before(){
		originalKey = new byte[8];
		pc1Result = new byte[7];
		
		for(int i=0; i<tempKey.length; i++){
			if(tempKey[i] == 1) {
				BitHelper.setBit(originalKey, i);
			}
		}
		
		for (int i = 0; i < tempPc1Result.length; i++) {
			if(tempPc1Result[i] == 1){
				BitHelper.setBit(pc1Result, i);
			}
		}
		
	}
	
	@Test
	public void testExecutePC1() { 
		try {
			byte[] result = KeyGenerator.executePC1(originalKey);
			assertArrayEquals(pc1Result, result);
		} catch (InvalidAlgorithmParameterException e) {
			fail(e.getMessage());
		}
	}
	
	@Test
	public void testGetLeftKey() {
		byte[] originalKey = {(byte) 0x12, (byte)0x33, (byte)0x14, (byte)0xAF, 
				(byte)0xD4, (byte)0xCC, (byte)0xE8};
		byte[] expected = {(byte) 0x12, (byte)0x33, (byte)0x14, (byte)0xA0};
		
		try {
			assertArrayEquals(expected, KeyGenerator.getLeftKey(originalKey));
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@Test
	public void testGetRightKey() {
		byte[] originalKey = {(byte) 0x12, (byte)0x33, (byte)0x14, (byte)0xAF, 
				(byte)0xD4, (byte)0xCC, (byte)0xE8};
		byte[] expected = {(byte)0xFD, (byte)0x4C, (byte)0xCE, (byte)0x80};
		
		try {
			assertArrayEquals(expected, KeyGenerator.getRightKey(originalKey));
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	@Test
	public void testRoundKeys(){
		int[][] expected = {
			{1,1,1,0,0,0,0,1,1,0,0,1,1,0,0,1,0,1,0,1,0,1,0,1,1,1,1,1,1,0,1,0,1,0,1,0,1,1,0,0,1,1,0,0,1,1,1,1,0,0,0,1,1,1,1,0},
			{1,1,0,0,0,0,1,1,0,0,1,1,0,0,1,0,1,0,1,0,1,0,1,1,1,1,1,1,0,1,0,1,0,1,0,1,1,0,0,1,1,0,0,1,1,1,1,0,0,0,1,1,1,1,0,1},
			{0,0,0,0,1,1,0,0,1,1,0,0,1,0,1,0,1,0,1,0,1,1,1,1,1,1,1,1,0,1,0,1,0,1,1,0,0,1,1,0,0,1,1,1,1,0,0,0,1,1,1,1,0,1,0,1},
			{0,0,1,1,0,0,1,1,0,0,1,0,1,0,1,0,1,0,1,1,1,1,1,1,1,1,0,0,0,1,0,1,1,0,0,1,1,0,0,1,1,1,1,0,0,0,1,1,1,1,0,1,0,1,0,1},
			{1,1,0,0,1,1,0,0,1,0,1,0,1,0,1,0,1,1,1,1,1,1,1,1,0,0,0,0,0,1,1,0,0,1,1,0,0,1,1,1,1,0,0,0,1,1,1,1,0,1,0,1,0,1,0,1},
			{0,0,1,1,0,0,1,0,1,0,1,0,1,0,1,1,1,1,1,1,1,1,0,0,0,0,1,1,1,0,0,1,1,0,0,1,1,1,1,0,0,0,1,1,1,1,0,1,0,1,0,1,0,1,0,1},
			{1,1,0,0,1,0,1,0,1,0,1,0,1,1,1,1,1,1,1,1,0,0,0,0,1,1,0,0,0,1,1,0,0,1,1,1,1,0,0,0,1,1,1,1,0,1,0,1,0,1,0,1,0,1,1,0},
			{0,0,1,0,1,0,1,0,1,0,1,1,1,1,1,1,1,1,0,0,0,0,1,1,0,0,1,1,1,0,0,1,1,1,1,0,0,0,1,1,1,1,0,1,0,1,0,1,0,1,0,1,1,0,0,1},
			{0,1,0,1,0,1,0,1,0,1,1,1,1,1,1,1,1,0,0,0,0,1,1,0,0,1,1,0,0,0,1,1,1,1,0,0,0,1,1,1,1,0,1,0,1,0,1,0,1,0,1,1,0,0,1,1},
			{0,1,0,1,0,1,0,1,1,1,1,1,1,1,1,0,0,0,0,1,1,0,0,1,1,0,0,1,1,1,1,1,0,0,0,1,1,1,1,0,1,0,1,0,1,0,1,0,1,1,0,0,1,1,0,0},
			{0,1,0,1,0,1,1,1,1,1,1,1,1,0,0,0,0,1,1,0,0,1,1,0,0,1,0,1,1,1,0,0,0,1,1,1,1,0,1,0,1,0,1,0,1,0,1,1,0,0,1,1,0,0,1,1},
			{0,1,0,1,1,1,1,1,1,1,1,0,0,0,0,1,1,0,0,1,1,0,0,1,0,1,0,1,0,0,0,1,1,1,1,0,1,0,1,0,1,0,1,0,1,1,0,0,1,1,0,0,1,1,1,1},
			{0,1,1,1,1,1,1,1,1,0,0,0,0,1,1,0,0,1,1,0,0,1,0,1,0,1,0,1,0,1,1,1,1,0,1,0,1,0,1,0,1,0,1,1,0,0,1,1,0,0,1,1,1,1,0,0},
			{1,1,1,1,1,1,1,0,0,0,0,1,1,0,0,1,1,0,0,1,0,1,0,1,0,1,0,1,1,1,1,0,1,0,1,0,1,0,1,0,1,1,0,0,1,1,0,0,1,1,1,1,0,0,0,1},
			{1,1,1,1,1,0,0,0,0,1,1,0,0,1,1,0,0,1,0,1,0,1,0,1,0,1,1,1,1,0,1,0,1,0,1,0,1,0,1,1,0,0,1,1,0,0,1,1,1,1,0,0,0,1,1,1},
			{1,1,1,1,0,0,0,0,1,1,0,0,1,1,0,0,1,0,1,0,1,0,1,0,1,1,1,1,0,1,0,1,0,1,0,1,0,1,1,0,0,1,1,0,0,1,1,1,1,0,0,0,1,1,1,1}
		};

		try {
			byte[][] result = KeyGenerator.roundKeys(pc1Result);
			byte[][] expectedBytes = new byte[16][7];
			for (int i = 0; i < expectedBytes.length; i++) {
				expectedBytes[i] = new byte[7];
				for (int j = 0; j < expectedBytes[i].length*8; j++) {
					if(expected[i][j] == 1){
						BitHelper.setBit(expectedBytes[i], j);
					}
				}
			}
			
			for (int i = 0; i < expectedBytes.length; i++) {
				assertArrayEquals(expectedBytes[i], result[i]);
				
			}
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	@Test
	public void testExecutePC2(){
		int[][] expected = {
			{0,0,0,1,1,0, 1,1,0,0,0,0, 0,0,1,0,1,1, 1,0,1,1,1,1, 1,1,1,1,1,1, 0,0,0,1,1,1, 0,0,0,0,0,1, 1,1,0,0,1,0},
			{0,1,1,1,1,0, 0,1,1,0,1,0, 1,1,1,0,1,1, 0,1,1,0,0,1, 1,1,0,1,1,0, 1,1,1,1,0,0, 1,0,0,1,1,1, 1,0,0,1,0,1},
			{0,1,0,1,0,1, 0,1,1,1,1,1, 1,1,0,0,1,0, 0,0,1,0,1,0, 0,1,0,0,0,0, 1,0,1,1,0,0, 1,1,1,1,1,0, 0,1,1,0,0,1},
			{0,1,1,1,0,0, 1,0,1,0,1,0, 1,1,0,1,1,1, 0,1,0,1,1,0, 1,1,0,1,1,0, 1,1,0,0,1,1, 0,1,0,1,0,0, 0,1,1,1,0,1},
			{0,1,1,1,1,1, 0,0,1,1,1,0, 1,1,0,0,0,0, 0,0,0,1,1,1, 1,1,1,0,1,0, 1,1,0,1,0,1, 0,0,1,1,1,0, 1,0,1,0,0,0},
			{0,1,1,0,0,0, 1,1,1,0,1,0, 0,1,0,1,0,0, 1,1,1,1,1,0, 0,1,0,1,0,0, 0,0,0,1,1,1, 1,0,1,1,0,0, 1,0,1,1,1,1},
			{1,1,1,0,1,1, 0,0,1,0,0,0, 0,1,0,0,1,0, 1,1,0,1,1,1, 1,1,1,1,0,1, 1,0,0,0,0,1, 1,0,0,0,1,0, 1,1,1,1,0,0},
			{1,1,1,1,0,1, 1,1,1,0,0,0, 1,0,1,0,0,0, 1,1,1,0,1,0, 1,1,0,0,0,0, 0,1,0,0,1,1, 1,0,1,1,1,1, 1,1,1,0,1,1},
			{1,1,1,0,0,0, 0,0,1,1,0,1, 1,0,1,1,1,1, 1,0,1,0,1,1, 1,1,1,0,1,1, 0,1,1,1,1,0, 0,1,1,1,1,0, 0,0,0,0,0,1},
			{1,0,1,1,0,0, 0,1,1,1,1,1, 0,0,1,1,0,1, 0,0,0,1,1,1, 1,0,1,1,1,0, 1,0,0,1,0,0, 0,1,1,0,0,1, 0,0,1,1,1,1},
			{0,0,1,0,0,0, 0,1,0,1,0,1, 1,1,1,1,1,1, 0,1,0,0,1,1, 1,1,0,1,1,1, 1,0,1,1,0,1, 0,0,1,1,1,0, 0,0,0,1,1,0},
			{0,1,1,1,0,1, 0,1,0,1,1,1, 0,0,0,1,1,1, 1,1,0,1,0,1, 1,0,0,1,0,1, 0,0,0,1,1,0, 0,1,1,1,1,1, 1,0,1,0,0,1},
			{1,0,0,1,0,1, 1,1,1,1,0,0, 0,1,0,1,1,1, 0,1,0,0,0,1, 1,1,1,1,1,0, 1,0,1,0,1,1, 1,0,1,0,0,1, 0,0,0,0,0,1},
			{0,1,0,1,1,1, 1,1,0,1,0,0, 0,0,1,1,1,0, 1,1,0,1,1,1, 1,1,1,1,0,0, 1,0,1,1,1,0, 0,1,1,1,0,0, 1,1,1,0,1,0},
			{1,0,1,1,1,1, 1,1,1,0,0,1, 0,0,0,1,1,0, 0,0,1,1,0,1, 0,0,1,1,1,1, 0,1,0,0,1,1, 1,1,1,1,0,0, 0,0,1,0,1,0},
			{1,1,0,0,1,0, 1,1,0,0,1,1, 1,1,0,1,1,0, 0,0,1,0,1,1, 0,0,0,0,1,1, 1,0,0,0,0,1, 0,1,1,1,1,1, 1,1,0,1,0,1}
		}; 
		
		try {
			byte[][] keyBytes = KeyGenerator.roundKeys(pc1Result);
			byte[][] expectedBytes = new byte[16][6];
			for (int i = 0; i < expectedBytes.length; i++) {
				expectedBytes[i] = new byte[6];
				for (int j = 0; j < expectedBytes[i].length*8; j++) {
					if(expected[i][j] == 1){
						BitHelper.setBit(expectedBytes[i], j);
					}
				}
			}
			
			for (int i = 0; i < expectedBytes.length; i++) {
				assertArrayEquals(expectedBytes[i], KeyGenerator.executePC2(keyBytes[i]));
				
			}
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	@Test
	public void TestRotateBytes(){
		byte[] original = {(byte)0xF0, (byte)0x00, (byte)0x00, (byte)0x00};
		byte[] expected = {(byte)0xE0, (byte)0x00, (byte)0x00, (byte)0x10};
		try {
			original = KeyGenerator.rotateBytes(1, original);
			assertArrayEquals(expected, original);
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
}