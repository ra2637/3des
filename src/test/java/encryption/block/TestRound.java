package encryption.block;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.fail;

import java.security.InvalidAlgorithmParameterException;

import org.junit.Test;

import utils.TestBitHelper;

public class TestRound {
	@Test
	public void testInitialPermutationl() {
		int[] msgInt = {
				0,0,0,0, 0,0,0,1, 0,0,1,0, 0,0,1,1, 
				0,1,0,0, 0,1,0,1, 0,1,1,0, 0,1,1,1, 
				1,0,0,0, 1,0,0,1, 1,0,1,0, 1,0,1,1,
				1,1,0,0, 1,1,0,1, 1,1,1,0, 1,1,1,1
		};
		int[] expectedIn = {
				1,1,0,0, 1,1,0,0, 0,0,0,0, 0,0,0,0, 
				1,1,0,0, 1,1,0,0, 1,1,1,1, 1,1,1,1, 
				1,1,1,1, 0,0,0,0, 1,0,1,0, 1,0,1,0, 
				1,1,1,1, 0,0,0,0, 1,0,1,0, 1,0,1,0
		};

		byte[] msg = TestBitHelper.setBitArray(msgInt);
		byte[] expected = TestBitHelper.setBitArray(expectedIn);
		
		try {
			byte[] result = Round.initialPermutation(msg);
			assertArrayEquals(expected, result);
		} catch (InvalidAlgorithmParameterException e) {
			fail(e.getMessage());
		}
	}
	
	@Test
	public void testEbox(){
		int[] R0Int = { 
			1,1,1,1, 0,0,0,0, 1,0,1,0, 1,0,1,0,
			1,1,1,1, 0,0,0,0, 1,0,1,0, 1,0,1,0
		};
		byte[] R0 = TestBitHelper.setBitArray(R0Int);;
		
		int[] expectedInt = {
			0,1,1,1,1,0, 1,0,0,0,0,1, 
			0,1,0,1,0,1, 0,1,0,1,0,1,
			0,1,1,1,1,0, 1,0,0,0,0,1, 
			0,1,0,1,0,1, 0,1,0,1,0,1
		};
		byte[] expected = TestBitHelper.setBitArray(expectedInt);
		
		try {
			byte[] result = Round.eBox(R0);
			assertArrayEquals(expected, result);
		} catch (InvalidAlgorithmParameterException e) {
			fail(e.getMessage());
		}
	}
	
	@Test
	public void testRoundKeyAddition(){
		int[] k1Int = {
			0,0,0,1,1,0, 1,1,0,0,0,0, 0,0,1,0,1,1, 1,0,1,1,1,1,
			1,1,1,1,1,1, 0,0,0,1,1,1, 0,0,0,0,0,1, 1,1,0,0,1,0 	
		};
		int[] ER0Int = {
			0,1,1,1,1,0, 1,0,0,0,0,1, 0,1,0,1,0,1, 0,1,0,1,0,1,
			0,1,1,1,1,0, 1,0,0,0,0,1, 0,1,0,1,0,1, 0,1,0,1,0,1 
		};
		int[] expectedInt = {
			0,1,1,0,0,0, 0,1,0,0,0,1, 0,1,1,1,1,0, 1,1,1,0,1,0, 
			1,0,0,0,0,1, 1,0,0,1,1,0, 0,1,0,1,0,0, 1,0,0,1,1,1
		};
		
		byte[] k1 = TestBitHelper.setBitArray(k1Int);
		byte[] ER0 = TestBitHelper.setBitArray(ER0Int);
		byte[] expected = TestBitHelper.setBitArray(expectedInt);
		
		try {
			assertArrayEquals(expected, Round.roundKeyAddition(ER0, k1));
		} catch (InvalidAlgorithmParameterException e) {
			fail(e.getMessage());
		}
	}
	
	@Test
	public void testSBox(){
		int[] inputInt = {
				0,1,1,0,0,0, 0,1,0,0,0,1, 0,1,1,1,1,0, 
				1,1,1,0,1,0, 1,0,0,0,0,1, 1,0,0,1,1,0, 
				0,1,0,1,0,0, 1,0,0,1,1,1
		};
		int[] expectedInt = {
				0,1,0,1, 1,1,0,0, 1,0,0,0, 0,0,1,0, 1,0,1,1, 0,1,0,1, 1,0,0,1, 0,1,1,1,
		};
		
		byte[] input = TestBitHelper.setBitArray(inputInt);
		byte[] expected = TestBitHelper.setBitArray(expectedInt);
		
		try {
			assertArrayEquals(expected, Round.sBox(input));
		} catch (InvalidAlgorithmParameterException e) {
			fail(e.getMessage());
		}
	}
	
	@Test
	public void testSInversePermutation(){
		int[] inputInt = { 0,1,0,1, 1,1,0,0, 1,0,0,0, 0,0,1,0, 1,0,1,1, 0,1,0,1, 1,0,0,1, 0,1,1,1};
		int[] expectedInt = {0,0,1,0, 0,0,1,1, 0,1,0,0, 1,0,1,0, 1,0,1,0, 1,0,0,1, 1,0,1,1, 1,0,1,1};
		
		byte[] input = TestBitHelper.setBitArray(inputInt);
		byte[] expected = TestBitHelper.setBitArray(expectedInt);
		
		try {
			assertArrayEquals(expected, Round.sInversePermutation(input));
		} catch (InvalidAlgorithmParameterException e) {
			fail(e.getMessage());
		}
	}
	
	@Test
	public void testFinalInverse() {
		int[] inputInt = {
				0,0,0,0,1,0,1,0,
				0,1,0,0,1,1,0,0,
				1,1,0,1,1,0,0,1,
				1,0,0,1,0,1,0,1,
				0,1,0,0,0,0,1,1,
				0,1,0,0,0,0,1,0,
				0,0,1,1,0,0,1,0,
				0,0,1,1,0,1,0,0
		};
		int[] expectInt = {
				1,0,0,0,0,1,0,1,
				1,1,1,0,1,0,0,0,
				0,0,0,1,0,0,1,1,
				0,1,0,1,0,1,0,0,
				0,0,0,0,1,1,1,1, 
				0,0,0,0,1,0,1,0,
				1,0,1,1,0,1,0,0,
				0,0,0,0,0,1,0,1
		};
		
		byte[] input = TestBitHelper.setBitArray(inputInt);
		byte[] expected = TestBitHelper.setBitArray(expectInt);
		
		try {
			assertArrayEquals(expected, Round.finalInvert(input));
		} catch (InvalidAlgorithmParameterException e) {
			fail(e.getMessage());
		}
	}
		
}
