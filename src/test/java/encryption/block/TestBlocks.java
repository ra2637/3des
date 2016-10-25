package encryption.block;

import static org.junit.Assert.*;

import org.junit.Test;

import utils.HexBinary;
import utils.TestBitHelper;

public class TestBlocks {
	@Test
	public void testBlockPadding() {
		int[] msgInt = {
				0,0,1,1,0,0,0,1,
				0,0,1,1,0,0,0,1,
				0,0,1,1,0,0,0,1,
				0,0,1,1,0,0,0,1,
				0,0,1,1,0,0,0,1,
				0,0,1,1,0,0,0,1,
				0,0,1,1,0,0,0,1
		};
		int[] expectedInt = {
				0,0,1,1,0,0,0,1,
				0,0,1,1,0,0,0,1,
				0,0,1,1,0,0,0,1,
				0,0,1,1,0,0,0,1,
				0,0,1,1,0,0,0,1,
				0,0,1,1,0,0,0,1,
				0,0,1,1,0,0,0,1,
				0,0,0,0,0,0,0,1
		};
		byte[] msg = TestBitHelper.setBitArray(msgInt);
		byte[] expected = TestBitHelper.setBitArray(expectedInt);
		
		int[] msgInt1 = {
				0,0,1,1,0,0,0,1,
				0,0,1,1,0,0,0,1,
				0,0,1,1,0,0,0,1,
				0,0,1,1,0,0,0,1,
				0,0,1,1,0,0,0,1,
				0,0,1,1,0,0,0,1,
		};
		int[] expectedInt1 = {
				0,0,1,1,0,0,0,1,
				0,0,1,1,0,0,0,1,
				0,0,1,1,0,0,0,1,
				0,0,1,1,0,0,0,1,
				0,0,1,1,0,0,0,1,
				0,0,1,1,0,0,0,1,
				0,0,0,0,0,0,1,0,
				0,0,0,0,0,0,1,0
		};
		byte[] msg1 = TestBitHelper.setBitArray(msgInt1);
		byte[] expected1 = TestBitHelper.setBitArray(expectedInt1);
		
		assertArrayEquals(expected, Blocks.blockPadding(msg));
		assertArrayEquals(expected1, Blocks.blockPadding(msg1));
		
	}
	@Test
	public void testRunBlockEncryp() {
		
		int[] msgInt = {
				0,0,1,1,0,0,0,1,
				0,0,1,1,0,0,0,1,
				0,0,1,1,0,0,0,1,
				0,0,1,1,0,0,0,1,
				0,0,1,1,0,0,0,1,
				0,0,1,1,0,0,0,1,
				0,0,1,1,0,0,0,1,
				0,0,1,1,0,0,0,1
		};
		int[] keyInt = {
				0,0,0,0,0,0,0,1,
				0,0,1,0,0,0,1,1,
				0,1,0,0,0,1,0,1,
				0,1,1,0,0,1,1,1,
				1,0,0,0,0,1,1,0,
				1,0,0,1,1,0,1,0,
				1,0,1,1,1,1,0,0,
				1,1,0,1,1,1,1,0
		};
		String expectedHex = "abb123da796a5f57".toUpperCase();

		byte[] msg = TestBitHelper.setBitArray(msgInt);
		byte[] key = TestBitHelper.setBitArray(keyInt);
		
		byte[] result = Blocks.runBlock(key, msg, true);
		assertEquals(expectedHex, HexBinary.encode(result));
	}
	
	@Test
	public void testRunBlockDecrypt() {
		
		int[] expectedInt = {
				0,0,1,1,0,0,0,1,
				0,0,1,1,0,0,0,1,
				0,0,1,1,0,0,0,1,
				0,0,1,1,0,0,0,1,
				0,0,1,1,0,0,0,1,
				0,0,1,1,0,0,0,1,
				0,0,1,1,0,0,0,1,
				0,0,1,1,0,0,0,1
		};
		int[] keyInt = {
				0,0,0,0,0,0,0,1,
				0,0,1,0,0,0,1,1,
				0,1,0,0,0,1,0,1,
				0,1,1,0,0,1,1,1,
				1,0,0,0,0,1,1,0,
				1,0,0,1,1,0,1,0,
				1,0,1,1,1,1,0,0,
				1,1,0,1,1,1,1,0
		};
		String cipherText = "abb123da796a5f57".toUpperCase();

		byte[] expected = TestBitHelper.setBitArray(expectedInt);
		byte[] key = TestBitHelper.setBitArray(keyInt);
		
		byte[] result = Blocks.runBlock(key, HexBinary.decode(cipherText), false);
		assertArrayEquals(expected, result);
	}
}
