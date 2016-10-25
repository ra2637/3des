package main;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.InputMismatchException;
import java.util.List;

import encryption.block.Blocks;
import main.Main.Mode;
import utils.ByteHelper;

public class Encrypt {

	/**
	 * General process for encryption and decryption
	 * @param parameters
	 *            inputFile keyFile outputFile mode
	 * @param isEncrypt
	 * @throws IOException
	 * @throws Exception
	 */

	public Encrypt(List<String> parameters, boolean isEncrypt) throws IOException {
		if (parameters.size() != 4) {
			throw new InputMismatchException("Insufficient parameters: inputFile keyFile outputFile mode");
		}

		String inputFileStr = parameters.get(0);
		String keyFileStr = parameters.get(1);
		String outputFileStr = parameters.get(2);
		String modeStr = parameters.get(3);

		// check if file is existed
		File inputFile = new File(inputFileStr);
		if (!inputFile.exists()) {
			throw new InputMismatchException("inputFile is not existed: " + inputFile);
		}

		File keyFile = new File(keyFileStr);
		if (!keyFile.exists()) {
			throw new InputMismatchException("keyFile is not existed: " + keyFile);
		}
		BufferedReader bufferReader = new BufferedReader(new FileReader(keyFile));
		String originalKey = bufferReader.readLine();
		bufferReader.close();

		File outputFile = new File(outputFileStr);
		if (outputFile.exists()) {
			System.out.println("Overwrite existed file: " + outputFileStr);
		}

		// get key array for 3 DES
		String[] keys = new String[3];
		if (isEncrypt) {
			keys[0] = originalKey.substring(0, 16);
			keys[1] = originalKey.substring(16, 32);
			keys[2] = originalKey.substring(32, 48);
		} else {
			keys[0] = originalKey.substring(32, 48);
			keys[1] = originalKey.substring(16, 32);
			keys[2] = originalKey.substring(0, 16);
		}
		
		// get inputFile and add padding under encrypt mode
		byte[] inputFileByte = Files.readAllBytes(Paths.get(inputFileStr));
		if (isEncrypt) {
			inputFileByte = Blocks.blockPadding(inputFileByte);
		}

		Mode mode = Main.Mode.valueOf(modeStr);
		byte[] result = null, finalResult = null;
		switch (mode) {
		case ECB:
			result = Blocks.ECBMode(keys, inputFileByte, isEncrypt);
			break;
		case CBC:
			result = Blocks.CBCMode(keys, inputFileByte, isEncrypt);
			break;
		case CTR:
			result = Blocks.CTRMode(keys, inputFileByte, isEncrypt);
			break;
		default:
			break;
		}

		if (isEncrypt) {
			finalResult = result;
		} else {
			byte paddingByte = result[result.length - 1];
			int paddingNumber = ByteHelper.byteToInt(paddingByte);
			finalResult = ByteHelper.subByte(result, 0, result.length-paddingNumber);
		}
		FileOutputStream fileOutputStream = new FileOutputStream(outputFile);
		fileOutputStream.write(finalResult);
		fileOutputStream.close();
	}
}
