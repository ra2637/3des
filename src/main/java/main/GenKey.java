package main;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.InputMismatchException;
import java.util.List;

import utils.HexBinary;

public class GenKey {

	/**
	 * Using sha-256 to generate hash key from password. Will take the first 192
	 * bits and store them in outputFile in hex format.
	 * 
	 * @param parameters
	 *            password outputFile
	 * @throws Exception
	 */
	public GenKey(List<String> parameters) throws InputMismatchException {
		// check args are valid
		if (parameters.size() != 2) {
			throw new InputMismatchException("Insufficient parameters: password outputFile");
		}

		String passwordStr = parameters.get(0);
		String outputFileStr = parameters.get(1);

		// check if file is existed
		File outputFile = new File(outputFileStr);
		if (outputFile.exists()) {
			System.out.println("Overwrite existed file: " + outputFileStr);
		}

		try {
			outputFile.createNewFile();
			// hash password
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] passwordHash = digest.digest(passwordStr.getBytes(StandardCharsets.UTF_8));

			// get needed key length and write to outputfile
			String usefulKeyHash = HexBinary.encode(passwordHash);
			usefulKeyHash = usefulKeyHash.substring(0, 192 / 4);
			FileWriter fileWriter = new FileWriter(outputFile);
			fileWriter.write(usefulKeyHash);
			fileWriter.close();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}
}
