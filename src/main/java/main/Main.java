package main;

import java.util.Arrays;
import java.util.InputMismatchException;
import java.util.List;

public class Main {
	public static enum Mode {
		ECB, CBC, CTR 
	}
	
	private static enum Command {
		GENKEY, ENCRYPT, DECRYPT
	}

	/**
	 * check the input as following
	 * 
	 * @param args
	 * args are 3 types input:
	 * genkey password outputFile
	 * encrypt inputFile keyFile outputFile mode
	 * decrypt inputFile keyFile outputFile mode
	 * mode: ECB, CBC, and CTR
	 */
	public static void main(String[] args) {
		try {
			// check command valid
			if (args.length < 1) {
				throw new InputMismatchException("Insufficient parameters.");
			}

			try {
				Command command = Command.valueOf(args[0].toUpperCase());
				List<String> parameters = Arrays.asList(args);
				parameters = parameters.subList(1, args.length);
				
				switch (command) {
				case GENKEY:
					new GenKey(parameters);
					break;
				case ENCRYPT:
					new Encrypt(parameters, true);
					break;
				case DECRYPT:
					new Encrypt(parameters, false);
					break;
				}
			} catch (IllegalArgumentException e) {
				throw new InputMismatchException("Invalid command: " + args[0]);
			} 
			catch (Exception e) {
				throw e;
			}
		} catch (Exception e) {
			System.err.println(e.getMessage());
		}
	}
}