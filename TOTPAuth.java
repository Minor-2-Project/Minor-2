package minor2;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
public class TOTPAuth {
	public static final int DEFAULT_TIME_SECONDS = 30;
	public static int DEFAULT_OTP_LENGTH = 6;
	private static final String blockOfZeros;
	private static int MAX_DIGITS = 100;
	public static int DEFAULT_QR_DIMENTION = 200;
	static {
		char[] arr = new char[MAX_DIGITS];
		Arrays.fill(arr, '0');
		blockOfZeros = new String(arr);
	}
	public static String generateBase32Secret() {
		return generateBase32Secret(16);
	}
	public static String generateBase32Secret(int numDigits) {
		StringBuilder sb = new StringBuilder(numDigits);
		Random random = new SecureRandom();
		for (int i = 0; i < numDigits; i++) {
			int val = random.nextInt(32);
			if (val < 26) {
				sb.append((char) ('A' + val));
			} else {
				sb.append((char) ('2' + (val - 26)));
			}
		}
		return sb.toString();
	}
	public static String generateHexSecret() {
		return generateHexSecret(32);
	}
	public static String generateHexSecret(int numDigits) {
		StringBuilder sb = new StringBuilder(numDigits);
		Random random = new SecureRandom();
		for (int i = 0; i < numDigits; i++) {
			int val = random.nextInt(16);
			if (val < 10) {
				sb.append((char) ('0' + val));
			} else {
				sb.append((char) ('A' + (val - 10)));
			}
		}
		return sb.toString();
	}
	public static boolean validateCurrentNumber(String base32Secret, int authNumber, long windowMillis)
			throws GeneralSecurityException {
		return validateCurrentNumber(base32Secret, authNumber, windowMillis, System.currentTimeMillis(),
				DEFAULT_TIME_SECONDS, DEFAULT_OTP_LENGTH);
	}
	public static boolean validateCurrentNumberHex(String hexSecret, int authNumber, long windowMillis)
			throws GeneralSecurityException {
		return validateCurrentNumberHex(hexSecret, authNumber, windowMillis, System.currentTimeMillis(),
				DEFAULT_TIME_SECONDS, DEFAULT_OTP_LENGTH);
	}
	public static boolean validateCurrentNumber(String base32Secret, int authNumber, long windowMillis, long timeMillis,
			int timeStepSeconds) throws GeneralSecurityException {
		return validateCurrentNumber(base32Secret, authNumber, windowMillis, timeMillis, timeStepSeconds,
				DEFAULT_OTP_LENGTH);
	}
	public static boolean validateCurrentNumberHex(String hexSecret, int authNumber, long windowMillis, long timeMillis,
			int timeStepSeconds) throws GeneralSecurityException {
		return validateCurrentNumberHex(hexSecret, authNumber, windowMillis, timeMillis, timeStepSeconds,
				DEFAULT_OTP_LENGTH);
	}
	public static boolean validateCurrentNumber(String base32Secret, int authNumber, long windowMillis, long timeMillis,
			int timeStepSeconds, int numDigits) throws GeneralSecurityException {
		byte[] key = decodeBase32(base32Secret);
		return validateCurrentNumber(key, authNumber, windowMillis, timeMillis, timeStepSeconds, numDigits);
	}
	public static boolean validateCurrentNumberHex(String hexSecret, int authNumber, long windowMillis, long timeMillis,
			int timeStepSeconds, int numDigits) throws GeneralSecurityException {
		byte[] key = decodeHex(hexSecret);
		return validateCurrentNumber(key, authNumber, windowMillis, timeMillis, timeStepSeconds, numDigits);
	}
	
	public static String generateCurrentNumberString(String base32Secret) throws GeneralSecurityException {
		return generateNumberString(base32Secret, System.currentTimeMillis(), DEFAULT_TIME_SECONDS,
				DEFAULT_OTP_LENGTH);
	}
	public static String generateCurrentNumberStringHex(String hexSecret) throws GeneralSecurityException {
		return generateNumberStringHex(hexSecret, System.currentTimeMillis(), DEFAULT_TIME_SECONDS,
				DEFAULT_OTP_LENGTH);
	}
	
	
	public static String generateCurrentNumberStringHex(String hexSecret, int numDigits)
			throws GeneralSecurityException {
		return generateNumberStringHex(hexSecret, System.currentTimeMillis(), DEFAULT_TIME_SECONDS, numDigits);
	}
	public static String generateNumberString(String base32Secret, long timeMillis, int timeStepSeconds, int numDigits)
			throws GeneralSecurityException {
		int number = generateNumber(base32Secret, timeMillis, timeStepSeconds, numDigits);
		return zeroPrepend(number, numDigits);
	}
	public static String generateNumberStringHex(String hexSecret, long timeMillis, int timeStepSeconds, int numDigits)
			throws GeneralSecurityException {
		int number = generateNumberHex(hexSecret, timeMillis, timeStepSeconds, numDigits);
		return zeroPrepend(number, numDigits);
	}
	

	public static String generateCurrentNumberString(String base32Secret, int numDigits)
			throws GeneralSecurityException {
		return generateNumberString(base32Secret, System.currentTimeMillis(), DEFAULT_TIME_SECONDS, numDigits);
	}
	public static int generateCurrentNumber(String base32Secret) throws GeneralSecurityException {
		return generateNumber(base32Secret, System.currentTimeMillis(), DEFAULT_TIME_SECONDS, DEFAULT_OTP_LENGTH);
	}
	public static int generateCurrentNumberHex(String hexSecret) throws GeneralSecurityException {
		return generateNumberHex(hexSecret, System.currentTimeMillis(), DEFAULT_TIME_SECONDS, DEFAULT_OTP_LENGTH);
	}

	public static int generateCurrentNumber(String base32Secret, int numDigits) throws GeneralSecurityException {
		return generateNumber(base32Secret, System.currentTimeMillis(), DEFAULT_TIME_SECONDS, numDigits);
	}
	public static int generateCurrentNumberHex(String hexSecret, int numDigits) throws GeneralSecurityException {
		return generateNumberHex(hexSecret, System.currentTimeMillis(), DEFAULT_TIME_SECONDS, numDigits);
	}

	public static int generateNumber(String base32Secret, long timeMillis, int timeStepSeconds)
			throws GeneralSecurityException {
		return generateNumber(base32Secret, timeMillis, timeStepSeconds, DEFAULT_OTP_LENGTH);
	}
	

	public static int generateNumber(String base32Secret, long timeMillis, int timeStepSeconds, int numDigits)
			throws GeneralSecurityException {
		long value = generateValue(timeMillis, timeStepSeconds);
		byte[] key = decodeBase32(base32Secret);
		return generateNumberFromKeyValue(key, value, numDigits);
	}
	public static int generateNumberHex(String hexSecret, long timeMillis, int timeStepSeconds)
			throws GeneralSecurityException {
		return generateNumberHex(hexSecret, timeMillis, timeStepSeconds, DEFAULT_OTP_LENGTH);
	}
	
	public static int generateNumberHex(String hexSecret, long timeMillis, int timeStepSeconds, int numDigits)
			throws GeneralSecurityException {
		long value = generateValue(timeMillis, timeStepSeconds);
		byte[] key = decodeHex(hexSecret);
		return generateNumberFromKeyValue(key, value, numDigits);
	}
	public static String qrImageUrl(String keyId, String secret) {
		return qrImageUrl(keyId, secret, DEFAULT_OTP_LENGTH, DEFAULT_QR_DIMENTION);
	}
	public static String qrImageUrl(String keyId, String secret, int numDigits) {
		return qrImageUrl(keyId, secret, numDigits, DEFAULT_QR_DIMENTION);
	}
	public static String qrImageUrl(String keyId, String secret, int numDigits, int imageDimension) {
		StringBuilder sb = new StringBuilder(128);
		sb.append("https://chart.googleapis.com/chart?chs=" + imageDimension + "x" + imageDimension + "&cht=qr&chl="
				+ imageDimension + "x" + imageDimension + "&chld=M|0&cht=qr&chl=");
		addOtpAuthPart(keyId, secret, sb, numDigits);
		return sb.toString();
	}
	public static String generateOtpAuthUrl(String keyId, String secret) {
		return generateOtpAuthUrl(keyId, secret, DEFAULT_OTP_LENGTH);
	}
	public static String generateOtpAuthUrl(String keyId, String secret, int numDigits) {
		StringBuilder sb = new StringBuilder(128);
		addOtpAuthPart(keyId, secret, sb, numDigits);
		return sb.toString();
	}

	private static void addOtpAuthPart(String keyId, String secret, StringBuilder sb, int numDigits) {
		sb.append("otpauth://totp/")
				.append(keyId)
				.append("%3Fsecret%3D")
				.append(secret)
				.append("%26digits%3D")
				.append(numDigits);
	}
	private static boolean validateCurrentNumber(byte[] key, int authNumber, long windowMillis, long timeMillis,
			int timeStepSeconds, int numDigits) throws GeneralSecurityException {
		if (windowMillis <= 0) {
			long value = generateValue(timeMillis, timeStepSeconds);
			long generatedNumber = generateNumberFromKeyValue(key, value, numDigits);
			return (generatedNumber == authNumber);
		}
		long startValue = generateValue(timeMillis - windowMillis, timeStepSeconds);
		long endValue = generateValue(timeMillis + windowMillis, timeStepSeconds);
		for (long value = startValue; value <= endValue; value++) {
			long generatedNumber = generateNumberFromKeyValue(key, value, numDigits);
			if (generatedNumber == authNumber) {
				return true;
			}
		}
		return false;
	}
	private static long generateValue(long timeMillis, int timeStepSeconds) {
		return timeMillis / 1000 / timeStepSeconds;
	}

	private static int generateNumberFromKeyValue(byte[] key, long value, int numDigits)
			throws GeneralSecurityException {

		byte[] data = new byte[8];
		for (int i = 7; value > 0; i--) {
			data[i] = (byte) (value & 0xFF);
			value >>= 8;
		}
		SecretKeySpec signKey = new SecretKeySpec(key, "HmacSHA1");
		Mac mac = Mac.getInstance("HmacSHA1");
		mac.init(signKey);
		byte[] hash = mac.doFinal(data);
		int offset = hash[hash.length - 1] & 0xF;
		long truncatedHash = 0;
		for (int i = offset; i < offset + 4; ++i) {
			truncatedHash <<= 8;
			truncatedHash |= (hash[i] & 0xFF);
		}
		truncatedHash &= 0x7FFFFFFF;
		long mask = 1;
		for (int i = 0; i < numDigits; i++) {
			mask *= 10;
		}
		truncatedHash %= mask;
		return (int) truncatedHash;
	}

	static String zeroPrepend(int num, int digits) {
		String numStr = Integer.toString(num);
		if (numStr.length() >= digits) {
			return numStr;
		} else {
			StringBuilder sb = new StringBuilder(digits);
			int zeroCount = digits - numStr.length();
			sb.append(blockOfZeros, 0, zeroCount);
			sb.append(numStr);
			return sb.toString();
		}
	}
	static byte[] decodeBase32(String str) {
		int numBytes = ((str.length() * 5) + 7) / 8;
		byte[] result = new byte[numBytes];
		int resultIndex = 0;
		int var = 0;
		int work = 0;
		for (int i = 0; i < str.length(); i++) {
			char ch = str.charAt(i);
			int val;
			if (ch >= 'a' && ch <= 'z') {
				val = ch - 'a';
			} else if (ch >= 'A' && ch <= 'Z') {
				val = ch - 'A';
			} else if (ch >= '2' && ch <= '7') {
				val = 26 + (ch - '2');
			} else if (ch == '=') {
				var = 0;// special case
				break;
			} else {
				throw new IllegalArgumentException("Invalid base-32 character: " + ch);
			}
			switch (var) {
				case 0:
					work = (val & 0x1F) << 3;
					var = 1;
					break;
				case 1:
					work |= (val & 0x1C) >> 2;
					result[resultIndex++] = (byte) work;
					work = (val & 0x03) << 6;
					var = 2;
					break;
				case 2:
					work |= (val & 0x1F) << 1;
					var = 3;
					break;
				case 3:
					work |= (val & 0x10) >> 4;
					result[resultIndex++] = (byte) work;
					work = (val & 0x0F) << 4;
					var = 4;
					break;
				case 4:
					work |= (val & 0x1E) >> 1;
					result[resultIndex++] = (byte) work;
					work = (val & 0x01) << 7;
					var = 5;
					break;
				case 5:
					work |= (val & 0x1F) << 2;
					var = 6;
					break;
				case 6:
					work |= (val & 0x18) >> 3;
					result[resultIndex++] = (byte) work;
					work = (val & 0x07) << 5;
					var = 7;
					break;
				case 7:
					work |= (val & 0x1F);
					result[resultIndex++] = (byte) work;
					var = 0;
					break;
			}
		}
		if (var != 0) {
			result[resultIndex++] = (byte) work;
		}
		if (resultIndex != result.length) {
			result = Arrays.copyOf(result, resultIndex);
		}
		return result;
	}
	
static byte[] decodeHex(String str) {
	// each hex character encodes 4 bits
	int numBytes = ((str.length() * 4) + 7) / 8;
	byte[] result = new byte[numBytes];
	int resultIndex = 0;
	int which = 0;
	int working = 0;
	for (int i = 0; i < str.length(); i++) {
		char ch = str.charAt(i);
		int val;
		if (ch >= '0' && ch <= '9') {
			val = (ch - '0');
		} else if (ch >= 'a' && ch <= 'f') {
			val = 10 + (ch - 'a');
		} else if (ch >= 'A' && ch <= 'F') {
			val = 10 + (ch - 'A');
		} else {
			throw new IllegalArgumentException("Invalid hex character: " + ch);
		}
		/*
		 * There are probably better ways to do this but this seemed the most straightforward.
		 */
		if (which == 0) {
			// top 4 bits
			working = (val & 0xF) << 4;
			which = 1;
		} else {
			// lower 4 bits
			working |= (val & 0xF);
			result[resultIndex++] = (byte) working;
			which = 0;
		}
	}
	if (which != 0) {
		result[resultIndex++] = (byte) (working >> 4);
	}
	if (resultIndex != result.length) {
		// may not happen but let's be careful out there
		result = Arrays.copyOf(result, resultIndex);
	}
	return result;
}
}