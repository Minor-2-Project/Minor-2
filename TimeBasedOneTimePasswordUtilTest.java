package minor2;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.GeneralSecurityException;
import java.util.Random;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Hex;
import org.junit.Test;

public class TimeBasedOneTimePasswordUtilTest {

	@Test
	public void testZeroPrepend() {
		Random random = new Random();
		for (int i = 0; i < 10000; i++) {
			int num = random.nextInt(1000000);
			/**
			 * NOTE: Did a speed test of these and the zeroPrepend is ~13x faster.
			 */
			assertEquals(String.format("%06d", num), TOTPAuth.zeroPrepend(num, 6));
		}
	}

	@Test
	public void testDecodeBase32() {
		Random random = new Random();
		random.nextBytes(new byte[100]);
		Base32 base32 = new Base32();
		for (int i = 0; i < 10000; i++) {
			byte[] bytes = new byte[random.nextInt(10) + 1];
			random.nextBytes(bytes);
			String encoded = base32.encodeAsString(bytes);
			byte[] expected = base32.decode(encoded);
			byte[] actual = minor2.TOTPAuth.decodeBase32(encoded);
			assertArrayEquals(expected, actual);
		}
	}

	@Test
	public void testDecodeHexadecimal() throws DecoderException {
		Random random = new Random();
		random.nextBytes(new byte[100]);
		for (int i = 0; i < 10000; i++) {
			byte[] bytes = new byte[random.nextInt(10) + 1];
			random.nextBytes(bytes);
			String encoded = Hex.encodeHexString(bytes);
			byte[] expected = Hex.decodeHex(encoded.toCharArray());
			byte[] actual = minor2.TOTPAuth.decodeHex(encoded);
			assertArrayEquals(expected, actual);
		}
	}

	@Test
	public void testBadBase32() {
		String[] strings =
				new String[] { "A", "AB", "ABC", "ABCD", "ABCDE", "ABCDEF", "ABCDEFG", "ABCDEFGH", "ABCDEFGHI" };
		Base32 base32 = new Base32();
		for (String str : strings) {
			byte[] decoded = minor2.TOTPAuth.decodeBase32(str);
			String encoded = base32.encodeAsString(decoded);
			byte[] result = minor2.TOTPAuth.decodeBase32(encoded);
			assertArrayEquals(decoded, result);
		}
	}

	@Test
	public void testValidate() throws GeneralSecurityException {
		String secret = "NY4A5CPJZ46LXZCP";
		assertEquals(162123, minor2.TOTPAuth.generateNumber(secret, 7439999,
				minor2.TOTPAuth.DEFAULT_TIME_SECONDS));
		assertTrue(minor2.TOTPAuth.validateCurrentNumber(secret, 325893, 0, 7455000,
				minor2.TOTPAuth.DEFAULT_TIME_SECONDS));
		assertFalse(minor2.TOTPAuth.validateCurrentNumber(secret, 948323, 0, 7455000,
				minor2.TOTPAuth.DEFAULT_TIME_SECONDS));
		assertTrue(minor2.TOTPAuth.validateCurrentNumber(secret, 325893, 15000, 7455000,
				minor2.TOTPAuth.DEFAULT_TIME_SECONDS));

		/*
		 * Test upper window which starts +15000 milliseconds.
		 */

		// but this is the next value and the window doesn't quite take us to the next time-step
		assertFalse(minor2.TOTPAuth.validateCurrentNumber(secret, 948323, 14999, 7455000,
				minor2.TOTPAuth.DEFAULT_TIME_SECONDS));
		// but this is the next value which is 15000 milliseconds ahead
		assertTrue(minor2.TOTPAuth.validateCurrentNumber(secret, 948323, 15000, 7455000,
				minor2.TOTPAuth.DEFAULT_TIME_SECONDS));
		assertFalse(minor2.TOTPAuth.validateCurrentNumber(secret, 287511, 15000, 7455000,
				minor2.TOTPAuth.DEFAULT_TIME_SECONDS));
		// but this is the previous value which is 15001 milliseconds earlier
		assertTrue(minor2.TOTPAuth.validateCurrentNumber(secret, 162123, 15001, 7455000,
				minor2.TOTPAuth.DEFAULT_TIME_SECONDS));
	}

	@Test
	public void testGenerateSecret() {
		assertEquals(16, minor2.TOTPAuth.generateBase32Secret().length());
		assertEquals(16, minor2.TOTPAuth.generateBase32Secret(16).length());
		assertEquals(1, minor2.TOTPAuth.generateBase32Secret(1).length());
	}

	@Test
	public void testWindow() throws GeneralSecurityException {
		String secret = minor2.TOTPAuth.generateBase32Secret();
		long window = 10000;
		Random random = new Random();
		for (int i = 0; i < 1000; i++) {
			long now = random.nextLong();
			if (now < 0) {
				now = -now;
			}
			int number = minor2.TOTPAuth.generateNumber(secret, now,
					minor2.TOTPAuth.DEFAULT_TIME_SECONDS);
			assertTrue(minor2.TOTPAuth.validateCurrentNumber(secret, number, window, now - window,
					minor2.TOTPAuth.DEFAULT_TIME_SECONDS));
			assertTrue(minor2.TOTPAuth.validateCurrentNumber(secret, number, window, now,
					minor2.TOTPAuth.DEFAULT_TIME_SECONDS));
			assertTrue(minor2.TOTPAuth.validateCurrentNumber(secret, number, window, now + window,
					minor2.TOTPAuth.DEFAULT_TIME_SECONDS));
		}
	}

	@Test
	public void testWindowStuff() throws GeneralSecurityException {
		String secret = minor2.TOTPAuth.generateBase32Secret();
		long window = 10000;
		long now = 5462669356666716002L;
		int number = minor2.TOTPAuth.generateNumber(secret, now,
				minor2.TOTPAuth.DEFAULT_TIME_SECONDS);
		assertTrue(minor2.TOTPAuth.validateCurrentNumber(secret, number, window, now - window,
				minor2.TOTPAuth.DEFAULT_TIME_SECONDS));
		assertTrue(minor2.TOTPAuth.validateCurrentNumber(secret, number, window, now,
				minor2.TOTPAuth.DEFAULT_TIME_SECONDS));
		assertTrue(minor2.TOTPAuth.validateCurrentNumber(secret, number, window, now + window,
				minor2.TOTPAuth.DEFAULT_TIME_SECONDS));

		now = 8835485943423840000L;
		number = minor2.TOTPAuth.generateNumber(secret, now,
				minor2.TOTPAuth.DEFAULT_TIME_SECONDS);
		assertFalse(minor2.TOTPAuth.validateCurrentNumber(secret, number, window, now - window - 1,
				minor2.TOTPAuth.DEFAULT_TIME_SECONDS));
		assertTrue(minor2.TOTPAuth.validateCurrentNumber(secret, number, window, now - window,
				minor2.TOTPAuth.DEFAULT_TIME_SECONDS));
		assertTrue(minor2.TOTPAuth.validateCurrentNumber(secret, number, window, now,
				minor2.TOTPAuth.DEFAULT_TIME_SECONDS));
		assertTrue(minor2.TOTPAuth.validateCurrentNumber(secret, number, window, now + window,
				minor2.TOTPAuth.DEFAULT_TIME_SECONDS));

		now = 8363681401523009999L;
		number = minor2.TOTPAuth.generateNumber(secret, now,
				minor2.TOTPAuth.DEFAULT_TIME_SECONDS);
		assertTrue(minor2.TOTPAuth.validateCurrentNumber(secret, number, window, now - window,
				minor2.TOTPAuth.DEFAULT_TIME_SECONDS));
		assertTrue(minor2.TOTPAuth.validateCurrentNumber(secret, number, window, now,
				minor2.TOTPAuth.DEFAULT_TIME_SECONDS));
		assertTrue(minor2.TOTPAuth.validateCurrentNumber(secret, number, window, now + window,
				minor2.TOTPAuth.DEFAULT_TIME_SECONDS));
		assertFalse(minor2.TOTPAuth.validateCurrentNumber(secret, number, window, now + window + 1,
				minor2.TOTPAuth.DEFAULT_TIME_SECONDS));
	}

	@Test
	public void testHexWindow() throws GeneralSecurityException {
		String hexSecret = minor2.TOTPAuth.generateHexSecret();
		long window = 10000;
		Random random = new Random();
		for (int i = 0; i < 1000; i++) {
			long now = random.nextLong();
			if (now < 0) {
				now = -now;
			}
			int number = minor2.TOTPAuth.generateNumberHex(hexSecret, now,
					minor2.TOTPAuth.DEFAULT_TIME_SECONDS);
			assertTrue(minor2.TOTPAuth.validateCurrentNumberHex(hexSecret, number, window, now - window,
					minor2.TOTPAuth.DEFAULT_TIME_SECONDS));
			assertTrue(minor2.TOTPAuth.validateCurrentNumberHex(hexSecret, number, window, now,
					minor2.TOTPAuth.DEFAULT_TIME_SECONDS));
			assertTrue(minor2.TOTPAuth.validateCurrentNumberHex(hexSecret, number, window, now + window,
					minor2.TOTPAuth.DEFAULT_TIME_SECONDS));
		}
	}

	@Test
	public void testCoverage() throws GeneralSecurityException {
		String secret = "ny4A5CPJZ46LXZCP";
		minor2.TOTPAuth.validateCurrentNumber(secret, 948323, 15000);
		assertEquals(minor2.TOTPAuth.DEFAULT_OTP_LENGTH,
				minor2.TOTPAuth.generateCurrentNumberString(secret).length());

		int number = minor2.TOTPAuth.generateCurrentNumber(secret);
		assertTrue(minor2.TOTPAuth.validateCurrentNumber(secret, number, 0, System.currentTimeMillis(),
				minor2.TOTPAuth.DEFAULT_TIME_SECONDS));

		int len = 3;
		assertEquals(len, minor2.TOTPAuth.generateCurrentNumberString(secret, len).length());
		int num = minor2.TOTPAuth.generateCurrentNumber(secret);
		assertTrue(num >= 0 && num < 1000000);
		num = minor2.TOTPAuth.generateCurrentNumber(secret, 3);
		assertTrue(num >= 0 && num < 1000);
		assertNotNull(minor2.TOTPAuth.generateOtpAuthUrl("key", secret));
		assertNotNull(minor2.TOTPAuth.generateOtpAuthUrl("key", secret, 8));
		assertNotNull(minor2.TOTPAuth.qrImageUrl("key", secret));
		assertNotNull(minor2.TOTPAuth.qrImageUrl("key", secret, 3));
		assertNotNull(minor2.TOTPAuth.qrImageUrl("key", secret, 3, 500));

		String hexSecret = "0123456789abcdefABCDEF";
		num = minor2.TOTPAuth.generateCurrentNumberHex(hexSecret);
		assertTrue(num >= 0 && num < 1000000);
		num = minor2.TOTPAuth.generateCurrentNumberHex(hexSecret, 3);
		assertTrue(num >= 0 && num < 1000);
		minor2.TOTPAuth.validateCurrentNumberHex(hexSecret, num, 0);
		assertNotNull(minor2.TOTPAuth.generateCurrentNumberStringHex(hexSecret));
		assertNotNull(minor2.TOTPAuth.generateCurrentNumberStringHex(hexSecret, 3));
		minor2.TOTPAuth.decodeHex("01234");

		try {
			minor2.TOTPAuth.generateCurrentNumber(".");
			fail("Should have thrown");
		} catch (IllegalArgumentException iae) {
			// expected
		}
		try {
			minor2.TOTPAuth.generateCurrentNumber("^");
			fail("Should have thrown");
		} catch (IllegalArgumentException iae) {
			// expected
		}

		try {
			minor2.TOTPAuth.decodeBase32("0");
			fail("Should have thrown");
		} catch (IllegalArgumentException iae) {
			// expected
		}

		try {
			minor2.TOTPAuth.decodeBase32("/");
			fail("Should have thrown");
		} catch (IllegalArgumentException iae) {
			// expected
		}

		try {
			minor2.TOTPAuth.decodeBase32("^");
			fail("Should have thrown");
		} catch (IllegalArgumentException iae) {
			// expected
		}

		try {
			minor2.TOTPAuth.decodeBase32("~");
			fail("Should have thrown");
		} catch (IllegalArgumentException iae) {
			// expected
		}

		try {
			minor2.TOTPAuth.decodeHex("z");
			fail("Should have thrown");
		} catch (IllegalArgumentException iae) {
			// expected
		}

		try {
			minor2.TOTPAuth.decodeHex("/");
			fail("Should have thrown");
		} catch (IllegalArgumentException iae) {
			// expected
		}

		try {
			minor2.TOTPAuth.decodeHex("^");
			fail("Should have thrown");
		} catch (IllegalArgumentException iae) {
			// expected
		}

		try {
			minor2.TOTPAuth.decodeHex("~");
			fail("Should have thrown");
		} catch (IllegalArgumentException iae) {
			// expected
		}
	}
}