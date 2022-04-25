package minor2;
public class TwoFactor 
{
	public static final String ANSI_RESET= "\u001B[0m";
	public static final String ANSI_BLUE= "\u001B[34m";
	public static void main(String[] args) throws Exception
	{
		 String base32Secret = TOTPAuth.generateBase32Secret();
		System.out.println("Secret Key " + base32Secret);
		String keyId = "minor2";
		System.out.print("Image URL = ");
		System.out.println(ANSI_BLUE+(TOTPAuth.qrImageUrl(keyId, base32Secret))+ANSI_RESET);
		String code;
		while (true) 
		{
			long time_diff = TOTPAuth.DEFAULT_TIME_SECONDS - ((System.currentTimeMillis() / 1000) % TOTPAuth.DEFAULT_TIME_SECONDS);
			code = TOTPAuth.generateCurrentNumberString(base32Secret);
			System.out.println("Secret code = " + code + ", change in " + time_diff + " seconds");
			Thread.sleep(1000);
		}
	}
}