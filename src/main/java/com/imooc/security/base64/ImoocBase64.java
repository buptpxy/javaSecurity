package main.java.com.imooc.security.base64;

import java.io.IOException;

import org.apache.commons.codec.binary.Base64;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class ImoocBase64 {

	private static String src = "imooc security base64";
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		jdkBase64();
		commonsCodesBase64();
		bouncyCastleBase64();
	}
	public static void jdkBase64() {
		BASE64Encoder encoder = new BASE64Encoder();
		String encode = encoder.encode(src.getBytes());
		System.out.println("jdkBase64 encode:" + encode);
		BASE64Decoder decoder = new BASE64Decoder();
		try {
			byte[] decode = decoder.decodeBuffer(encode);
			System.out.println("jdkBase64 decode:" + new String(decode));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	public static void commonsCodesBase64() {
		byte[] encode = Base64.encodeBase64(src.getBytes());
		System.out.println("commonsCodesBase64 encode:" + new String(encode));
		byte[] decode = Base64.decodeBase64(encode);
		System.out.println("commonsCodesBase64 decode:" + new String(decode));
	}
	public static void bouncyCastleBase64() {
		byte[] encode = org.bouncycastle.util.encoders.Base64.encode(src.getBytes());
		System.out.println("bouncyCastleBase64 encode:" + new String(encode));
		byte[] decode = org.bouncycastle.util.encoders.Base64.decode(encode);
		System.out.println("bouncyCastleBase64 decode:" + new String(decode));
	}

}
