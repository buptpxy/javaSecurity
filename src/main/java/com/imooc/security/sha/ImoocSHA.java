package main.java.com.imooc.security.sha;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class ImoocSHA {
	private static String src = "imooc security sha";
	public static void main(String[] args) {
		jdkSHA1();
		bcSHA1();
		ccSHA1();
	}
	public static void jdkSHA1() {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA");
			byte[] sha1 = md.digest(src.getBytes());
			/*
			  这一句可使用以下两句替代，得到的摘要是一样的
		    md.update(src.getBytes());
			byte[] sha1 = md.digest();
			*/
			System.out.println("jdkSHA1:" + Hex.encodeHexString(sha1));
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	public static void bcSHA1() {
		Digest digest = new SHA1Digest();
		digest.update(src.getBytes(), 0, src.getBytes().length);
		byte[] sha1 = new byte[digest.getDigestSize()];
		digest.doFinal(sha1, 0);
		System.out.println("bcSHA1:" + org.bouncycastle.util.encoders.Hex.toHexString(sha1));
	}
	public static void ccSHA1() {
		byte[] sha1 = DigestUtils.getSha1Digest().digest(src.getBytes());
		System.out.println("ccSHA1:" + Hex.encodeHexString(sha1));
	}
}
