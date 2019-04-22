package main.java.com.imooc.security.hmac;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class ImoocHmac {
	private static String src = "imooc security hmac"; 
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		jdkHmacMD5();
		bcHmacMD5();
	}
	
	public static void jdkHmacMD5() {
		try {
			//初始化KeyGenerator
			KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacMD5");
			//产生密钥
			SecretKey secretKey = keyGenerator.generateKey();
			//获得密钥
//			byte[] key = secretKey.getEncoded();//随机生成密钥
			byte[] key = Hex.decodeHex(new char[]{'a','a','a','a','a','a','a','a','a','a'});//使用给定的密钥
			System.out.println("key:" + Hex.encodeHexString(key));
			//还原密钥
			SecretKey restoreSecretKey = new SecretKeySpec(key, "HmacMD5");
			System.out.println("restoreSecretKey:" + restoreSecretKey);
			//实例化mac
			Mac mac = Mac.getInstance(restoreSecretKey.getAlgorithm());
			//初始化mac
			mac.init(restoreSecretKey);
			System.out.println("mac:" + mac);
			//执行摘要
			byte[] hmac = mac.doFinal(src.getBytes());
			//打印摘要
			System.out.println("jdkHmacMD5:" + Hex.encodeHexString(hmac));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public static void bcHmacMD5() {
		HMac hMac = new HMac(new MD5Digest());
		hMac.init(new KeyParameter(org.bouncycastle.util.encoders.Hex.decode("aaaaaaaaaa")));
		hMac.update(src.getBytes(), 0, src.getBytes().length);
		byte[] hmac5 = new byte[hMac.getMacSize()];
		hMac.doFinal(hmac5, 0);
		System.out.println("bcHmacMD5:" + org.bouncycastle.util.encoders.Hex.toHexString(hmac5));
	}
	
	
}
