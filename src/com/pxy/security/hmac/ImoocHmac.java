package com.pxy.security.hmac;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

public class ImoocHmac {
	private static String src = "imooc security hmac"; 
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		jdkHmacMD5();
		bcHmacMD5();
	}
	
	public static void jdkHmacMD5() {
		try {
			//��ʼ��KeyGenerator
			KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacMD5");
			//������Կ
			SecretKey secretKey = keyGenerator.generateKey();
			//�����Կ
//			byte[] key = secretKey.getEncoded();//���������Կ
			byte[] key = Hex.decodeHex(new char[]{'a','a','a','a','a','a','a','a','a','a'});//ʹ�ø�������Կ
			System.out.println("key:" + Hex.encodeHexString(key));
			//��ԭ��Կ
			SecretKey restoreSecretKey = new SecretKeySpec(key, "HmacMD5");
			System.out.println("restoreSecretKey:" + restoreSecretKey);
			//ʵ����mac
			Mac mac = Mac.getInstance(restoreSecretKey.getAlgorithm());
			//��ʼ��mac
			mac.init(restoreSecretKey);
			System.out.println("mac:" + mac);
			//ִ��ժҪ
			byte[] hmac = mac.doFinal(src.getBytes());
			//��ӡժҪ
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
