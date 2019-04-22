package com.pxy.security.aes;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;

public class AES {
	private static String src = "security aes";
	public static void main(String[] args) {
		// TODO Auto-generated method stub

		jdkAES();
		bcAES();
	}
	
	public static void jdkAES() {
		
		try {
			//������Կ
			KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
			keyGenerator.init(new SecureRandom());
			SecretKey secretKey = keyGenerator.generateKey();
			byte[] key = secretKey.getEncoded();
			//ת����Կ
			Key convertKey = new SecretKeySpec(key, "AES");
			//����
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, convertKey);
			byte[] result = cipher.doFinal(src.getBytes());
			System.out.println("jdkAES encrypt:" + Hex.encodeHexString(result) );
			//����
			cipher.init(Cipher.DECRYPT_MODE, convertKey);
			result = cipher.doFinal(result);
			System.out.println("jdkAES decrypt:" + new String(result));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
public static void bcAES() {
		
		try {
			Security.addProvider(new BouncyCastleProvider());
			//������Կ
			KeyGenerator keyGenerator = KeyGenerator.getInstance("AES","BC");
			keyGenerator.init(128);//������new SecureRandom()
			SecretKey secretKey = keyGenerator.generateKey();
			byte[] key = secretKey.getEncoded();
			//ת����Կ
			Key convertKey = new SecretKeySpec(key, "AES");
			//����
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, convertKey);
			byte[] result = cipher.doFinal(src.getBytes());
			System.out.println("bcAES encrypt:" + Hex.encodeHexString(result) );
			//����
			cipher.init(Cipher.DECRYPT_MODE, convertKey);
			result = cipher.doFinal(result);
			System.out.println("bcAES decrypt:" + new String(result));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

}
