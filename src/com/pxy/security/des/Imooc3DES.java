package com.pxy.security.des;

import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Imooc3DES {
	private static String src = "imooc security 3des";
	
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		jdk3DES();
		bc3DES();
	}
	
	public static void jdk3DES() {
		try {
			//������Կ
			KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede");
			keyGenerator.init(new SecureRandom());//�Զ�����Կһ��Ĭ�ϳ���
			SecretKey secretKey = keyGenerator.generateKey();//������Կ
			byte[] key = secretKey.getEncoded();//����Կ����
			
			//ת��Ϊ������Կ
			DESedeKeySpec deSedeKeySpec = new DESedeKeySpec(key);//����Կת��Ϊ���õĸ�ʽ
			SecretKeyFactory factory = SecretKeyFactory.getInstance("DESede");
			Key convertKey = factory.generateSecret(deSedeKeySpec);//����Կ����
			
			//������Կ�����ݼ���
			Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, convertKey);
			byte[] result = cipher.doFinal(src.getBytes());
			System.out.println("jdk3DES encrypt:" + Hex.encodeHexString(result));
			
			//����ͬһ��Կ�����ݽ���
			cipher.init(Cipher.DECRYPT_MODE, convertKey);
			result = cipher.doFinal(result);
			System.out.println("jdk3DES decrypt:" + new String(result));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public static void bc3DES() {
		try {
			//������Կ
			Security.addProvider(new BouncyCastleProvider());
			KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede","BC");
			keyGenerator.init(new SecureRandom());//�Զ�����Կһ��Ĭ�ϳ���
			SecretKey secretKey = keyGenerator.generateKey();//������Կ
			byte[] key = secretKey.getEncoded();//����Կ����
			
			//ת��Ϊ������Կ
			DESedeKeySpec deSedeKeySpec = new DESedeKeySpec(key);//����Կת��Ϊ���õĸ�ʽ
			SecretKeyFactory factory = SecretKeyFactory.getInstance("DESede");
			Key convertKey = factory.generateSecret(deSedeKeySpec);//����Կ����
			
			//������Կ�����ݼ���
			Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, convertKey);
			byte[] result = cipher.doFinal(src.getBytes());
			System.out.println("bc3DES encrypt:" + Hex.encodeHexString(result));
			
			//����ͬһ��Կ�����ݽ���
			cipher.init(Cipher.DECRYPT_MODE, convertKey);
			result = cipher.doFinal(result);
			System.out.println("bc3DES decrypt:" + new String(result));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
