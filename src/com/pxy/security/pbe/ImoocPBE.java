package com.pxy.security.pbe;

import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.apache.commons.codec.binary.Hex;

public class ImoocPBE {
	private static String src = "imooc security pbe"; 
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		jdkPBE();
	}
	public static void jdkPBE() {
		try {
			//��ʼ����
			SecureRandom random = new SecureRandom();
			byte[] salt = random.generateSeed(8);
			
			//����ת������Կ
			String password = "imooc";
			PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());//�ѿ���ת����pbe���õĸ�ʽ
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBEWITHMD5andDES");
			Key key = factory.generateSecret(pbeKeySpec);//�ѿ�����ܳ���Կ
			
			//����
			PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, 100);
			Cipher cipher = Cipher.getInstance("PBEWITHMD5andDES");
			cipher.init(Cipher.ENCRYPT_MODE, key, pbeParameterSpec);
			byte[] result = cipher.doFinal(src.getBytes());
			System.out.println("jdkPBE encrypt:" + Hex.encodeHexString(result));
			
			//����
			cipher.init(Cipher.DECRYPT_MODE, key, pbeParameterSpec);
			result = cipher.doFinal(result);
			System.out.println("jdkPBE decrypt:" + new String(result));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
