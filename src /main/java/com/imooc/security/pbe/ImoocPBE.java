package main.java.com.imooc.security.pbe;

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
			//初始化盐
			SecureRandom random = new SecureRandom();
			byte[] salt = random.generateSeed(8);
			
			//口令转换成密钥
			String password = "imooc";
			PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());//把口令转换成pbe可用的格式
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBEWITHMD5andDES");
			Key key = factory.generateSecret(pbeKeySpec);//把口令加密成密钥
			
			//加密
			PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, 100);
			Cipher cipher = Cipher.getInstance("PBEWITHMD5andDES");
			cipher.init(Cipher.ENCRYPT_MODE, key, pbeParameterSpec);
			byte[] result = cipher.doFinal(src.getBytes());
			System.out.println("jdkPBE encrypt:" + Hex.encodeHexString(result));
			
			//解密
			cipher.init(Cipher.DECRYPT_MODE, key, pbeParameterSpec);
			result = cipher.doFinal(result);
			System.out.println("jdkPBE decrypt:" + new String(result));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
