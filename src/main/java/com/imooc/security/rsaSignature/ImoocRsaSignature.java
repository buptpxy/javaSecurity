package main.java.com.imooc.security.rsaSignature;

import org.apache.commons.codec.binary.Hex;

import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class ImoocRsaSignature {

	private static String src = "imooc rsa signature";
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		jdkRsaSignature();
	}

	private static void jdkRsaSignature() {
		// TODO Auto-generated method stub
		try {
			//������Կ
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(512);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
			RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
			
			//ִ��ǩ��
			PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(rsaPrivateKey.getEncoded());
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		    PrivateKey privateKey =	keyFactory.generatePrivate(pkcs8EncodedKeySpec);
		    Signature signature = Signature.getInstance("MD5withRSA");
		    signature.initSign(privateKey);
		    signature.update(src.getBytes());
		    byte[] result = signature.sign();
		    System.out.println("signature:" + Hex.encodeHexString(result));
		    
		    //��֤ǩ��
		    X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(rsaPublicKey.getEncoded());
		    keyFactory = KeyFactory.getInstance("RSA");
		    PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
		    signature = Signature.getInstance("MD5withRSA");
		    signature.initVerify(publicKey);
		    signature.update(src.getBytes());
		    boolean bool = signature.verify(result);
		    System.out.println("verify:" + bool);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

}
