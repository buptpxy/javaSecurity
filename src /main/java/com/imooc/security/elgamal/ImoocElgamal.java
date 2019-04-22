package main.java.com.imooc.security.elgamal;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.spec.DHParameterSpec;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ImoocElgamal {
	private static String src = "imooc security Elgamal" ;
	public static void main(String[] args) {
		BCElGamal();
	}

	public static void BCElGamal() {
		// TODO Auto-generated method stub
		try {
			Security.addProvider(new BouncyCastleProvider());
			AlgorithmParameterGenerator algorithmParameterGenerator =AlgorithmParameterGenerator.getInstance("ElGamal");
			algorithmParameterGenerator.init(256);
			AlgorithmParameters algorithmParameters = algorithmParameterGenerator.generateParameters();
			DHParameterSpec dhParameterSpec = (DHParameterSpec)algorithmParameters.getParameterSpec(DHParameterSpec.class);
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ElGamal");
			keyPairGenerator.initialize(dhParameterSpec, new SecureRandom());
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			PublicKey elGamalPublicKey = keyPair.getPublic();
			PrivateKey elGamalPrivateKey = keyPair.getPrivate();
			System.out.println("public key:" + Base64.encodeBase64String(elGamalPublicKey.getEncoded()));
			System.out.println("private key:" + Base64.encodeBase64String(elGamalPrivateKey.getEncoded()));
			//π´‘øº”√‹
			X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(elGamalPublicKey.getEncoded());
			KeyFactory keyFactory = KeyFactory.getInstance("ElGamal");
			PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
			Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			byte[] result = cipher.doFinal(src.getBytes());
			System.out.println("encrypt:" + Base64.encodeBase64String(result) );
			//ÀΩ‘øΩ‚√‹
			PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(elGamalPrivateKey.getEncoded());
			keyFactory = KeyFactory.getInstance("ElGamal");
			PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
			cipher = Cipher.getInstance("ElGamal");
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			result = cipher.doFinal(result);
			System.out.println("decrypt:" + new String(result));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
}
