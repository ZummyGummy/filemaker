import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream
import java.io.ObjectOutputStream
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.NoSuchAlgorithmException
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.InvalidKeySpecException
import java.security.spec.RSAPrivateKeySpec
import java.security.spec.RSAPublicKeySpec
import javax.crypto.Cipher

final String PUBLIC_KEY_FILE = "Public.key"
final String PRIVATE_KEY_FILE = "Private.key"
//Muda o caminho :) formato .pem!
String fileName = "C:\\Users\\bruno.manica\\Desktop\\FM-js\\pktest.txt"

String data = "The quick brown fox jumps over teh lazy dog"

KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA")
keyPairGenerator.initialize(2048)
KeyPair keyPair = keyPairGenerator.generateKeyPair()

//PublicKey publicKey = keyPair.getPublic()
//PrivateKey privateKey = keyPair.getPrivate()

KeyFactory keyFactory = KeyFactory.getInstance("RSA")
//RSAPublicKeySpec rsaPublicKeySpec = keyFactory.getKeySpec(publicKey, RSAPublicKeySpec.class)
//RSAPrivateKeySpec rsaPrivateKeySpec = keyFactory.getKeySpec(privateKey, RSAPrivateKeySpec.class)

//read the keys
FileInputStream fis = null
ObjectInput ois = null

fis = new FileInputStream(new File(fileName))
ois = new ObjectInputStream(fis)

BigInteger modulus = (BigInteger) ois.readObject()
BigInteger exponent = (BigInteger) ois.readObject()

RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, exponent)
KeyFactory fact = KeyFactory.getInstance("RSA")
PublicKey publicKey = fact.generatePublic(rsaPublicKeySpec)



//Encrypt
byte[] dataToencrypt = data.getBytes()
byte[] encryptedData = null

try {
    Cipher cipher = Cipher.getInstance("RSA")
    cipher.init(Cipher.ENCRYPT_MODE, publicKey)
} catch (Exception e) {

}
