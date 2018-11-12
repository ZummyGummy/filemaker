import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import javax.crypto.Cipher;

final String PUBLIC_KEY_FILE = ""
final String PRIVATE_KEY_FILE = ""

String data = "ENTRADA DO PROGRAMA"
PublicKey pubKey = "public key";

KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA")
keyPairGenerator.initialize(2048)
KeyPair keyPair = keyPairGenerator.generateKeyPair()

PublicKey publicKey = keyPair.getPublic()
PrivateKey privateKey = keyPair.getPrivate()

KeyFactory keyFactory = KeyFactory.getInstance("RSA")
RSAPublicKeySpec rsaPublicKeySpec = keyFactory.getKeySpec(publicKey, RSAPublicKeySpec.class)
RSAPrivateKeySpec rsaPrivateKeySpec = keyFactory.getKeySpec(privateKey, RSAPrivateKeySpec.class)

FileInputStream fis = null
ObjectInput ois = null

BigInteger modulus = (BigInteger) ois.readObject()
BigInteger exponent = (BigInteger) ois.readObject()



//Encrypt
byte[] dataToencrypt = data.getBytes()
byte[] encryptedData = null

try {
    PublicKey pubKey = pubKey
} catch () {

}
