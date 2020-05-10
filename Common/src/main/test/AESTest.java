import junit.framework.Assert;
import org.junit.jupiter.api.Test;
import ru.geographer29.cryptography.AES;

public class AESTest {

    @Test
    public void shouldEncryptAndDecryptWith128BitKey(){
        String plain = "54776F204F6E65204E696E652054776F";
        int[][] iv = {{0, 0, 0, 0}, {0, 0, 0, 0}, {0, 0, 0, 0}, {0, 0, 0, 0}};
        String secretKey = "5468617473206D79204B756E67204675";
        AES aes = new AES(AES.Mode.ECB);
        System.out.println("Plain message = " + plain);

        String encrypted = aes.encrypt(plain, iv, secretKey);
        System.out.println("Encrypted message = " + encrypted);

        String decrypted = aes.decrypt(encrypted, iv, secretKey);
        System.out.println("Decrypted message = " + decrypted);

        Assert.assertEquals(plain, decrypted);
    }

    @Test
    public void shouldEncryptAndDecryptLongStringWith128BitKey(){
        String plain = "54776F204F6E65204E696E652054776F000000000000000054776F204F6E6520";
        int[][] iv = {{0, 0, 0, 0}, {0, 0, 0, 0}, {0, 0, 0, 0}, {0, 0, 0, 0}};
        String secretKey = "5468617473206D79204B756E67204675";
        AES aes = new AES(AES.Mode.ECB);
        System.out.println("Plain message = " + plain);

        String encrypted = aes.encrypt(plain, iv, secretKey);
        System.out.println("Encrypted message = " + encrypted);

        String decrypted = aes.decrypt(encrypted, iv, secretKey);
        System.out.println("Decrypted message = " + decrypted);

        Assert.assertEquals(plain, decrypted);
    }

    @Test
    public void shouldGenerateSecretKey(){
        String key = AES.generateSecretKey(128);
        System.out.println("Secret key = " + key);
        Assert.assertNotNull(key);
    }

    @Test
    public void shouldEncryptAndDecryptLongStringWith256BitKey(){
        String plain = "54776F204F6E65204E696E652054776F000000000000000054776F204F6E6520";
        int[][] iv = {{0, 0, 0, 0}, {0, 0, 0, 0}, {0, 0, 0, 0}, {0, 0, 0, 0}};
        String secretKey = "5468617473206D79204B756E672046753E24CAF8EE6CB4E03AA25E5F2B8D9E17";
        AES aes = new AES(AES.Mode.ECB);
        System.out.println("Plain message = " + plain);

        String encrypted = aes.encrypt(plain, iv, secretKey);
        System.out.println("Encrypted message = " + encrypted);

        String decrypted = aes.decrypt(encrypted, iv, secretKey);
        System.out.println("Decrypted message = " + decrypted);

        Assert.assertEquals(plain, decrypted);
    }

}
