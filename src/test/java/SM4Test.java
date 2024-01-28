import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static com.github.zhuobie.sm4.SM4.*;

public class SM4Test {
    @Test
    public void sm4_test() {
        // sm4 ecb encrypt and decrypt
        byte[] key = "1234567812345678".getBytes();
        byte[] data = "abc".getBytes();
        byte[] enc = encrypt_ecb(data, key);
        byte[] dec = decrypt_ecb(enc, key);
        assertArrayEquals(dec, data);

        // sm4 ecb encrypt_base64 and decrypt_base64
        String enc_base64 = encrypt_ecb_base64(data, key);
        System.out.println(enc_base64);
        dec = decrypt_ecb_base64(enc_base64, key);
        assertArrayEquals(dec, data);

        // sm4 ecb encrypt hex and decrypt hex
        String enc_hex = encrypt_ecb_hex(data, key);
        System.out.println(enc_hex);
        dec = decrypt_ecb_hex(enc_hex, key);
        assertArrayEquals(dec, data);

        // sm4 cbc encrypt and decrypt
        byte[] iv = "0000000000000000".getBytes();
        enc = encrypt_cbc(data, key, iv);
        dec = decrypt_cbc(enc, key, iv);
        assertArrayEquals(dec, data);

        // sm4 cbc encrypt_base64 and cbc decrypt_base64
        enc_base64 = encrypt_cbc_base64(data, key, iv);
        dec = decrypt_cbc_base64(enc_base64, key, iv);
        assertArrayEquals(dec, data);

        // sm4 cbc encrypt_hex and cbc decrypt_hex
        enc_hex = encrypt_cbc_hex(data, key, iv);
        dec = decrypt_cbc_hex(enc_hex, key, iv);
        assertArrayEquals(dec, data);
    }
}
