import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static dev.yumeng.sm2.SM2.*;

public class SM2Test {
    @Test
    public void sm2_test() {
        // gen_keypair
        Keypair keypair = gen_keypair();

        // pk_from_sk
        String public_key = pk_from_sk(keypair.private_key);
        assertEquals(public_key, keypair.public_key);

        // pubkey_valid
        int valid = pubkey_valid(keypair.public_key);
        assertEquals(valid, 1);

        // sign and verify
        byte[] id = "yumeng@foxmail.com".getBytes();
        byte[] data = {97, 98, 99};
        String private_key = keypair.private_key;
        byte[] sig = sign(id, data, private_key);
        int verify = verify(id, data, sig, keypair.public_key);
        assertEquals(verify, 1);

        // encrypt and decrypt
        byte[] enc = encrypt(data, keypair.public_key);
        byte[] dec = decrypt(enc, keypair.private_key);
        assertArrayEquals(data, dec);

        // keyexchange
        int klen = 16;
        byte[] id_a = "a@github.com".getBytes();
        byte[] id_b = "b@github.com".getBytes();
        String ska = gen_keypair().private_key;
        String skb = gen_keypair().private_key;
        var keyexchange_a = keyexchange_1ab(klen, id_a, ska);
        var keyexchange_b = keyexchange_1ab(klen, id_b, skb);
        var keyexchange_2a = keyexchange_2a(id_a, ska, keyexchange_a.private_key_r, keyexchange_b.data);
        var keyexchange_2b = keyexchange_2b(id_b, skb, keyexchange_b.private_key_r, keyexchange_a.data);
        assertEquals(keyexchange_2a.k, keyexchange_2b.k);

        // encrypt_c1c2c3 and decrypt_c1c2c3
        enc = encrypt_c1c2c3(data, keypair.public_key);
        dec = decrypt_c1c2c3(enc, keypair.private_key);
        assertArrayEquals(data, dec);

        // encrypt_asna1 and decrypt asna1
        enc = encrypt_asna1(data, keypair.public_key);
        dec = decrypt_asna1(enc, keypair.private_key);
        assertArrayEquals(data, dec);

        // encrypt_hex and decrypt_hex
        String enc_hex = encrypt_hex(data, keypair.public_key);
        dec = decrypt_hex(enc_hex, keypair.private_key);
        assertArrayEquals(data, dec);

        // encrypt_base64 and decrypt_base64
        String enc_base64 = encrypt_base64(data, keypair.public_key);
        dec = decrypt_base64(enc_base64, keypair.private_key);
        assertArrayEquals(data, dec);
    }
}
