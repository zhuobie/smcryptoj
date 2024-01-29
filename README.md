## SM国密算法Java绑定

### 简介

SM国密算法的Java绑定，使用JNA绑定Rust FFI实现，已实现功能：

- SM3消息摘要算法。
- SM2非对称加密算法，包括密钥生成/导入/导出，签名/验签，加密/解密，密钥协商。
- SM4对称加密算法，包括ECB模式和CBC模式。

因为通过调用本地库实现，目前仅支持Windows x64和Linux x64平台，要在其他平台实现，可自行编译。

### 快速开始

在Maven项目中引入`pom.xml`文件：

```xml
<dependency>
    <groupId>dev.yumeng</groupId>
    <artifactId>smcryptoj</artifactId>
    <version>0.1.0</version>
</dependency>
```

### 代码示例

```java
import java.util.Arrays;

import dev.yumeng.sm3.SM3;
import dev.yumeng.sm2.SM2;
import dev.yumeng.sm4.SM4;

/**
 * 测试了SM3、SM2、SM4算法，打印出结果。
 */
public class testSM {
    public static void test_sm() {
        //// SM3 Test
        byte[] msg_bytes = {97, 98, 99};
        String msg_bytes_hash = SM3.sm3_hash(msg_bytes);
        System.out.println("sm3 hash: " + msg_bytes_hash);

        //// SM2 Test
        // gen_keypair
        SM2.Keypair keypair = SM2.gen_keypair();
        System.out.println("private key: " + keypair.private_key);
        System.out.println("public_key: " + keypair.public_key);

        // pk_from_sk
        String public_key = SM2.pk_from_sk(keypair.private_key);
        System.out.println("public key from private key: " + public_key);

        // pubkey_valid
        int valid = SM2.pubkey_valid(keypair.public_key);
        System.out.println("public key valid: " + valid);

        // sign and verify
        byte[] id = "yumeng@foxmail.com".getBytes();
        byte[] data = {97, 98, 99};
        String private_key = keypair.private_key;
        byte[] sig = SM2.sign(id, data, private_key);
        int verify = SM2.verify(id, data, sig, keypair.public_key);
        System.out.println("verify result: " + verify);

        // encrypt and decrypt
        byte[] enc = SM2.encrypt(data, keypair.public_key);
        byte[] dec = SM2.decrypt(enc, keypair.private_key);
        System.out.println("decrypt data: " + Arrays.toString(dec));

        // keyexchange
        int klen = 16;
        byte[] id_a = "a@github.com".getBytes();
        byte[] id_b = "b@github.com".getBytes();
        String ska = SM2.gen_keypair().private_key;
        String skb = SM2.gen_keypair().private_key;
        var keyexchange_a = SM2.keyexchange_1ab(klen, id_a, ska);
        var keyexchange_b = SM2.keyexchange_1ab(klen, id_b, skb);
        var keyexchange_2a = SM2.keyexchange_2a(id_a, ska, keyexchange_a.private_key_r, keyexchange_b.data);
        var keyexchange_2b = SM2.keyexchange_2b(id_b, skb, keyexchange_b.private_key_r, keyexchange_a.data);
        System.out.println("key from a: " + keyexchange_2a.k);
        System.out.println("key from b: " + keyexchange_2b.k);

        // encrypt_c1c2c3 and decrypt_c1c2c3
        enc = SM2.encrypt_c1c2c3(data, keypair.public_key);
        dec = SM2.decrypt_c1c2c3(enc, keypair.private_key);
        System.out.println("decrypt data: " + Arrays.toString(dec));

        // encrypt_asna1 and decrypt asna1
        enc = SM2.encrypt_asna1(data, keypair.public_key);
        dec = SM2.decrypt_asna1(enc, keypair.private_key);
        System.out.println("decrypt data: " + Arrays.toString(dec));

        // encrypt_hex and decrypt_hex
        String enc_hex = SM2.encrypt_hex(data, keypair.public_key);
        dec = SM2.decrypt_hex(enc_hex, keypair.private_key);
        System.out.println("decrypt data: " + Arrays.toString(dec));

        // encrypt_base64 and decrypt_base64
        String enc_base64 = SM2.encrypt_base64(data, keypair.public_key);
        dec = SM2.decrypt_base64(enc_base64, keypair.private_key);
        System.out.println("decrypt data: " + Arrays.toString(dec));

        //// SM4 Test
        // sm4 ecb encrypt and decrypt
        byte[] key = "1234567812345678".getBytes();
        enc = SM4.encrypt_ecb(data, key);
        dec = SM4.decrypt_ecb(enc, key);

        // sm4 ecb encrypt_base64 and decrypt_base64
        enc_base64 = SM4.encrypt_ecb_base64(data, key);
        dec = SM4.decrypt_ecb_base64(enc_base64, key);
        System.out.println("decrypt data: " + Arrays.toString(dec));

        // sm4 ecb encrypt hex and decrypt hex
        enc_hex = SM4.encrypt_ecb_hex(data, key);
        dec = SM4.decrypt_ecb_hex(enc_hex, key);
        System.out.println("decrypt data: " + Arrays.toString(dec));

        // sm4 cbc encrypt and decrypt
        byte[] iv = "0000000000000000".getBytes();
        enc = SM4.encrypt_cbc(data, key, iv);
        dec = SM4.decrypt_cbc(enc, key, iv);
        System.out.println("decrypt data: " + Arrays.toString(dec));

        // sm4 cbc encrypt_base64 and cbc decrypt_base64
        enc_base64 = SM4.encrypt_cbc_base64(data, key, iv);
        dec = SM4.decrypt_cbc_base64(enc_base64, key, iv);
        System.out.println("decrypt data: " + Arrays.toString(dec));

        // sm4 cbc encrypt_hex and cbc decrypt_hex
        enc_hex = SM4.encrypt_cbc_hex(data, key, iv);
        dec = SM4.decrypt_cbc_hex(enc_hex, key, iv);
        System.out.println("decrypt data: " + Arrays.toString(dec));
    }

    public static void main(String[] args) {
        for (int i = 1; i <= 100; i++) {
            System.out.println("count: " + i);
            test_sm();
        }
    }
}
```
