package com.github.zhuobie.sm2;

import com.sun.jna.*;

import java.util.Arrays;
import java.util.List;

interface CLibrary extends Library {
    CLibrary INSTANCE = Native.load("smcrypto", CLibrary.class);
    class Keypair extends Structure {
        public static class ByReference extends Keypair implements Structure.ByReference {}
        public static class ByValue extends Keypair implements Structure.ByValue {}
        public String private_key;
        public String public_key;
        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("private_key", "public_key");
        }
    }
    Keypair.ByReference gen_keypair();
    Pointer pk_from_sk(String private_key);
    int pubkey_valid(String public_key);
    Keypair.ByReference keypair_from_pem_file(String file_path);
    void keypair_to_pem_file(String private_key, String file_path);
    Pointer pubkey_from_pem_file(String public_key);
    void pubkey_to_pem_file(String public_key, String file_path);
    Pointer sign(byte[] id, int id_len, byte[] data, int data_len, String private_key, Pointer sig_length);
    int verify(byte[] id, int id_len, byte[] data, int data_len, byte[] sign, int sign_len, String public_key);
    void sign_to_file(byte[] id, int id_len, byte[] data, int data_len, String sign_file, String private_key);
    int verify_from_file(byte[] id, int id_len, byte[] data, int data_len, String sign_file, String public_key);
    Pointer encrypt(byte[] data, int data_len, String public_key, Pointer enc_len);
    Pointer decrypt(byte[] data, int data_len, String private_key, Pointer dec_len);
    Pointer encrypt_c1c2c3(byte[] data, int data_len, String public_key, Pointer enc_len);
    Pointer decrypt_c1c2c3(byte[] data, int data_len, String private_key, Pointer dec_len);
    Pointer encrypt_asna1(byte[] data, int data_len, String public_key, Pointer enc_len);
    Pointer decrypt_asna1(byte[] data, int data_len, String private_key, Pointer dec_len);
    Pointer encrypt_hex(byte[] data, int data_len, String public_key);
    Pointer decrypt_hex(String data, String private_key, Pointer dec_len);
    Pointer encrypt_base64(byte[] data, int data_len, String public_key);
    Pointer decrypt_base64(String data, String private_key, Pointer dec_len);
    void encrypt_to_file(byte[] data, int data_len, String enc_file, String public_key);
    Pointer decrypt_from_file(String dec_file, String private_key, Pointer dec_len);

    class KeyExchangeData extends Structure {
        public static class ByReference extends KeyExchangeData implements Structure.ByReference {}
        public static class ByValue extends KeyExchangeData implements Structure.ByValue {}
        public Pointer data;
        public String private_key_r;
        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("data", "private_key_r");
        }
    }
    class KeyExchangeResult extends Structure {
        public static class ByReference extends KeyExchangeResult implements Structure.ByReference {}
        public static class ByValue extends KeyExchangeResult implements Structure.ByValue {}
        public String k;
        public Pointer s12;
        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("k", "s12");
        }
    }
    KeyExchangeData.ByReference keyexchange_1ab(int klen, byte[] id, int id_len, String private_key, Pointer data_len);
    KeyExchangeResult.ByReference keyexchange_2a(byte[] id, int id_len, String private_key, String private_key_r, byte[] recive_bytes, int recive_bytes_len, Pointer s12_len);
    KeyExchangeResult.ByReference keyexchange_2b(byte[] id, int id_len, String private_key, String private_key_r, byte[] recive_bytes, int recive_bytes_len, Pointer s12_len);

    void free_byte_array(Pointer ptr, int len);
    void free_char_array(Pointer ptr);
    void free_struct_keyexchangedata(KeyExchangeData.ByReference keyexchangedata);
    void free_struct_keyexchangeresult(KeyExchangeResult.ByReference keyexchangeresult);
    void free_struct_keypair(Keypair.ByReference keypair);
}

/**
 * 用于国密SM2非对称加密算法，包含密钥生成/导入/导出、签名/验签、加密/解密、密钥交换
 */
public class SM2 {
    /**
     * 密钥对，包含2个成员，分别代表私钥和公钥，以16进制字符串表示
     */
    public static class Keypair {
        public String private_key;
        public String public_key;
    }

    /**
     * 生成密钥对，公钥不包含开头的04标记
     * @return 生成的密钥对对象
     */
    public static Keypair gen_keypair() {
        var keypair = CLibrary.INSTANCE.gen_keypair();
        Keypair result = new Keypair();
        result.private_key = keypair.private_key;
        result.public_key = keypair.public_key;
        CLibrary.INSTANCE.free_struct_keypair(keypair);
        return result;
    }

    /**
     * 从私钥中提取公钥
     * @param private_key 私钥
     * @return 公钥，不包含开头的04标记
     */
    public static String pk_from_sk(String private_key) {
        Pointer p = CLibrary.INSTANCE.pk_from_sk(private_key);
        String result = p.getString(0);
        CLibrary.INSTANCE.free_char_array(p);
        return result;
    }

    /**
     * 验证公钥是否合法
     * @param public_key 公钥
     * @return 返回1代表合法，0代表非法
     */
    public static int pubkey_valid(String public_key) {
        return CLibrary.INSTANCE.pubkey_valid(public_key);
    }

    /**
     * 从本地pem文件中提取密钥对
     * @param file_path 本地pem文件路径
     * @return 提取到的密钥对
     */
    public static Keypair keypair_from_pem_file(String file_path) {
        var keypair = CLibrary.INSTANCE.keypair_from_pem_file(file_path);
        Keypair result = new Keypair();
        result.private_key = keypair.private_key;
        result.public_key = keypair.public_key;
        CLibrary.INSTANCE.free_struct_keypair(keypair);
        return result;
    }

    /**
     * 将密钥对写入本地pem文件
     * @param private_key 私钥
     * @param file_path 写入本地pem文件的路径
     */
    public static void keypair_to_pem_file(String private_key, String file_path) {
        CLibrary.INSTANCE.keypair_to_pem_file(private_key, file_path);
    }

    /**
     * 从本地pem文件中提取公钥
     * @param file_path 本地pem文件路径
     * @return 公钥
     */
    public static String pubkey_from_pem_file(String file_path) {
        Pointer p = CLibrary.INSTANCE.pubkey_from_pem_file(file_path);
        String result = p.getString(0);
        CLibrary.INSTANCE.free_char_array(p);
        return result;
    }

    /**
     * 将公钥写入本地pem文件
     * @param public_key 公钥
     * @param file_path 要写入的本地pem文件路径
     */
    public static void pubkey_to_pem_file(String public_key, String file_path) {
        CLibrary.INSTANCE.pubkey_to_pem_file(public_key, file_path);
    }

    /**
     * 签名操作
     * @param id 以字节数组表示的id
     * @param data 待签名数据
     * @param private_key 私钥
     * @return 签名数据
     */
    public static byte[] sign(byte[] id, byte[] data, String private_key) {
        Pointer sig_length = new Memory(4);
        Pointer p = CLibrary.INSTANCE.sign(id, id.length, data, data.length, private_key, sig_length);
        byte[] sig = p.getByteArray(0, sig_length.getInt(0));
        CLibrary.INSTANCE.free_byte_array(p, sig_length.getInt(0));
        return sig;
    }

    /**
     * 验签操作
     * @param id 以字节数组表示的id
     * @param data 待验签数据
     * @param sign 签名数据
     * @param public_key 公钥
     * @return 返回1为验证通过，0为不通过
     */
    public static int verify(byte[] id, byte[] data, byte[] sign, String public_key) {
        return CLibrary.INSTANCE.verify(id, id.length, data, data.length, sign, sign.length, public_key);
    }

    /**
     * 签名并保存签名数据到本地文件
     * @param id 以字节数组表示的id
     * @param data 待签名数据
     * @param sign_file 要保存签名数据的路径
     * @param private_key 私钥
     */
    public static void sign_to_file(byte[] id, byte[] data, String sign_file, String private_key) {
        CLibrary.INSTANCE.sign_to_file(id, id.length, data, data.length, sign_file, private_key);
    }

    /**
     * 从本地文件进行验签
     * @param id 以自己数组表示的id
     * @param data 待验签数据
     * @param sign_file 签名文件
     * @param public_key 公钥
     * @return 返回1为验证通过，0为不通过
     */
    public static int verify_from_file(byte[] id, byte[] data, String sign_file, String public_key) {
        return CLibrary.INSTANCE.verify_from_file(id, id.length, data, data.length, sign_file, public_key);
    }

    /**
     * SM2加密
     * @param data 待加密数据
     * @param public_key 公钥
     * @return 密文
     */
    public static byte[] encrypt(byte[] data, String public_key) {
        Pointer enc_length = new Memory(4);
        Pointer p = CLibrary.INSTANCE.encrypt(data, data.length, public_key, enc_length);
        byte[] enc = p.getByteArray(0, enc_length.getInt(0));
        CLibrary.INSTANCE.free_byte_array(p, enc_length.getInt(0));
        return enc;
    }

    /**
     * SM2解密
     * @param data 待解密数据
     * @param private_key 私钥
     * @return 原文
     */
    public static byte[] decrypt(byte[] data, String private_key) {
        Pointer dec_length = new Memory(4);
        Pointer p = CLibrary.INSTANCE.decrypt(data, data.length, private_key, dec_length);
        byte[] dec = p.getByteArray(0, dec_length.getInt(0));
        CLibrary.INSTANCE.free_byte_array(p, dec_length.getInt(0));
        return dec;
    }

    /**
     * SM2加密，但密文排列方式为c1c2c3
     * @param data 待加密数据
     * @param public_key 公钥
     * @return 密文
     */
    public static byte[] encrypt_c1c2c3(byte[] data, String public_key) {
        Pointer enc_length = new Memory(4);
        Pointer p = CLibrary.INSTANCE.encrypt_c1c2c3(data, data.length, public_key, enc_length);
        byte[] enc = p.getByteArray(0, enc_length.getInt(0));
        CLibrary.INSTANCE.free_byte_array(p, enc_length.getInt(0));
        return enc;
    }

    /**
     * SM3解密，但密文排列方式为c1c2c3
     * @param data 待解密数据
     * @param private_key 私钥
     * @return 原文
     */
    public static byte[] decrypt_c1c2c3(byte[] data, String private_key) {
        Pointer dec_length = new Memory(4);
        Pointer p = CLibrary.INSTANCE.decrypt_c1c2c3(data, data.length, private_key, dec_length);
        byte[] dec = p.getByteArray(0, dec_length.getInt(0));
        CLibrary.INSTANCE.free_byte_array(p, dec_length.getInt(0));
        return dec;
    }

    /**
     * SM2加密，结果使用ASN.1编码
     * @param data 待加密数据
     * @param public_key 公钥
     * @return 密文
     */
    public static byte[] encrypt_asna1(byte[] data, String public_key) {
        Pointer enc_length = new Memory(4);
        Pointer p = CLibrary.INSTANCE.encrypt_asna1(data, data.length, public_key, enc_length);
        byte[] enc = p.getByteArray(0, enc_length.getInt(0));
        CLibrary.INSTANCE.free_byte_array(p, enc_length.getInt(0));
        return enc;
    }

    /**
     * SM2解密，密文使用ASN.1编码
     * @param data 待解密数据
     * @param private_key 私钥
     * @return 原文
     */
    public static byte[] decrypt_asna1(byte[] data, String private_key) {
        Pointer dec_length = new Memory(4);
        Pointer p = CLibrary.INSTANCE.decrypt_asna1(data, data.length, private_key, dec_length);
        byte[] dec = p.getByteArray(0, dec_length.getInt(0));
        CLibrary.INSTANCE.free_byte_array(p, dec_length.getInt(0));
        return dec;
    }

    /**
     * SM2加密，但密文以16进制字符串输出
     * @param data 待加密数据
     * @param public_key 公钥
     * @return 密文
     */
    public static String encrypt_hex(byte[] data, String public_key) {
        Pointer p = CLibrary.INSTANCE.encrypt_hex(data, data.length, public_key);
        String result = p.getString(0);
        CLibrary.INSTANCE.free_char_array(p);
        return result;
    }

    /**
     * SM2解密，但密文以16进制字符串输入
     * @param data 待解密数据
     * @param private_key 私钥
     * @return 明文
     */
    public static byte[] decrypt_hex(String data, String private_key) {
        Pointer dec_length = new Memory(4);
        Pointer p = CLibrary.INSTANCE.decrypt_hex(data, private_key, dec_length);
        byte[] dec = p.getByteArray(0, dec_length.getInt(0));
        CLibrary.INSTANCE.free_byte_array(p, dec_length.getInt(0));
        return dec;
    }

    /**
     * SM2解密，但密文以base64形式输出
     * @param data 待加密数据
     * @param public_key 公钥
     * @return 密文
     */
    public static String encrypt_base64(byte[] data, String public_key) {
        Pointer p = CLibrary.INSTANCE.encrypt_base64(data, data.length, public_key);
        String result = p.getString(0);
        CLibrary.INSTANCE.free_char_array(p);
        return result;
    }

    /**
     * SM2解密，但密文以base64形式输入
     * @param data 待解密数据
     * @param private_key 私钥
     * @return 原文
     */
    public static byte[] decrypt_base64(String data, String private_key) {
        Pointer dec_length = new Memory(4);
        Pointer p = CLibrary.INSTANCE.decrypt_base64(data, private_key, dec_length);
        byte[] dec = p.getByteArray(0, dec_length.getInt(0));
        CLibrary.INSTANCE.free_byte_array(p, dec_length.getInt(0));
        return dec;
    }

    /**
     * SM2加密数据到文件
     * @param data 待加密数据
     * @param enc_file 输出加密数据文件
     * @param public_key 公钥
     */
    public static void encrypt_to_file(byte[] data, String enc_file, String public_key) {
        CLibrary.INSTANCE.encrypt_to_file(data, data.length, enc_file, public_key);
    }

    /**
     * SM2从文件解密
     * @param dec_file 待解密数据文件
     * @param private_key 私钥
     * @return 原文
     */
    public static byte[] decrypt_from_file(String dec_file, String private_key) {
        Pointer dec_length = new Memory(4);
        Pointer p = CLibrary.INSTANCE.decrypt_from_file(dec_file, private_key, dec_length);
        byte[] dec = p.getByteArray(0, dec_length.getInt(0));
        CLibrary.INSTANCE.free_byte_array(p, dec_length.getInt(0));
        return dec;
    }

    /**
     * a和b进行密钥协商交换的数据
     */
    public static class KeyExchangeData {
        public byte[] data;
        public String private_key_r;
    }

    /**
     * 密钥协商的结果，包含协商的密钥
     */
    public static class KeyExchangeResult {
        public String k;
        byte[] s12;
    }

    /**
     * 第一步，a和b各自生成发送给对方的数据
     * @param klen 密钥长度
     * @param id 各自个人id
     * @param private_key 各自私钥
     * @return 要发送给对方的数据
     */
    public static KeyExchangeData keyexchange_1ab(int klen, byte[] id, String private_key) {
        Pointer data_length = new Memory(4);
        var keyexchangedata = CLibrary.INSTANCE.keyexchange_1ab(klen, id, id.length, private_key, data_length);
        KeyExchangeData result = new KeyExchangeData();
        result.private_key_r = keyexchangedata.private_key_r;
        result.data = keyexchangedata.data.getByteArray(0, data_length.getInt(0));
        CLibrary.INSTANCE.free_struct_keyexchangedata(keyexchangedata);
        return result;
    }

    /**
     * 第二步，a获取密钥协商的结果
     * @param id a的个人id
     * @param private_key a的私钥
     * @param private_key_r a的临时私钥
     * @param recive_bytes a从b接收到的数据
     * @return 密钥协商结果，包含协商的密钥
     */
    public static KeyExchangeResult keyexchange_2a(byte[] id, String private_key, String private_key_r, byte[] recive_bytes) {
        Pointer s12_len = new Memory(4);
        var keyexchangeresult = CLibrary.INSTANCE.keyexchange_2a(id, id.length, private_key, private_key_r, recive_bytes, recive_bytes.length, s12_len);
        KeyExchangeResult result = new KeyExchangeResult();
        result.k = keyexchangeresult.k;
        result.s12 = keyexchangeresult.s12.getByteArray(0, s12_len.getInt(0));
        CLibrary.INSTANCE.free_struct_keyexchangeresult(keyexchangeresult);
        return result;
    }

    /**
     * 第二步，b获取密钥协商的结果
     * @param id b的个人id
     * @param private_key b的私钥
     * @param private_key_r b的临时私钥
     * @param recive_bytes b从a接收到的数据
     * @return 密钥协商结果，包含协商的密钥
     */
    public static KeyExchangeResult keyexchange_2b(byte[] id, String private_key, String private_key_r, byte[] recive_bytes) {
        Pointer s12_len = new Memory(4);
        var keyexchangeresult = CLibrary.INSTANCE.keyexchange_2b(id, id.length, private_key, private_key_r, recive_bytes, recive_bytes.length, s12_len);
        KeyExchangeResult result = new KeyExchangeResult();
        result.k = keyexchangeresult.k;
        result.s12 = keyexchangeresult.s12.getByteArray(0, s12_len.getInt(0));
        CLibrary.INSTANCE.free_struct_keyexchangeresult(keyexchangeresult);
        return result;
    }
}
