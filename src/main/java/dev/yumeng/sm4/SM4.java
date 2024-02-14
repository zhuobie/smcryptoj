package dev.yumeng.sm4;

import com.sun.jna.*;

interface CLibrary extends Library {
    CLibrary INSTANCE = Native.load("smcrypto", CLibrary.class);
    Pointer encrypt_ecb(byte[] input_data, int input_data_len, byte[] key, int key_len, Pointer output_data_len);
    Pointer encrypt_ecb_base64(byte[] input_data, int input_data_len, byte[] key, int key_len);
    Pointer encrypt_ecb_hex(byte[] input_data, int input_data_len, byte[] key, int key_len);
    void encrypt_ecb_to_file(String input_file, String output_file, byte[] key, int key_len);
    Pointer decrypt_ecb(byte[] input_data, int input_data_len, byte[] key, int key_len, Pointer output_data_len);
    Pointer decrypt_ecb_base64(String input_data, byte[] key, int key_len, Pointer output_data_len);
    Pointer decrypt_ecb_hex(String input_data, byte[] key, int key_len, Pointer output_data_len);
    void decrypt_ecb_from_file(String input_file, String output_file, byte[] key, int key_len);
    Pointer encrypt_cbc(byte[] input_data, int input_data_len, byte[] key, int key_len, byte[] iv, int iv_len, Pointer output_data_len);
    Pointer encrypt_cbc_base64(byte[] input_data, int input_data_len, byte[] key, int key_len, byte[] iv, int iv_len);
    Pointer encrypt_cbc_hex(byte[] input_data, int input_data_len, byte[] key, int key_len, byte[] iv, int iv_len);
    void encrypt_cbc_to_file(String input_file, String output_file, byte[] key, int key_len, byte[] iv, int iv_len);
    Pointer decrypt_cbc(byte[] input_data, int input_data_len, byte[] key, int key_len, byte[] iv, int iv_len, Pointer output_data_len);
    Pointer decrypt_cbc_base64(String input_data, byte[] key, int key_len, byte[] iv, int iv_len, Pointer output_data_len);
    Pointer decrypt_cbc_hex(String input_data, byte[] key, int key_len, byte[] iv, int iv_len, Pointer output_data_len);
    void decrypt_cbc_from_file(String input_file, String output_file, byte[] key, int key_len, byte[] iv, int iv_len);
    void free_byte_array(Pointer ptr, int len);
    void free_char_array(Pointer ptr);}

/**
 * SM4对称加密算法，包含ECB和CBC模式
 */
public class SM4 {
    /**
     * SM4加密数据，ECB模式
     * @param input_data 待加密数据
     * @param key 密钥
     * @return 密文
     */
    public static byte[] encrypt_ecb(byte[] input_data, byte[] key) {
        Pointer output_data_len = new Memory(4);
        Pointer p = CLibrary.INSTANCE.encrypt_ecb(input_data, input_data.length, key, key.length, output_data_len);
        byte[] enc = p.getByteArray(0, output_data_len.getInt(0));
        CLibrary.INSTANCE.free_byte_array(p, output_data_len.getInt(0));
        return enc;
    }

    /**
     * SM4加密数据，ECB模式，密文以base64形式返回
     * @param input_data 待加密数据
     * @param key 密钥
     * @return 密文
     */
    public static String encrypt_ecb_base64(byte[] input_data, byte[] key) {
        Pointer p = CLibrary.INSTANCE.encrypt_ecb_base64(input_data, input_data.length, key, key.length);
        String result = p.getString(0);
        CLibrary.INSTANCE.free_char_array(p);
        return result;
    }

    /**
     * SM4加密数据，ECB模式，密文以16进制字符串形式返回
     * @param input_data 待加密数据
     * @param key 密钥
     * @return 密文
     */
    public static String encrypt_ecb_hex(byte[] input_data, byte[] key) {
        Pointer p = CLibrary.INSTANCE.encrypt_ecb_hex(input_data, input_data.length, key, key.length);
        String result = p.getString(0);
        CLibrary.INSTANCE.free_char_array(p);
        return result;
    }

    /**
     * SM4加密数据，ECB模式，加密到本地文件
     * @param input_file 待加密文件
     * @param output_file 加密输出文件
     * @param key 密钥
     */
    public static void encrypt_ecb_to_file(String input_file, String output_file, byte[] key) {
        CLibrary.INSTANCE.encrypt_ecb_to_file(input_file, output_file, key, key.length);
    }

    /**
     * SM4解密数据，ECB模式
     * @param input_data 待解密数据
     * @param key 密钥
     * @return 原文
     */
    public static byte[] decrypt_ecb(byte[] input_data, byte[] key) {
        Pointer output_data_len = new Memory(4);
        Pointer p = CLibrary.INSTANCE.decrypt_ecb(input_data, input_data.length, key, key.length, output_data_len);
        byte[] dec = p.getByteArray(0, output_data_len.getInt(0));
        CLibrary.INSTANCE.free_byte_array(p, output_data_len.getInt(0));
        return dec;
    }

    /**
     * SM4解密数据，ECB模式，密文通过base64形式传入
     * @param input_data 密文，base64格式
     * @param key 密钥
     * @return 原文
     */
    public static byte[] decrypt_ecb_base64(String input_data, byte[] key) {
        Pointer output_data_len = new Memory(4);
        Pointer p = CLibrary.INSTANCE.decrypt_ecb_base64(input_data, key, key.length, output_data_len);
        byte[] dec = p.getByteArray(0, output_data_len.getInt(0));
        CLibrary.INSTANCE.free_byte_array(p, output_data_len.getInt(0));
        return dec;
    }

    /**
     * SM4解密数据，ECB模式，密文通过16进制字符串形式传入
     * @param input_data 密文，16进制字符串形式
     * @param key 密钥
     * @return 原文
     */
    public static byte[] decrypt_ecb_hex(String input_data, byte[] key) {
        Pointer output_data_len = new Memory(4);
        Pointer p = CLibrary.INSTANCE.decrypt_ecb_hex(input_data, key, key.length, output_data_len);
        byte[] dec = p.getByteArray(0, output_data_len.getInt(0));
        CLibrary.INSTANCE.free_byte_array(p, output_data_len.getInt(0));
        return dec;
    }

    /**
     * SM4从文件解密，ECB模式
     * @param input_file 待解密文件
     * @param output_file 原文件输出
     * @param key 密钥
     */
    public static void decrypt_ecb_from_file(String input_file, String output_file, byte[] key) {
        CLibrary.INSTANCE.decrypt_ecb_from_file(input_file, output_file, key, key.length);
    }

    /**
     * SM4加密数据，CBC模式
     * @param input_data 待加密数据
     * @param key 密钥
     * @param iv 初始化向量
     * @return 密文
     */
    public static byte[] encrypt_cbc(byte[] input_data, byte[] key, byte[] iv) {
        Pointer output_data_len = new Memory(4);
        Pointer p = CLibrary.INSTANCE.encrypt_cbc(input_data, input_data.length, key, key.length, iv, iv.length, output_data_len);
        byte[] enc = p.getByteArray(0, output_data_len.getInt(0));
        CLibrary.INSTANCE.free_byte_array(p, output_data_len.getInt(0));
        return enc;
    }

    /**
     * SM4加密数据，CBC模式，密文以base64格式输出
     * @param input_data 待加密数据
     * @param key 密钥
     * @param iv 初始化向量
     * @return 密文
     */
    public static String encrypt_cbc_base64(byte[] input_data, byte[] key, byte[] iv) {
        Pointer p = CLibrary.INSTANCE.encrypt_cbc_base64(input_data, input_data.length, key, key.length, iv, iv.length);
        String result = p.getString(0);
        CLibrary.INSTANCE.free_char_array(p);
        return result;
    }

    /**
     * SM4加密数据，密文以16进制字符串形式输出
     * @param input_data 待加密数据
     * @param key 密钥
     * @param iv 初始化向量
     * @return 密文
     */
    public static String encrypt_cbc_hex(byte[] input_data, byte[] key, byte[] iv) {
        Pointer p = CLibrary.INSTANCE.encrypt_cbc_hex(input_data, input_data.length, key, key.length, iv, iv.length);
        String result = p.getString(0);
        CLibrary.INSTANCE.free_char_array(p);
        return result;
    }

    /**
     * SM4加密文件，CBC模式
     * @param input_file 待加密文件
     * @param output_file 解密文件输出
     * @param key 密钥
     * @param iv 初始化向量
     */
    public static void encrypt_cbc_to_file(String input_file, String output_file, byte[] key, byte[] iv) {
        CLibrary.INSTANCE.encrypt_cbc_to_file(input_file, output_file, key, key.length, iv, iv.length);
    }

    /**
     * SM4解密数据，CBC模式
     * @param input_data 待解密数据
     * @param key 密钥
     * @param iv 初始化向量
     * @return 原文
     */
    public static byte[] decrypt_cbc(byte[] input_data, byte[] key, byte[] iv) {
        Pointer output_data_len = new Memory(4);
        Pointer p = CLibrary.INSTANCE.decrypt_cbc(input_data, input_data.length, key, key.length, iv, iv.length, output_data_len);
        byte[] dec = p.getByteArray(0, output_data_len.getInt(0));
        CLibrary.INSTANCE.free_byte_array(p, output_data_len.getInt(0));
        return dec;
    }

    /**
     * SM4解密数据，密文以base64形式传入
     * @param input_data 密文
     * @param key 密钥
     * @param iv 初始化向量
     * @return 原文
     */
    public static byte[] decrypt_cbc_base64(String input_data, byte[] key, byte[] iv) {
        Pointer output_data_len = new Memory(4);
        Pointer p = CLibrary.INSTANCE.decrypt_cbc_base64(input_data, key, key.length, iv, iv.length, output_data_len);
        byte[] dec = p.getByteArray(0, output_data_len.getInt(0));
        CLibrary.INSTANCE.free_byte_array(p, output_data_len.getInt(0));
        return dec;
    }

    /**
     * SM4解密，CBC模式，密文以16进制字符串形式传入
     * @param input_data 待解密数据
     * @param key 密钥
     * @param iv 初始化向量
     * @return 原文
     */
    public static byte[] decrypt_cbc_hex(String input_data, byte[] key, byte[] iv) {
        Pointer output_data_len = new Memory(4);
        Pointer p = CLibrary.INSTANCE.decrypt_cbc_hex(input_data, key, key.length, iv, iv.length, output_data_len);
        byte[] dec = p.getByteArray(0, output_data_len.getInt(0));
        CLibrary.INSTANCE.free_byte_array(p, output_data_len.getInt(0));
        return dec;
    }

    /**
     * SM4解密文件，CBC模式
     * @param input_file 待解密文件
     * @param output_file 解密文件输出
     * @param key 密钥
     * @param iv 初始化向量
     */
    public static void decrypt_cbc_from_file(String input_file, String output_file, byte[] key, byte[] iv) {
        CLibrary.INSTANCE.decrypt_cbc_from_file(input_file, output_file, key, key.length, iv, iv.length);
    }
}
