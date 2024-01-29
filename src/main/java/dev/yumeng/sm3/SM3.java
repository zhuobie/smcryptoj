package dev.yumeng.sm3;

import com.sun.jna.Library;
import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;

interface CLibrary extends Library {
    CLibrary INSTANCE = (CLibrary) Native.load("smcrypto", CLibrary.class);
    Pointer sm3_hash(byte[] msg_bytes, int len);
    Pointer sm3_hash_string(String msg_string);
    void free_char_array(Pointer ptr);
}

/**
 * SM3消息摘要算法
 */
public class SM3 {
    /**
     * SM3消息摘要算法
     * @param msg_bytes 输入数据，以字节数组表示
     * @return SM3消息摘要结果，以64位16进制字符串表示
     */
    public static String sm3_hash(byte[] msg_bytes) {
        Pointer p = CLibrary.INSTANCE.sm3_hash(msg_bytes, msg_bytes.length);
        String hash = p.getString(0);
        CLibrary.INSTANCE.free_char_array(p);
        return hash;
    }

    /**
     * SM3消息摘要算法，但是传入字符串
     * @param msg_string 传入的字符串
     * @return SM3消息摘要结果
     */
    public static String sm3_hash_string(String msg_string) {
        Pointer p = CLibrary.INSTANCE.sm3_hash_string(msg_string);
        String hash = p.getString(0);
        CLibrary.INSTANCE.free_char_array(p);
        return hash;
    }
}
