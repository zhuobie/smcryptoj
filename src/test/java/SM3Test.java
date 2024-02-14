import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static dev.yumeng.sm3.SM3.*;

public class SM3Test {
    @Test
    public void sm3_hash_test() {
        byte[] msg_bytes = {97, 98, 99};
        String msg_bytes_hash = sm3_hash(msg_bytes);
        assertEquals(msg_bytes_hash, "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");
    }
}