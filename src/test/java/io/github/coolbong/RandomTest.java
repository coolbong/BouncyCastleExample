package io.github.coolbong;

import org.junit.Test;

import static io.github.coolbong.Util.toHex;
import static org.junit.Assert.assertNotEquals;

public class RandomTest {

    @Test
    public void random_test_001() {
        Random rnd = new Random();
        byte[] random1 = rnd.rand(8);
        byte[] random2 = rnd.rand(8);

        assertNotEquals(toHex(random1), toHex(random2));
    }
}
