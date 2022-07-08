package cn.starlight.hashlib;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class SHA256 {

    // 以下所有长度都以bit数量而非byte数量为准，须知1byte = 8bits，遇到代码中与注释“长度”不符时，请自行换算

    // 初始8个32bit的hash值，作为第一个block的初始8个word进行后续计算
    private static final long[] init_hash_values = {
            0x6a09e667L, 0xbb67ae85L, 0x3c6ef372L, 0xa54ff53aL, 0x510e527fL, 0x9b05688cL, 0x1f83d9abL, 0x5be0cd19L
    };

    // 64个hash常量，参与对尾端word的加和运算
    private static final long[] const_hash_values = {
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };

    private final static long OVER = 0xFFFFFFFFL;  // 等效于余除2^32，保证任何运算结果不得超过2^32

    /**
     * 连接两个byte数组，用于输入原始数据的补位
     * @param first 靠前的数组
     * @param second 靠后的数组
     * @return 连接好的数组，结果为[first, second]
     */
    private static byte[] concat(byte[] first, byte[] second) {
        byte[] result = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, result, first.length, second.length);

        return result;
    }

    /**
     * 将补好位的数组依照每32个bit为一个word的形式进行划分
     * @param arr 补位后的byte数组
     * @return 划分好的数组
     */
    private static int[] reSplit(byte[] arr){
        int byte_len = arr.length;
        int[] result = new int[byte_len / 4];

        for(int i = 0; i < byte_len; i++){
            result[(i / 4)] += ((arr[i] & 0xff) << (24 - 8 * (i % 4)));
        }

        return result;
    }

    /**
     * 为原始消息按SHA-256的标准进行补位
     * SHA-256要求现将消息补位至长度模除512后与448同余，最后补上64bit的长度信息后，使得消息长度恰好为512的整倍数
     * 须知，即使原始消息已满足与448同余，也必须补足512bit的补位数据后再进行长度信息附加
     * 因为SHA-256标准要求至少在原始消息后补充一个1，因而会产生上述问题
     * @param raw_msg 输入的原始消息
     * @return 补位后的消息
     */
    private static byte[] filling(byte[] raw_msg){
        byte[] filling_arr;

        int msg_len = raw_msg.length;
        final int surplus_length = msg_len % 64;

        if(surplus_length < 56){
            filling_arr = new byte[64 - surplus_length];
        }
        else {
            filling_arr = new byte[128 - surplus_length];
        }

        filling_arr[0] = -128;

        msg_len *= 8;

        filling_arr[filling_arr.length - 2] = (byte) ((msg_len >> 8) & 255);
        filling_arr[filling_arr.length - 1] = (byte) (msg_len & 255);

        return concat(raw_msg, filling_arr);
    }

    /**
     * 安全的循环右移方法
     * 确保右移后，有效数据长度依然为32bit
     * 之所以不直接使用int类型，是因为Java对数据溢出有限制，一旦发生数据溢出会报错
     * 为避免这种报错，以下所有方法传入值和返回值都将为long类型
     * @param data 待循环右移的数据
     * @param count 循环右移的次数
     * @return 循环右移后的结果
     */
    private static long rightRotation(long data, long count){
        return (((data & OVER) >> count) | (data & OVER) << (32 - count));
    }

    /**
     * SHA-256标准中Ch函数的实现
     */
    private static long Ch(long x, long y, long z){
        return ((x & y) ^ (~x & z)) & OVER;
    }

    /**
     * SHA-256标准中Maj函数的实现
     */
    private static long Maj(long x, long y, long z){
        return ((x & y) ^ (x & z) ^ (y & z)) & OVER;
    }

    /**
     * SHA-256标准中Σ0函数的实现
     */
    private static long Sigma0(long x){
        return (rightRotation(x, 2) ^ rightRotation(x, 13) ^ rightRotation(x, 22)) & OVER;
    }

    /**
     * SHA-256标准中Σ1函数的实现
     */
    private static long Sigma1(long x){
        return (rightRotation(x, 6) ^ rightRotation(x, 11) ^ rightRotation(x, 25)) & OVER;
    }

    /**
     * SHA-256标准中σ0函数的实现
     */
    private static long sigma0(long x){
        return (rightRotation(x, 7) ^ rightRotation(x, 18) ^ (x & OVER) >>> 3) & OVER;
    }

    /**
     * SHA-256标准中σ1函数的实现
     */
    private static long sigma1(long x){
        return (rightRotation(x, 17) ^ rightRotation(x, 19) ^ ((x & OVER) >>> 10)) & OVER;
    }

    /**
     * 将循环结束后得到的hash结果以16进制字符串的形式输出
     * @param arr 计算得到的hash数组
     * @return 转换得到的16进制字符串
     */
    private static String getHash(long[] arr) {
        StringBuilder result = new StringBuilder();

        for (long l : arr) {
            String hash = Long.toHexString(l);
            if (hash.length() > 8) {
                result.append(hash.substring(hash.length() - 8));
            } else {
                int count0 = 8 - hash.length();
                result.append("0".repeat(count0));
                result.append(hash);
            }
        }

        return result.toString();
    }

    /**
     * 将传入的二进制数组依照SHA-256标准进行hash处理
     * @param data 传入的二进制数组
     * @return SHA-256结果，以全小写字母的16进制形式输出
     */
    private static String calc(byte[] data){
        int[] raw_data_arr = reSplit(filling(data));

        // 缓存每个block的处理结果，以作为下一个block的初始hash值参与运算
        long[] hash_cache = init_hash_values.clone();  // 初始化hash缓存区，该缓存区用于缓存每个block的运算中间结果
        long[] result_arr = init_hash_values.clone();  // 初始化运算列表，使循环开始时，以初始的8个hash值为起始
        long[] w_arr = new long[64];  // 申请一块区域，缓存运算得到的Wt结果

        long t1, t2;  // 缓存尾word的处理中间结果

        int block_num = raw_data_arr.length / 16;

        for(int i = 0; i < block_num; i++) {

            for (int j = 0; j < 64; j++){
                if (j < 16) {
                    w_arr[j] = raw_data_arr[i * 16 + j];
                } else {
                    w_arr[j] = (((((sigma1(w_arr[j - 2]) + w_arr[j - 7]) & OVER) + sigma0(w_arr[j - 15])) & OVER) + w_arr[j - 16]) & OVER;
                }
            }

            for (int j = 0; j < 64; j++) {

                t1 = ((((((result_arr[7] + Sigma1(result_arr[4])) & OVER) + Ch(result_arr[4], result_arr[5], result_arr[6]) & OVER) + const_hash_values[j]) & OVER) + w_arr[j]) & OVER;
                t2 = (Sigma0(result_arr[0]) + Maj(result_arr[0], result_arr[1], result_arr[2])) & OVER;

                result_arr[7] = result_arr[6];
                result_arr[6] = result_arr[5];
                result_arr[5] = result_arr[4];
                result_arr[4] = (result_arr[3] + t1) & OVER;
                result_arr[3] = result_arr[2];
                result_arr[2] = result_arr[1];
                result_arr[1] = result_arr[0];

                result_arr[0] = (t1 + t2) & OVER;
            }

            for (int j = 0; j < 8; j++) {
                result_arr[j] = (result_arr[j] + hash_cache[j]) & OVER;
            }

            hash_cache = result_arr.clone();
        }

        return getHash(result_arr);
    }

    /**
     * 计算传入字符串的SHA-256值
     * @param data 传入的字符串
     * @return 传入字符串的SHA-256结果，以全小写字母的16进制形式输出
     */
    public static String getStringHash(String data){
        return calc(data.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * 计算传入字符串的SHA-256值
     * @param data 传入的字符串
     * @param code 字符串的编码
     * @return 传入字符串的SHA-256结果，以全小写字母的16进制形式输出
     */
    public static String getStringHash(String data, Charset code){
        return calc(data.getBytes(code));
    }

    /**
     * 计算传入二进制数据的SHA-256值
     * @param data 传入的二进制数据
     * @return 传入二进制数据的SHA-256结果，以全小写字母的16进制形式输出
     */
    public static String getBinaryHash(byte[] data){
        return calc(data);
    }

}
