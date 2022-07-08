import cn.starlight.hashlib.SHA256;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class TestCases {
    public static void main(String[] args) {
        System.out.println("======================================================================");
        System.out.println("[WARN] 你正在运行test cases，你也可以在这里补充更多test cases以进行测试!");
        System.out.println("[WARN] 所有标准数据来源于Python的hashlib库的计算结果!");
        System.out.println("======================================================================");

        String x = "Hello World!";
        String x_sha256 = SHA256.getStringHash(x);
        String x_sha256_std = "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069";
        System.out.printf("\"%s\"的SHA-256结果是：%s%n", x, x_sha256);
        System.out.printf("与标准计算结果%s%n", x_sha256_std.equals(x_sha256) ? "一致" : "不一致");

        System.out.println("======================================================================");

        String y = "今天又是一个好天气，好天气通常伴随着好心情，正是在这种好心情的驱使下，我背起了我的小行囊，踏上了去往郊外的春游之路！";
        String y_sha256 = SHA256.getStringHash(y);
        String y_sha256_std = "79df7ae3235028ce51e6b38fa20c285357419073a8e73eb83c3ea147b1da272e";
        System.out.printf("\"%s\"的SHA-256结果是：%s%n", y, y_sha256);
        System.out.printf("与标准计算结果%s%n", y_sha256_std.equals(y_sha256) ? "一致" : "不一致");

        System.out.println("======================================================================");

        String z = "This is an apple. I like apples! Apples are good for ourselves!";
        String z_sha256 = SHA256.getStringHash(z);
        String z_sha256_std = "a2fde1ea70a84ea66f4c4b97242b578844db12d5cc2ff8795dbe3981c979b0be";
        System.out.printf("\"%s\"的SHA-256结果是：%s%n", z, z_sha256);
        System.out.printf("与标准计算结果%s%n", z_sha256_std.equals(z_sha256) ? "一致" : "不一致");

        System.out.println("======================================================================");

        String utf16_case = "本插件作者: Disy920 in StarLight";
        String utf16_case_sha256 = SHA256.getStringHash(utf16_case, StandardCharsets.UTF_16BE);
        String utf16_case_sha256_std = "a8f50fa3cc33d82f0b887d512ea407e2926d8853f33ee2a7f3f678320124e21c";
        System.out.printf("\"%s\"(UTF-16 big-endian编码)的SHA-256结果是：%s%n", utf16_case, utf16_case_sha256);
        System.out.printf("与标准计算结果%s%n", utf16_case_sha256_std.equals(utf16_case_sha256) ? "一致" : "不一致");

        System.out.println("======================================================================");

        byte[] bin_case = new byte[]{0x0a, 0x0c, 0x00, 0x09, 0x02, 0x00};
        String bin_sha256 = SHA256.getBinaryHash(bin_case);
        String bin_sha256_std = "5e876ad05e6050202f4a07725f1d5e71c00a7b2dd87ab62dfee36eb1e9275762";
        System.out.printf("\"%s\"(二进制数据)的SHA-256结果是：%s%n", Arrays.toString(bin_case), bin_sha256);
        System.out.printf("与标准计算结果%s%n", bin_sha256_std.equals(bin_sha256) ? "一致" : "不一致");
    }
}
