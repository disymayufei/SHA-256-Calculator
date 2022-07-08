package cn.starlight.hashlib;

public class Main {
    public static void main(String[] args) {

        /*
         * 调用本库的方法如下：
         * 复制SHA256.java文件进入你的项目，而后可使用以下api：
         * cn.starlight.hashlib.SHA256.getStringHash(String str): 计算字符串str的SHA-256值，编码为UTF-8
         * cn.starlight.hashlib.SHA256.getStringHash(String str, Charset code): 以code编码字符串str后，计算其SHA-256值、
         * cn.starlight.hashlib.SHA256.getBinaryHash(byte[] data): 计算二进制数据data的SHA-256值
         */

        String author = "Author by Disy!";
        System.out.printf("\"%s\"的SHA-256结果是：%s%n", author, SHA256.getStringHash(author));
    }
}
