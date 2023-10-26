package edu.security.saesbackend.pojo;

import lombok.extern.slf4j.Slf4j;
import service.AesService;

@Slf4j
public class SAES {
    public static void main(String[] args) {
        int[] key1=new int[]{1,0,1,0,0,0,1,1,1,0,1,0,1,1,1,1};
        int[] key2=new int[]{1,0,1,0,0,0,1,1,1,0,1,0,1,1,1,0};
        String info="1010000010100000";

        log.info("DOUBLE_EN");
        log.info("密钥1是{}",key1);
        log.info("密钥2是{}",key2);
//        AesService aesService=new AesService();
//        aesService.setKey1(AesService.BinaryToString(key1));
//        aesService.setKey2(AesService.BinaryToString(key2));
//        int[] ans =aesService.DoubleAESEncrypt(info);
//        log.info("直接加密结果{}",ans);
        AesService aesService1=new AesService();
        aesService1.setKey1(AesService.BinaryToString(key1));
        int[] mid=aesService1.SAESEncrypt(info);
        log.info("中间加密结果{}",mid);
        AesService aesService2=new AesService();
        aesService2.setKey1(AesService.BinaryToString(key2));
        int[] finalAns =aesService2.SAESEncrypt(AesService.BinaryToString(mid));
        log.info("最后加密结果{}",finalAns);

    }
}
