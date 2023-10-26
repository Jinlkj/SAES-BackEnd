package edu.security.saesbackend.controller;

import edu.security.saesbackend.pojo.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import service.AesService;

import java.util.*;

@Slf4j
@RestController
public class SAESController {
    @Autowired
    Encryption encryption;
    @Autowired
    Decryption decryption;
    @PostMapping("/SAESEncrypt")
    public Result Encrypt(@RequestBody RequestData data){
        log.info("处理数据{},操作{},密钥是{}",data.getPlainText(),data.getOperation(),data.getKey1());
        long starttime=System.currentTimeMillis();
        AesService aesService=new AesService();
        aesService.setKey1(data.getKey1());
        String res=AesService.BinaryToString(aesService.SAESEncrypt(data.getPlainText()));
        long endtime=System.currentTimeMillis();
        long time=starttime-endtime;
        ResponseData responseData=new ResponseData(data.getPlainText(), data.getKey1(), data.getKey2(),null,null,null, res,time);
        return Result.success(responseData);
    }
    @PostMapping("/SAESDecrypt")
    public Result Decrypt(@RequestBody RequestData data){
        log.info("处理数据{},操作{},密钥是{}",data.getPlainText(),data.getOperation(),data.getKey1());
        long starttime=System.currentTimeMillis();
        AesService aesService=new AesService();
        aesService.setKey1(data.getKey1());
        String res=AesService.BinaryToString(aesService.SAESDecrypy(data.getCypherText()));
        long endtime=System.currentTimeMillis();
        long time=starttime-endtime;
        ResponseData responseData=new ResponseData(res, data.getKey1(), data.getKey2(), null,null,null,data.getCypherText(),time);
        return Result.success(responseData);
    }
    @PostMapping("/DoubleSAESEncrypt")
    public Result DoubleEncrypt(@RequestBody RequestData data){
        log.info("处理数据{},操作{},密钥是{},{}",data.getPlainText(),data.getOperation(),data.getKey1(),data.getKey2());
        long starttime=System.currentTimeMillis();
        AesService aesService=new AesService();
        aesService.setKey1(data.getKey1());
        aesService.setKey2(data.getKey2());
        String res=AesService.BinaryToString(aesService.DoubleAESEncrypt(data.getPlainText()));
        long endtime=System.currentTimeMillis();
        long time=starttime-endtime;
        ResponseData responseData=new ResponseData(data.getPlainText(), data.getKey1(), data.getKey2(),null ,null,null,res,time);
        return Result.success(responseData);
    }
    @PostMapping("/TrippleSAESEncrypt")
    public Result TrippleEncrypt(@RequestBody RequestData data){
        log.info("处理数据{},操作{},密钥是{},{}",data.getPlainText(),data.getOperation(),data.getKey1(),data.getKey2());
        long starttime=System.currentTimeMillis();
        AesService aesService=new AesService();
        aesService.setKey1(data.getKey1());
        aesService.setKey2(data.getKey2());
        String res=AesService.BinaryToString(aesService.TrippleAESEncrypt(data.getPlainText()));
        long endtime=System.currentTimeMillis();
        long time=starttime-endtime;
        ResponseData responseData=new ResponseData(data.getPlainText(), data.getKey1(), data.getKey2(),null,null,null, res,time);
        return Result.success(responseData);
    }
    @PostMapping("/Attack")
    public Result Attack(@RequestBody RequestData data){
        log.info("Atacking!开始攻击");
        long starttime=System.currentTimeMillis();
        List<String> plainTexts =data.getPlainTexts();
        List<String> cypherTexts=data.getCypherTexts();
        Set<String> ans=new HashSet<>();
        ans=AesService.MidAttack(plainTexts,cypherTexts);
        long endtime=System.currentTimeMillis();
        long time=endtime-starttime;
        if(ans.isEmpty()){
            log.info("finish error");
            return Result.error("无法找到密钥");
        }else{
            List<List<String>> res=new ArrayList<>();
            for(String s:ans){
                List<String> midres=new ArrayList<>();
                String key1=s.substring(0,16);
                String key2=s.substring(16,32);
                midres.add(key1);
                midres.add(key2);
                res.add(midres);
            }
            ResponseData responseData=new ResponseData(null,null,null,res,null,null,null,time);
            log.info("finish找到密钥对，结束");
            return Result.success(responseData);
        }
    }
    @PostMapping("/EncryptWords")
    public Result EncryptWords(@RequestBody RequestData data){
        long starttime=System.currentTimeMillis();
        AesService aesService=new AesService();
        aesService.setKey1(data.getKey1());
        List<String> keys=AesService.WordsToKeys(data.getPlainText());
        List<String> res=new ArrayList<>();
        for(String s:keys){
            log.info("{}",s);
            res.add(AesService.BinaryToString(aesService.SAESEncrypt(s)));
        }
        long endtime=System.currentTimeMillis();
        long time=starttime-endtime;
        ResponseData responseData=new ResponseData(data.getPlainText(),data.getKey1(),data.getKey2(),null,null,res,null,time);
        return Result.success(responseData);
    }
    @PostMapping("/DecryptWords")
    public Result DecryptWords(@RequestBody RequestData data){
        long starttime=System.currentTimeMillis();
        AesService aesService=new AesService();
        aesService.setKey1(data.getKey1());
        List<String> keys=data.getCypherTexts();
        StringBuilder res=new StringBuilder();
        for(String s:keys){
            res.append((char) Integer.parseInt(AesService.BinaryToString(aesService.SAESDecrypy(s)),2));
        }
        long endtime=System.currentTimeMillis();
        long time=starttime-endtime;
        ResponseData responseData=new ResponseData(res.toString(),data.getKey1(),data.getKey2(),null,null,null,null,time);
        return Result.success(responseData);
    }
    @PostMapping("/EncryptWordsCBC")
    public Result EncryptWordsCBC(@RequestBody RequestData data){
        long starttime=System.currentTimeMillis();
        AesService aesService=new AesService();
        aesService.setKey1(data.getKey1());
        List<String> keys=AesService.WordsToKeys(data.getPlainText());
        List<String> res=new ArrayList<>();
        String init=data.getInitVector();
        for(String s:keys){
            s=AesService.BinaryToString(Encryption.XOR(AesService.StringtoBinary(s),AesService.StringtoBinary(init)));
            init=AesService.BinaryToString(aesService.SAESEncrypt(s));
            res.add(init);
        }
        long endtime=System.currentTimeMillis();
        long time=starttime-endtime;
        ResponseData responseData=new ResponseData(data.getPlainText(),data.getKey1(),data.getKey2(),null,null,res,null,time);
        return Result.success(responseData);
    }
    @PostMapping("/DecryptWordsCBC")
    public Result DecryptWordsCBC(@RequestBody RequestData data){
        long starttime=System.currentTimeMillis();
        AesService aesService=new AesService();
        aesService.setKey1(data.getKey1());
        List<String> keys=data.getCypherTexts();
        StringBuilder res=new StringBuilder();
        String init=data.getInitVector();
        for(String s:keys){
            int[] midRes= aesService.SAESDecrypy(s);
            int[] midInit =AesService.StringtoBinary(init);
            int[] midXor=Encryption.XOR(midInit,midRes);
            int finalAns=Encryption.binaryToDecimal(midXor);
            res.append((char) finalAns);
            init=s;
        }
        long endtime=System.currentTimeMillis();
        long time=starttime-endtime;
        ResponseData responseData=new ResponseData(res.toString(),data.getKey1(),data.getKey2(),null,null,null,null,time);
        return Result.success(responseData);
    }
}
