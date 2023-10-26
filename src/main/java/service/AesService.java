package service;

import edu.security.saesbackend.pojo.Decryption;
import edu.security.saesbackend.pojo.Encryption;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.*;
@Service
@Slf4j
public class AesService {
    Encryption encryption=new Encryption();
    Decryption decryption=new Decryption();
    public String key1;
    public String key2;
    public String plainText;
    public String cypherText;

    public void setKey1(String key1) {
        this.key1 = key1;
    }

    public void setCypherText(String cypherText) {
        this.cypherText = cypherText;
    }

    public void setEncryption(Encryption encryption) {
        this.encryption = encryption;
    }

    public void setKey2(String key2) {
        this.key2 = key2;
    }

    public void setPlainText(String plainText) {
        this.plainText = plainText;
    }

    public int[] DoubleAESEncrypt(String plainText){
        AesService aesService=new AesService();
        aesService.setKey1(this.key1);
        int[] midText=aesService.SAESEncrypt(plainText);
        aesService.setKey1(this.key2);
        int[] finalAns=aesService.SAESEncrypt(BinaryToString(midText));
        return finalAns;
    }
    public int[] TrippleAESEncrypt(String plainText){
        AesService aesService= new AesService();
        aesService.setKey1(this.key1);
        int[] midText=aesService.SAESEncrypt(plainText);
        aesService.setKey1(this.key2);
        midText=aesService.SAESDecrypy(BinaryToString(midText));
        aesService.setKey1(this.key1);
        int[] finalAns=aesService.SAESEncrypt(BinaryToString(midText));
        return finalAns;
    }
    public int[] DoubleAESDecrypt(String cypherText){
        AesService aesService=new AesService();
        aesService.setKey1(this.key2);
        int[] midText=aesService.SAESDecrypy(cypherText);
        aesService.setKey1(this.key1);
        int[] finalAns=aesService.SAESDecrypy(BinaryToString(midText));

        return finalAns;
    }
    public int[] TrippleAESDecrypt(String cypherText){
        this.setCypherText(cypherText);
        encryption.setKey0(this.key1.substring(0,8));
        encryption.setKey1(this.key1.substring(8,16));

        decryption.setKey0(this.key2.substring(0,8));
        decryption.setKey1(this.key2.substring(8,16));

        int[] midText1=decryption.decrypt(this.cypherText);
        String midTextString1=BinaryToString(midText1);

        int[] midText2=encryption.encrypt(midTextString1);
        String midTextString2=BinaryToString(midText2);

        return encryption.encrypt(midTextString2);
    }
    public int[] SAESEncrypt(String plainText){
        this.setPlainText(plainText);
        encryption.setKey0(this.key1.substring(0,8));
        encryption.setKey1(this.key1.substring(8,16));
        return encryption.encrypt(this.plainText);
    }
    public int[] SAESDecrypy(String cypherText){
        this.setCypherText(cypherText);
        decryption.setKey0(this.key1.substring(0,8));
        decryption.setKey1(this.key1.substring(8,16));
        return decryption.decrypt(this.cypherText);
    }
    public static String BinaryToString(int[] binaryArray) {
        StringBuilder sb = new StringBuilder(binaryArray.length);
        for (int bit : binaryArray) {
            sb.append(bit);
        }
        return sb.toString();
    }
    public static int[] StringtoBinary(String s){
        int num=0;
        for(char c:s.toCharArray()){
            num=num*2+c-'0';
        }
        return DecimalToBinary(num);
    }
    public static List<String> WordsToKeys(String words) {
        List<String> binaryList = new ArrayList<>();

        // Iterate through each character in the input text
        for (char c : words.toCharArray()) {
            // Convert the character to its binary representation with leading zeros
            String binaryString = Integer.toBinaryString(c);
            while (binaryString.length() < 16) {
                binaryString = "0" + binaryString;
            }
            binaryList.add(binaryString);
        }
        return binaryList;
    }
    public static int[] DecimalToBinary(int decimalValue) {
        int[] binaryArray = new int[16];
        for (int i = 15; i >= 0; i--) {
            binaryArray[i] = decimalValue % 2;
            decimalValue /= 2;
        }
        return binaryArray;
    }
    public static Set<String> Attack(String plainText,String cypherText,String plainText2,String cypherText2){
        int n = (int) Math.pow(2, 16); // 计算2的16次方
        List<String>midText=new ArrayList<>();
        Set<String> possibleKeys=new HashSet<>();
        for (int i = 0; i < n; i++) {
            int[] key1 = DecimalToBinary(i);
            AesService aesService = new AesService();
            aesService.setKey1(BinaryToString(key1));
            int[] tmp=aesService.SAESEncrypt(plainText);
            midText.add(i,BinaryToString(tmp));
        }
        for (int i = 0; i < n; i++) {
            int[] key1 = DecimalToBinary(i);
            AesService aesService = new AesService();
            aesService.setKey1(BinaryToString(key1));
            int[] tmp=aesService.SAESDecrypy(cypherText);
            if(midText.contains(BinaryToString(tmp))){
                int j=midText.indexOf(BinaryToString(tmp));
                int[] key0=DecimalToBinary(j);
                AesService aesServiceNew=new AesService();
                aesServiceNew.setKey1(BinaryToString(key0));
                aesServiceNew.setKey2(BinaryToString(key1));
                int[] res=aesServiceNew.DoubleAESEncrypt(plainText2);
                if(cypherText2.equals(BinaryToString(res))){
                    StringBuilder ans=new StringBuilder();
                    ans.append(BinaryToString(key0));
                    ans.append(BinaryToString(key1));
                    possibleKeys.add(ans.toString());
                }
            }
        }
        return possibleKeys;
    }
    public static Set<String> MidAttack(List<String> plainTexts,List<String> cypherTexts){
        Set<String> ans=new HashSet<>();
        while(plainTexts.isEmpty()==false){
            String plaintext1= plainTexts.remove(0);
            String cypherText1=cypherTexts.remove(0);
            StringBuilder plaintext2=new StringBuilder();
            StringBuilder cypherText2=new StringBuilder();
            if(plainTexts.isEmpty()){
                plaintext2.append(plaintext1);
                cypherText2.append(cypherText1);
            }else{
                plaintext2.append(plainTexts.remove(0));
                cypherText2.append(cypherTexts.remove(0));
            }
            if(ans.isEmpty()==true){
                ans.addAll(Attack(plaintext1,cypherText1,plaintext2.toString(),cypherText2.toString()));
            }else{
                ans.retainAll(Attack(plaintext1,cypherText1,plaintext2.toString(),cypherText2.toString()));
            }
            if(ans.isEmpty() || ans.size()==1){
                return ans;
            }
        }
        return ans;
    }

}