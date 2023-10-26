package edu.security.saesbackend.pojo;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ResponseData {
    String plainText;
    String key1;
    String key2;
    List<List<String>> possibleKeys;
    List<String> plainTexts;
    List<String> cypherTexts;
    String cypherText;
    long time;
}
