package edu.security.saesbackend.pojo;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class RequestData {
    String plainText;
    String cypherText;
    List plainTexts;
    List cypherTexts;
    String Key1;
    String key2;
    String operation;
    String initVector;
}
