package edu.security.saesbackend.pojo;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class Result {
    Integer code;
    String msg;
    Object data;
    public static Result success(Object data){
        return new Result(1,"Success",data);
    };
    public static Result error(String errorMsg){
        return new Result(0,errorMsg,null);
    }

}
