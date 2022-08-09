package com.zaguiini.RNPureJwt;

import android.util.Base64;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.WritableMap;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Date;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.impl.DefaultClaims;

public class RNPureJwtModule extends ReactContextBaseJavaModule {

    public RNPureJwtModule(ReactApplicationContext reactContext) {
        super(reactContext);
    }

    @Override
    public String getName() {
    return "RNPureJwt";
  }

    private String toBase64(String plainString) {
        return Base64.encodeToString(plainString.getBytes(Charset.forName("UTF-8")), Base64.DEFAULT);
    }

    @ReactMethod
    public void sign(ReadableMap claims, String secret, ReadableMap options, Promise callback) {
        String algorithm = options.hasKey("alg") ? options.getString("alg") : "HS256";
        JwtBuilder constructedToken = Jwts.builder()
                .signWith(SignatureAlgorithm.forName(algorithm), this.toBase64(secret))
                .setHeaderParam("alg", algorithm)
                .setHeaderParam("typ", "JWT");

        Set<Map.Entry<String, Object>> entries = claims.toHashMap().entrySet();

        for (Object entry: entries) {
            Map.Entry item = (Map.Entry) entry;

            String key = (String) item.getKey();
            Object value = item.getValue();

            Double valueAsDouble;

            switch (key) {
                case "alg":
                    break;

                case "exp":
                    valueAsDouble = (double) value;
                    constructedToken.setExpiration(new Date(valueAsDouble.longValue()));
                    break;

                case "iat":
                    valueAsDouble = (double) value;
                    constructedToken.setIssuedAt(new Date(valueAsDouble.longValue()));
                    break;

                case "nbf":
                    valueAsDouble = (double) value;
                    constructedToken.setNotBefore(new Date(valueAsDouble.longValue()));
                    break;

                case "aud":
                    constructedToken.setAudience(value.toString());
                    break;

                case "iss":
                    constructedToken.setIssuer(value.toString());
                    break;

                case "sub":
                    constructedToken.setSubject(value.toString());
                    break;

                case "jti":
                    constructedToken.setId(value.toString());
                    break;

                default:
                    constructedToken.claim(key, value);
            }
        }

        callback.resolve(constructedToken.compact());
    }
}
