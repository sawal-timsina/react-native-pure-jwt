package com.zaguiini.RNPureJwt;

import android.os.Build;
import android.util.Base64;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;

import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableMap;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Map;
import java.util.Set;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class RNPureJwtModule extends ReactContextBaseJavaModule {

  public RNPureJwtModule(ReactApplicationContext reactContext) {
    super(reactContext);
  }

  @NonNull
  @Override
  public String getName() {
    return "RNPureJwt";
  }

  @RequiresApi(api = Build.VERSION_CODES.KITKAT)
  private String toBase64(String plainString) {
    return Base64.encodeToString(plainString.getBytes(StandardCharsets.UTF_8), Base64.DEFAULT);
  }

  @RequiresApi(api = Build.VERSION_CODES.KITKAT)
  @ReactMethod
  public void sign(ReadableMap claims, String secret, ReadableMap options, Promise callback) {
    String algorithm = options.hasKey("alg") ? options.getString("alg") : "HS256";
    JwtBuilder constructedToken = Jwts.builder()
      .signWith(SignatureAlgorithm.forName(algorithm), this.toBase64(secret))
      .setHeaderParam("alg", algorithm)
      .setHeaderParam("typ", "JWT");

    Set<Map.Entry<String, Object>> entries = claims.toHashMap().entrySet();

    for (Object entry : entries) {
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
        case "id":
          constructedToken.claim(key, (int) value);
          break;

        default:
          constructedToken.claim(key, value);
      }
    }

    callback.resolve(constructedToken.compact());
  }
}
