package com.river_tiger.jtouch.util;

import javax.crypto.Cipher;
import java.security.NoSuchAlgorithmException;

/*
 * helper Class for managing runtime dependencies
 */
public class RuntimeUtil {

  /*
   * returns the runtime Java version
   */
  public final static int getVersion() {
    String version = System.getProperty("java.version");
    if(version.startsWith("1.")) {
      version = version.substring(2, 3);
    }
    else {
      int dot = version.indexOf(".");
      if(dot != -1) {
        version = version.substring(0, dot);
      }
    }
    return Integer.parseInt(version);
  }

  /*
   * returns the runtime Java minor version
   *
   * @since 1.0.6
   */
  public final static int getMinorVersion() {

    String version = System.getProperty("java.runtime.version");
    String minorVersion = "0" ;

    if(version.startsWith("1.") && version.contains("_") && version.contains("-")) {
      int delimiter1 = version.indexOf("_");
      int delimiter2 = version.indexOf("-");
      if(delimiter2>delimiter1)
        minorVersion = version.substring(delimiter1 + 1, delimiter2);
    }
    else {
      int delimiter1 = version.indexOf("+");
      if(delimiter1 != -1)
        minorVersion = version.substring(delimiter1 + 1);
    }
    return Integer.parseInt(minorVersion);
  }

  /*
   * returns a boolean indicating if the runtime is limited
   * value of TRUE means it IS limited and the unlimited jurisdiction files are not installed
   */
  public final static boolean restrictedCryptography() {
    try {
        return Cipher.getMaxAllowedKeyLength("AES/CBC/PKCS5Padding") < Integer.MAX_VALUE;
    } catch (final NoSuchAlgorithmException e) {
        throw new IllegalStateException("The transform \"AES/CBC/PKCS5Padding\" is not available (the availability of this algorithm is mandatory for Java SE implementations)", e);
    }
  }

} // end class

