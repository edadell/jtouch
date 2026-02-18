package com.river_tiger.jtouch.util;

import javax.crypto.Cipher;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.regex.*;

/*
 * helper Class for managing runtime dependencies
 */
public class RuntimeUtil {

  static final String likeV9 = "^\\d\\+(\\d+).*";
  static final String likeV10 = "^\\d\\d\\.\\d\\.(\\d+).*";

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
   * In case we aren't able to parse correctly, throw an Exception
   *
   * @since 1.0.6
   */
  public final static int getMinorVersion() throws NumberFormatException {

    String version = System.getProperty("java.runtime.version");
    String minorVersion = "0" ;

    /*
     * older versions :
     *  all start by "1." and the minor version
     *  and the minor version is between "_" and "-"
     */
    if(version.startsWith("1.") && version.contains("_") && version.contains("-")) {
      int delimiter1 = version.indexOf("_");
      int delimiter2 = version.indexOf("-");
      if(delimiter2>delimiter1)
        minorVersion = version.substring(delimiter1 + 1, delimiter2);
    }
    /*
     * newer versions : use Pattern matching
     */
    else {
      // 10+ versions
      Pattern pat = Pattern.compile(likeV10);
      Matcher mat = pat.matcher(version);
      if(mat.matches()) {
        minorVersion = mat.group(1);
      }

      // version 9
      pat = Pattern.compile(likeV9);
      mat = pat.matcher(version);
      if(mat.matches()) {
        minorVersion = mat.group(1);
      }
    }

    // DEBUG System.out.println("'" + minorVersion + "'");
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

  /*
   * returns a boolean indicating if the runtime is limited
   * value of TRUE means it IS limited and the unlimited jurisdiction files are not installed
   */
  public final static boolean supportsIBMJSSE2v7() {
    boolean rezult = false;

    Provider [] providerList = Security.getProviders();
    for (Provider provider : providerList) {
      if( "IBMJSSE2".equals(provider.getName()) && "1.7".equals(Double.toString(provider.getVersion())) )
        rezult = true;
    }

    return rezult;
  }

} // end class

