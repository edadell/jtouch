package com.river_tiger.jtouch.util;

import java.util.Hashtable;

/*
 * helper Class for extracting the directives of a Digest Challenge
 * see RFC 2617 chapter 3.2.1
 * 
 * This class will not be instantiated, we call its static method
 */
public class DigestChallenge {

  //private Hashtable<String, String[]> h;

  /*
   * returns an Hashtable with all the extracted names/values
   *
   * challenge is the "digest-challenge" as explained in the RFC 2617 3.2.1
   */
  public static Hashtable extractDirectives(String challenge, boolean debug) {

    Hashtable<String, String> h = new Hashtable<String, String>();

    byte[] credz = challenge.getBytes();
    StringBuffer sbnam = new StringBuffer();
    StringBuffer sbval = new StringBuffer();

    // h contains all credentials receveived or "" when not specified
    h.put("realm", "");
    h.put("domain", "");  // won't be used (should be stored for client purpose)
    h.put("nonce", "");
    h.put("opaque", "");
    h.put("stale", ""); // won't be used (should be checked if value is TRUE and retry, ignore any other case)
    h.put("algorithm", "");
    h.put("qop-options", "");
    h.put("auth-param", "");  // RFC2617 says it is RFU, then must be ignored

    int j = 0;
    int AEFstate = 0;
    boolean blnError = false;

    // parse the credentials
    byte car = 0;
    while( (j < credz.length) && !blnError) {
      car = credz[j];

      /*
       * The parsing automaton states (AEFstate) are explained below.
       *
       * Although the RFC says the challenge parameter values are all quoted-strings, 
       *   we see from experiments it is not always true (Apache 2.4.33 algorithm value for example)
       *
       *   0 : adding characters to a parameter name, until we meet the '=' char
       *   1 : '=' char has been detected, we will wait for " or any other valid char (in this case, jump to state 5)
       *   2 : '"' char has been detected, this means a parameter value will follow, adding characters to parameter value
       *   3 : '"' closing char has been detected, parameter value is finished
       *   4 : ',' char means we will start another parameter, return to state 0
       *   5 : jumped from state 1 when a parameter value is not enclosed by " characters 
       *   6 : ',' like in state 4, parameter value reading is finished, go back to state 0 
       *
       */
      switch(car) {
        case 32:  // ' '
          switch(AEFstate) {
            case 0:
              blnError = true;
              break;

            case 1:
              // shouldn't happen, but ignore this white space
              break;

            case 2:
              sbval.append((char)car);
              break;

            case 3:
              blnError = true;
              break;

            case 4:
              // expected white space, ignore
              break;

            case 5:
              sbval.append((char)car);
              break;

            case 6:
              AEFstate = 0; // end of process, seeking for the next name/value
              break;
          }

          break;

        case 34:  // '"'
          switch(AEFstate) {
            case 0:
              blnError = true;
              break;

            case 1:
              AEFstate++;
              break;

            case 2:
              // okay we found name + value, we store them in the H
              h.put(sbnam.toString(), sbval.toString());
              if(debug)
                System.err.println(sbnam.toString() + ":" + sbval.toString());
              sbnam = new StringBuffer();
              AEFstate++;
              break;

            case 3:
              blnError = true;
              break;

            case 4:
              blnError = true;
              break;

            case 5:
              blnError = true;
              break;

            case 6:
              blnError = true;
              break;
          }

          break;

        case 44:  // ','
          switch(AEFstate) {
            case 0:
              blnError = true;
              break;

            case 1:
              blnError = true;
              break;

            case 2:
              sbval.append((char)car);
              break;

            case 3:
              AEFstate++;
              break;

            case 4:
              blnError = true;
              break;

            case 5:
              // okay we found name + value, we store them in the H
              h.put(sbnam.toString(), sbval.toString());
              if(debug)
                System.err.println(sbnam.toString() + ":" + sbval.toString());
              sbnam = new StringBuffer();
              AEFstate++;
              break;

            case 6:
              // shouldn't happen, but ignore this redundant , char 
              break;
          }

          break;

        case 61:  // '='
          switch(AEFstate) {
            case 0:
              sbval = new StringBuffer();
              AEFstate++;
              break;

            case 1:
              blnError = true;
              break;

            case 2:
              sbval.append((char)car);
              break;

            case 3:
              blnError = true;
              break;

            case 4:
              blnError = true;
              break;

            case 5:
              blnError = true;
              break;

            case 6:
              blnError = true;
              break;
          }

          break;

        default:
          switch(AEFstate) {
            case 0:
              sbnam.append((char)car);
              break;

            case 1:
              //-> TO DO
              //sbnam.append((char)car);
              sbval.append((char)car);
              AEFstate = 5;
              break;

            case 2:
              sbval.append((char)car);
              break;

            case 3:
              blnError = true;
              break;

            case 4:
              AEFstate = 0; // end of process, seeking for the next name/value
              sbnam.append((char)car);
              break;

            case 5:
              sbval.append((char)car);
              break;

            case 6:
              AEFstate = 0; // end of process, seeking for the next name/value
              sbnam.append((char)car);
              break;
            }

            break;
      }

      j++;
    }
    if(blnError) {
      System.err.println("Error parsing character " + car + " at index " + j);
      return new Hashtable<String, String>();
    }
    else
      return h;
  }

}

