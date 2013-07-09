package com.river_tiger.jtouch.util;

import java.util.Hashtable;
import java.util.Enumeration;

/*
 * helper Class for managing an hashtable of : String->String[]
 * when a key is first initialised : put(key, "")
 * after this, "" is authorised in values
 */
public class StringHashtable extends Hashtable {

  private Hashtable<String, String[]> h;

  /* constructor */
  public StringHashtable() {
    h = new Hashtable<String, String[]>();
  }

  /* overwrite Hashtable methods that we need */

  public void clear() {
    h.clear();
  }


  public Enumeration keys() {
    return h.keys();
  }

  // putting a key/val means adding a val to the array belonging to the right key
  public void put(String key, String val) {

    // dealing with a new key
    if(!h.containsKey(key)) {
      if(!val.equals(""))
        h.put(key, new String[] {val});
      else  // initialising the array
        h.put(key, new String[0]);
    }

    // key is well-known, add the value to at the last position of a bigger array
    else {
      String[] hold = (String[])h.get(key);
      String[] hnew = new String[hold.length + 1];
      java.lang.System.arraycopy(hold, 0, hnew, 0, hold.length);
      hnew[hold.length] = val;
      h.put(key, hnew);
    }

  }

  // looking for a val means looking if this exact array belongs to a key
  public boolean containsValue(String[] strz) {
    boolean rez = false;

    for (Enumeration eK = keys() ; eK.hasMoreElements() ;) {
      String str = eK.nextElement().toString();
      String[] vals = (String[])(get(str));
      if(strz.length == vals.length) {
        rez = true;
        for(int i=0; i<vals.length; i++)
          if(!strz[i].equals(vals[i]))
            rez = false;
      }
      if(rez == true)
        return true;
    }

    return false;
  }

  public String[] get(String key) {
    return((String[])h.get(key));
  }

  public int size() {
    return h.size();
  }

  public String toString() {
    String rez = new String();
    return h.toString();
  }

  // TO DO maybe : clone contains

}

