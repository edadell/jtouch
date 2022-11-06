/*
    JTouch java web browser, running in GUI or command-line.
    It demonstrates the pluggability of JSSE and the low-level configuration of SSL handshakes.
    Copyright (C) under Modified BSD License
    Contact : nephylim@users.sourceforge.net

*/
import java.io.*;
import java.nio.charset.Charset;
import java.net.*;
import java.util.Hashtable;
import java.util.Enumeration;
import java.util.Vector;
import java.util.Timer;
import java.util.TimerTask;
import java.nio.ByteBuffer;
import java.util.regex.*;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Calendar;
import java.util.SimpleTimeZone;
import java.util.Locale;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.event.*;
import javax.swing.text.*;
import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeEvent;
import java.text.*;

import javax.naming.*;
import javax.naming.directory.*;

import com.sun.security.ntlm.*;
import com.river_tiger.jtouch.util.StringHashtable;
import com.river_tiger.jtouch.util.DigestChallenge;
import com.river_tiger.jtouch.util.RuntimeUtil;

public class JTouch extends JFrame {

  /*
   * stores all common parameters coming from GUI or command-line
   */
  private static Hashtable<String, Object> hFast = new Hashtable<String, Object>();

  /*
   * stores all parameters and objects related to the GUI
   * most of the values will be used to build the hFast table
   */
  private static Hashtable<String, Object> hGUI = new Hashtable<String, Object>();

  /*
   * Keep-Alive is a pain in the ass
   * 1st, being compliant to RFCs (by default : closing connections in 1.0, keeping alive in 1.1 ; unless specified by the Keep-Alive header in both cases)
   * 2nd, handling connection errors in Java (we never know that an opened connection was later closed, until we write on the socket again, or even read..)
   * 3rd, every change on the requested server (name or port), or on the used proxy (name or port) will terminate the keep-alive
   * 4th, many GUI-related changes will terminate the keep-alive (http->https, provider, SSL parameters,..)
   */

  /*
   * remember the last request (hostname+port+proxyname+proxyport)
   * any change will break the keep-alive if any (this can be improved for both proxies, and end-server)
   */
  private static String lastHost = "";

  /*
   * tracks the GUI activity. If any change is significant (http->https, SSL changes,..), we should break the keep-alive (if any)
   */
  private static Boolean reuseConn = false;

  /*
   * GUI constructor
   */
  public JTouch(String WindowTitle) {
    super(WindowTitle);

    /*
     * design the MENU
     *
     * File -> [Abort current job, Log settings, Quit]
     * Edit -> [Select PLAF]
     * Tools -> [SSL Server check-up, See last cert]
     * Advanced -> [Cookie support, Select SSL Provider, Truststore, SSL Random settings]
     * Help -> [About]
     *
     * any change to the menu must be carefully checked, particularly the show/hide for 'see last certificate'
     */
    JMenuBar theJMenuBar = new JMenuBar();

    /* File */
    JMenu menua = new JMenu("File");
    menua.setMnemonic(KeyEvent.VK_F);
    //mymenu.getAccessibleContext().setAccessibleDescription("The only menu in this program that has menu items");
    JMenuItem oItem1 = new JMenuItem("Abort current job", KeyEvent.VK_A);
    oItem1.addActionListener(new swgAbort(this));
    menua.add(oItem1);
    JMenuItem oItem2 = new JMenuItem("Log settings", KeyEvent.VK_L);
    oItem2.addActionListener(new swgLogSettings(this));
    menua.add(oItem2);
    JMenuItem oItem3 = new JMenuItem("Exit", KeyEvent.VK_E);
    oItem3.addActionListener(new swgQuitter(this));
    menua.add(oItem3);
    theJMenuBar.add(menua);

    /* Edit */
    JMenu menub = new JMenu("Edit");
    menub.setMnemonic(KeyEvent.VK_E);
    JMenuItem oItem4 = new JMenuItem("Select PLAF", KeyEvent.VK_P);
    oItem4.addActionListener(new swgSelectPLAF(this));
    menub.add(oItem4);
    theJMenuBar.add(menub);

    /* Tools */
    JMenu menuc = new JMenu("Tools");
    menuc.setMnemonic(KeyEvent.VK_T);
    JMenuItem oItem5 = new JMenuItem("SSL Server check-up", KeyEvent.VK_S);
    oItem5.addActionListener(new swgSSLServerCheckUp(this));
    menuc.add(oItem5);
    JMenuItem oItem6 = new JMenuItem("See last cert", KeyEvent.VK_L);
    oItem6.addActionListener(new swgLastCertificate(this));
    oItem6.setEnabled(false);
    menuc.add(oItem6);
    theJMenuBar.add(menuc);

    /* Advanced */
    JMenu menud = new JMenu("Advanced");
    menud.setMnemonic(KeyEvent.VK_A);
    JMenuItem oItem7 = new JMenuItem("Cookie support", KeyEvent.VK_C);
    oItem7.addActionListener(new swgCookieSupport(this));
    menud.add(oItem7);
    JMenuItem oItem8 = new JMenuItem("Select SSL Provider", KeyEvent.VK_C);
    oItem8.addActionListener(new swgConfigSSL(this));
    menud.add(oItem8);
    JMenuItem oItem9 = new JMenuItem("Select Truststore", KeyEvent.VK_T);
    oItem9.addActionListener(new swgSSLTruststore(this));
    menud.add(oItem9);
    JMenuItem oItem11 = new JMenuItem("SSL Random settings", KeyEvent.VK_R);
    oItem11.addActionListener(new swgSSLRandom(this));
    menud.add(oItem11);
    theJMenuBar.add(menud);

    JMenu menue = new JMenu("Help");
    menue.setMnemonic(KeyEvent.VK_H);
    JMenuItem oItem10 = new JMenuItem("About", KeyEvent.VK_A);
    oItem10.addActionListener(new swgAbout(this));
    menue.add(oItem10);
    theJMenuBar.add(menue);
    setJMenuBar(theJMenuBar);
    /* end of menu */

    /* preferredSize to use later*/
    Dimension dimScroll1 = new Dimension(200, 200);
    Dimension dimInput1 = new Dimension(80, 20);

    /* * global panel and constraints * */
    JPanel pane = new JPanel();
    pane.setLayout(new GridBagLayout());
    GridBagConstraints c = new GridBagConstraints();
    c.fill = GridBagConstraints.HORIZONTAL;
    c.anchor = GridBagConstraints.FIRST_LINE_START;
    c.insets = new Insets(1, 1, 1, 1);

    /* * First-Line panel * */
    JPanel paneFL = new JPanel();
    paneFL.setLayout(new GridBagLayout());
    GridBagConstraints cFL = new GridBagConstraints();
    cFL.fill = GridBagConstraints.HORIZONTAL;
    cFL.insets = new Insets(1, 1, 1, 1);
    cFL.anchor = GridBagConstraints.LINE_END;
    cFL.weightx = 0;
    cFL.weighty = 0;

    JLabel flLMethod = new JLabel("Method");
    cFL.gridx = 0;
    cFL.gridy = 0;
    paneFL.add(flLMethod, cFL);

    String[] flSMethod = { "GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "CONNECT", "OPTIONS" };
    JComboBox flCMethod = new JComboBox(flSMethod);
    flCMethod.setSelectedIndex(0);
    flCMethod.setEditable(false);
    cFL.gridx = 1;
    cFL.gridy = 0;
    flCMethod.addActionListener(new swgMethod(this));
    paneFL.add(flCMethod, cFL);
    Hashtable<String, Object> ht = new Hashtable<String, Object>();
    ht.put("objectID", flCMethod);
    ht.put("value", (String)flCMethod.getSelectedItem());
    hGUI.put("guiMethod", ht);

    JLabel flLHost = new JLabel("Host");
    cFL.gridx = 2;
    cFL.gridy = 0;
    paneFL.add(flLHost, cFL);

    /*
     * we need some consistency between the free input boxes (host, port, path) and their init values
     * then we use one var _sConsistency in order to avoid mistakes
     */
    String _sConsistency = "sourceforge.net";

    String[] flSHost = { _sConsistency };
    JComboBox flCHost = new JComboBox(flSHost);
    flCHost.setSelectedIndex(0);
    flCHost.setEditable(true);
    cFL.gridx = 3;
    cFL.gridy = 0;
    // combobox is resizable
    cFL.weightx = 1;
    flCHost.addActionListener(new swgHost(this));

    //anti-resizing bug of JComboBox
    JPanel miniPanel2 = new JPanel(new BorderLayout());
    flCHost.setPreferredSize(new Dimension(205, 24));
    miniPanel2.add(flCHost, BorderLayout.CENTER);
    paneFL.add(miniPanel2, cFL);
    //paneFL.add(flCHost, cFL);

    ht = new Hashtable<String, Object>();
    ht.put("objectID", flCHost);
    ht.put("value", (String)flCHost.getSelectedItem());

    List<String> list = new ArrayList<String>();
    list.add(_sConsistency);
    ht.put("vals", list);
    hGUI.put("guiHost", ht);

    JLabel flLPort = new JLabel("Port");
    cFL.gridx = 4;
    cFL.gridy = 0;
    cFL.weightx = 0;
    paneFL.add(flLPort, cFL);

    _sConsistency = "80";

    String[] flSPort = { _sConsistency };
    JComboBox flCPort = new JComboBox(flSPort);
    flCPort.setSelectedIndex(0);
    flCPort.setEditable(true);
    cFL.gridx = 5;
    cFL.gridy = 0;
    flCPort.addActionListener(new swgPort(this));
    paneFL.add(flCPort, cFL);
    ht = new Hashtable<String, Object>();
    ht.put("objectID", flCPort);
    ht.put("value", (String)flCPort.getSelectedItem());
    list = new ArrayList<String>();
    list.add( _sConsistency );
    ht.put("vals", list);
    hGUI.put("guiPort", ht);

    JLabel flLVersion = new JLabel("Ver");
    cFL.gridx = 6;
    cFL.gridy = 0;
    paneFL.add(flLVersion, cFL);

    String[] flSVersion = { "1.0", "1.1" };
    JComboBox flCVersion = new JComboBox(flSVersion);
    flCVersion.setSelectedIndex(1);
    flCVersion.setEditable(false);
    cFL.gridx = 7;
    cFL.gridy = 0;
    flCVersion.addActionListener(new swgVersion(this));
    paneFL.add(flCVersion, cFL);
    ht = new Hashtable<String, Object>();
    ht.put("objectID", flCVersion);
    ht.put("value", "HTTP/".concat((String)flCVersion.getSelectedItem()) );
    hGUI.put("guiVersion", ht);

    JButton butGO = new JButton("GO");
    butGO.setVerticalTextPosition(AbstractButton.CENTER);
    butGO.setHorizontalTextPosition(AbstractButton.LEADING);
    butGO.addActionListener(new swgGo(this));
    cFL.gridx = 8;
    cFL.gridy = 0;
    paneFL.add(butGO, cFL);
    ht = new Hashtable<String, Object>();
    ht.put("objectID", butGO);
    ht.put("value", "");
    hGUI.put("guiGo", ht);

    JLabel flLPath = new JLabel("Path");
    cFL.gridx = 0;
    cFL.gridy = 1;
    paneFL.add(flLPath, cFL);

    _sConsistency = "/";

    String[] flSPath = { _sConsistency };
    JComboBox flCPath = new JComboBox(flSPath);
    flCPath.setSelectedIndex(0);
    flCPath.setEditable(true);
    cFL.gridx = 1;
    cFL.gridwidth = 7;
    cFL.gridy = 1;
    cFL.weightx = 1;
    flCPath.addActionListener(new swgPath(this));

    //anti-resizing bug of JComboBox
    JPanel miniPanel1 = new JPanel(new BorderLayout());
    flCPath.setPreferredSize(new Dimension(564, 24));
    miniPanel1.add(flCPath, BorderLayout.CENTER);
    paneFL.add(miniPanel1, cFL);
    //paneFL.add(flCPath, cFL);

    ht = new Hashtable<String, Object>();
    ht.put("objectID", flCPath);
    ht.put("value", (String)flCPath.getSelectedItem());
    list = new ArrayList<String>();
    list.add( _sConsistency );
    ht.put("vals", list);
    hGUI.put("guiPath", ht);

    /* * FirstLine border * */
    paneFL.setBorder(BorderFactory.createLineBorder(Color.black));

    /* * add paneFirstLine to global panel * */
    c.weightx = 0;
    c.weighty = 0;
    c.gridx = 0;
    c.gridy = 0;
    //c.anchor = GridBagConstraints.EAST;
    pane.add(paneFL, c);

    /* * authentication panel * */
    JPanel paneAuth = new JPanel();
    paneAuth.setLayout(new GridBagLayout());
    GridBagConstraints cAuth = new GridBagConstraints();
    cAuth.fill = GridBagConstraints.HORIZONTAL;
    cAuth.insets = new Insets(1, 1, 1, 1);
    cAuth.weightx = 0;
    cAuth.weighty = 0;
    cAuth.anchor = GridBagConstraints.LAST_LINE_END;

    JLabel autMethod = new JLabel("Method");
    cAuth.gridx = 0;
    cAuth.gridy = 0;
    paneAuth.add(autMethod, cAuth);

    String[] autSMethod = { "Anonymous", "Basic", "Digest", "NTLM" };
    //String[] autSMethod = { "Anonymous", "Basic", "Digest" };
    JComboBox autCMethod = new JComboBox(autSMethod);
    autCMethod.setSelectedIndex(0);
    autCMethod.setEditable(false);
    cAuth.gridx = 1;
    cAuth.gridy = 0;
    autCMethod.addActionListener(new swgAuthMethod(this));
    paneAuth.add(autCMethod, cAuth);
    ht = new Hashtable<String, Object>();
    ht.put("objectID", autCMethod);
    ht.put("value", (String)autCMethod.getSelectedItem());
    hGUI.put("guiAuthMethod", ht);

    JLabel autMeth = new JLabel("User");
    cAuth.gridx = 0;
    cAuth.gridy = 1;
    paneAuth.add(autMeth, cAuth);

    JTextField autUser = new JTextField("", 12);
    cAuth.gridx = 1;
    cAuth.gridy = 1;
    autUser.setEnabled(false);
    paneAuth.add(autUser, cAuth);
    ht = new Hashtable<String, Object>();
    ht.put("objectID", autUser);
    ht.put("value", (String)autUser.getText());
    hGUI.put("guiAuthUser", ht);

    JLabel autMet = new JLabel("Password");
    cAuth.gridx = 0;
    cAuth.gridy = 2;
    paneAuth.add(autMet, cAuth);

    JPasswordField autPassword = new JPasswordField("", 12);
    cAuth.gridx = 1;
    cAuth.gridy = 2;
    autPassword.setEnabled(false);
    paneAuth.add(autPassword, cAuth);
    ht = new Hashtable<String, Object>();
    ht.put("objectID", autPassword);
    ht.put("value", (String)autPassword.getText());
    hGUI.put("guiAuthPassword", ht);

    JLabel autDome = new JLabel("Domain");
    cAuth.gridx = 0;
    cAuth.gridy = 3;
    paneAuth.add(autDome, cAuth);

    JTextField autDom = new JTextField("", 12);
    cAuth.gridx = 1;
    cAuth.gridy = 3;
    autDom.setEnabled(false);
    paneAuth.add(autDom, cAuth);
    ht = new Hashtable<String, Object>();
    ht.put("objectID", autDom);
    ht.put("value", (String)autDom.getText());
    hGUI.put("guiAuthDomain", ht);

    /* * authentication border panel * */
    paneAuth.setBorder(
      BorderFactory.createCompoundBorder(
        BorderFactory.createCompoundBorder(
          BorderFactory.createTitledBorder("Authentication"),
          BorderFactory.createEmptyBorder(5, 5, 5, 5)),
        paneAuth.getBorder()));

    /* * connection panel * */
    JPanel paneConn = new JPanel();
    paneConn.setLayout(new GridBagLayout());
    GridBagConstraints cPan = new GridBagConstraints();
    cPan.fill = GridBagConstraints.HORIZONTAL;
    cPan.insets = new Insets(1, 1, 1, 1);
    cPan.weightx = 0;
    cPan.weighty = 0;

    JLabel panMethod = new JLabel("Connect");
    cPan.gridwidth = 1;
    cPan.gridx = 0;
    cPan.gridy = 0;
    paneConn.add(panMethod, cPan);

    /* TLS versions depends on Java Runtime version */
    String[] panSMethod = new String[0];
    switch(RuntimeUtil.getVersion()) {
      case 5:
      case 6:
      case 7: // early JSSE is not handling over TLS 1.0 
        panSMethod = new String[]{ "http", "SSL 3.0", "TLS 1.0" };
        break;

      case 8: // starting from 8u261, TLS 1.3 is handled by JSSE 8
        if(RuntimeUtil.getMinorVersion() < 261)
          panSMethod = new String[]{ "http", "SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2" };
        else
          panSMethod = new String[]{ "http", "SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3" };
        break;

      case 11: // see https://stackoverflow.com/a/73097062/7748072
      case 17:
      case 18:
        panSMethod = new String[]{ "http", "SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3" };
        break;

      default: // 9+ , not everyone is supporting TLS 1.3
        panSMethod = new String[]{ "http", "SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2" };
        break;
    }

    //String[] panSMethod = { "http", "SSL 3.0", "TLS 1.0"};
    JComboBox panCMethod = new JComboBox(panSMethod);
    panCMethod.setSelectedIndex(0);
    panCMethod.setEditable(false);
    cPan.gridx = 1;
    cPan.gridwidth = 2;
    cPan.gridy = 0;
    panCMethod.addActionListener(new swgConnConnect(this));
    paneConn.add(panCMethod, cPan);
    ht = new Hashtable<String, Object>();
    ht.put("objectID", panCMethod);
    ht.put("value", (String)panCMethod.getSelectedItem());
    hGUI.put("guiConnConnect", ht);

    JLabel panMetho = new JLabel("Cipher");
    cPan.weightx = 0;
    cPan.weighty = 0;
    cPan.gridwidth = 1;
    cPan.gridx = 0;
    cPan.gridy = 1;
    paneConn.add(panMetho, cPan);

    String[] panSCipher = { "" };
    JComboBox panCCipher = new JComboBox(panSCipher);
    panCCipher.setSelectedIndex(0);
    panCCipher.setEditable(true);
    cPan.weightx = 0;
    cPan.weighty = 0;
    cPan.gridx = 1;
    cPan.gridwidth = 2;
    cPan.gridy = 1;
    panCCipher.setEnabled(false);
    panCCipher.setActionCommand("guiConnCipher");
    panCCipher.addActionListener(new swgConnCipher(this));
    paneConn.add(panCCipher, cPan);
    ht = new Hashtable<String, Object>();
    ht.put("objectID", panCCipher);
    ht.put("value", (String)panCCipher.getSelectedItem());
    hGUI.put("guiConnCipher", ht);

    JLabel panMeth = new JLabel("Client cert");
    cPan.weightx = 0;
    cPan.weighty = 0;
    cPan.gridwidth = 1;
    cPan.gridx = 0;
    cPan.gridy = 2;
    //RFU paneConn.add(panMeth, cPan);

    JTextField panUser = new JTextField("", 12);
    cPan.weightx = 0;
    cPan.weighty = 0;
    cPan.gridx = 1;
    cPan.gridwidth = 2;
    cPan.gridy = 2;
    //RFU paneConn.add(panUser, cPan);

    /* * connection border panel * */
    paneConn.setBorder(
      BorderFactory.createCompoundBorder(
        BorderFactory.createCompoundBorder(
          BorderFactory.createTitledBorder("Connection"),
          BorderFactory.createEmptyBorder(5, 5, 5, 5)),
        paneConn.getBorder()));

    /* * proxy panel * */
    JPanel paneProxy = new JPanel();
    paneProxy.setLayout(new GridBagLayout());
    GridBagConstraints cProx = new GridBagConstraints();
    cProx.fill = GridBagConstraints.HORIZONTAL;
    cProx.insets = new Insets(1, 1, 1, 1);

    JCheckBox proxOnOff = new JCheckBox("use proxy");
    cProx.weightx = 0;
    cProx.weighty = 0;
    cProx.gridwidth = 2;
    cProx.gridx = 0;
    cProx.gridy = 0;
    proxOnOff.addActionListener(new swgProxOnOff(this));
    paneProxy.add(proxOnOff, cProx);
    ht = new Hashtable<String, Object>();
    ht.put("objectID", proxOnOff);
    ht.put("value", (Boolean)proxOnOff.isSelected());
    hGUI.put("guiProxOnOff", ht);

    JLabel proxCName = new JLabel("Proxyname");
    cProx.weightx = 0;
    cProx.weighty = 0;
    cProx.gridwidth = 1;
    cProx.gridx = 0;
    cProx.gridy = 1;
    paneProxy.add(proxCName, cProx);

    JTextField proxName = new JTextField("127.0.0.1", 12);
    proxName.setPreferredSize(dimInput1);
    proxName.setMinimumSize(dimInput1);
    cProx.gridx = 1;
    cProx.gridwidth = 1;
    cProx.gridy = 1;
    proxName.setEnabled(false);
    paneProxy.add(proxName, cProx);
    ht = new Hashtable<String, Object>();
    ht.put("objectID", proxName);
    ht.put("value", (String)proxName.getText());
    hGUI.put("guiProxyname", ht);

    JLabel proxCPort = new JLabel("Port");
    cProx.weightx = 0;
    cProx.weighty = 0;
    cProx.gridwidth = 1;
    cProx.gridx = 0;
    cProx.gridy = 2;
    paneProxy.add(proxCPort, cProx);

    JTextField proxPort = new JTextField("8080", 12);
    cProx.weightx = 0;
    cProx.weighty = 0;
    cProx.gridx = 1;
    cProx.gridwidth = 1;
    cProx.gridy = 2;
    proxPort.setEnabled(false);
    paneProxy.add(proxPort, cProx);
    ht = new Hashtable<String, Object>();
    ht.put("objectID", proxPort);
    ht.put("value", (String)proxPort.getText());
    hGUI.put("guiProxyport", ht);

    JLabel proxCUser = new JLabel("User");
    cProx.weightx = 0;
    cProx.weighty = 0;
    cProx.gridwidth = 1;
    cProx.gridx = 0;
    cProx.gridy = 3;
    paneProxy.add(proxCUser, cProx);

    //JTextField proxUser = new JTextField("firstname.lastname", 12);
    JTextField proxUser = new JTextField(12);
    cProx.weightx = 0;
    cProx.weighty = 0;
    cProx.gridx = 1;
    cProx.gridwidth = 1;
    cProx.gridy = 3;
    proxUser.setEnabled(false);
    paneProxy.add(proxUser, cProx);
    ht = new Hashtable<String, Object>();
    ht.put("objectID", proxUser);
    ht.put("value", (String)proxUser.getText());
    hGUI.put("guiProxyuser", ht);

    JLabel proxCPass = new JLabel("Password");
    cProx.weightx = 0;
    cProx.weighty = 0;
    cProx.gridwidth = 1;
    cProx.gridx = 0;
    cProx.gridy = 4;
    paneProxy.add(proxCPass, cProx);

    JPasswordField proxPass = new JPasswordField(6);
    cProx.weightx = 0;
    cProx.weighty = 0;
    cProx.gridx = 1;
    cProx.gridy = 4;
    proxPass.setEnabled(false);
    paneProxy.add(proxPass, cProx);
    ht = new Hashtable<String, Object>();
    ht.put("objectID", proxPass);
    ht.put("value", (String)proxPass.getText());
    hGUI.put("guiProxypass", ht);


    /* * proxy border panel * */
    paneProxy.setBorder(
      BorderFactory.createCompoundBorder(
        BorderFactory.createCompoundBorder(
          BorderFactory.createTitledBorder("Proxy"),
          BorderFactory.createEmptyBorder(5, 5, 5, 5)),
        paneProxy.getBorder()));

    JPanel paneInt = new JPanel();
    paneInt.setLayout(new GridBagLayout());
    GridBagConstraints cInt = new GridBagConstraints();
    cInt.fill = GridBagConstraints.BOTH;
    cInt.anchor = GridBagConstraints.FIRST_LINE_START;

    paneInt.setBorder(BorderFactory.createLineBorder(Color.black));

    cInt.weightx = 0;
    cInt.weighty = 0;
    cInt.gridx = 0;
    cInt.gridy = 0;
    paneInt.add(paneAuth, cInt);

    cInt.weightx = 0;
    cInt.weighty = 0;
    cInt.gridx = 1;
    cInt.gridy = 0;
    paneInt.add(paneConn, cInt);

    cInt.weightx = 0;
    cInt.weighty = 0;
    cInt.gridx = 2;
    cInt.gridy = 0;
    paneInt.add(paneProxy, cInt);


    c.weightx = 0.0;
    c.weighty = 0;
    c.gridx = 0;
    c.gridy = 1;
    pane.add(paneInt, c);

    /* * empty space under authentication & connection * */
    c.weightx = 0;
    c.weighty = 0;
    c.gridx = 0;
    c.gridy = 2;
    //pane.add(new JPanel(), c);


    /* * ADVANCED REQUEST * */
    JPanel adJPanel = new JPanel();
    adJPanel.setLayout(new GridBagLayout());
    GridBagConstraints d = new GridBagConstraints();
    d.fill = GridBagConstraints.HORIZONTAL;
    d.anchor = GridBagConstraints.FIRST_LINE_START;
    //d.fill = GridBagConstraints.BOTH;

    //  combo box `Advanced Request`
    String[] advStrings = { "Disabled", "Add Headers", "Add Body", "Add Headers & Body", "Raw Request" };
    JComboBox advList = new JComboBox(advStrings);
    advList.setSelectedIndex(0);
    advList.setActionCommand("guiAdvancedRequest");
    advList.addActionListener(new swgAdvList(this));
    advList.setPreferredSize(new Dimension(120, 24));
    d.insets = new Insets(1, 1, 1, 1);
    d.weightx = 0;
    d.weighty = 0;
    d.gridx = 0;
    d.gridy = 0;
    adJPanel.add(advList, d);
    ht = new Hashtable<String, Object>();
    ht.put("objectID", advList);
    ht.put("value", (String)advList.getSelectedItem());
    hGUI.put("guiAdvancedRequest", ht);

    // textarea `Advanced Request`
    JTextArea extArea = new JTextArea(
      "User-Agent: JTouch 1.0.5\r\n" +
      "Accept-Charset: utf-8\r\n" +
      "Accept-Encoding: gzip\r\n" +
      "Accept-Language: en-US\r\n" +
      "Cache-Control: no-cache\r\n" +
      "Pragma: no-cache"
    );
    extArea.setFont(new Font("Courier New", Font.ITALIC, 10));
    extArea.setLineWrap(true);
    extArea.setWrapStyleWord(true);
    extArea.setEnabled(false);
    JScrollPane areaScrollPane = new JScrollPane();
    areaScrollPane.setViewportView(extArea);
    areaScrollPane.setVerticalScrollBarPolicy(
      JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
    areaScrollPane.setPreferredSize(dimScroll1);
    areaScrollPane.setMinimumSize(dimScroll1);

    ht = new Hashtable<String, Object>();
    ht.put("objectID", extArea);
    ht.put("value", "");
    hGUI.put("guiAdvanced", ht);

    adJPanel.setBorder(
      BorderFactory.createCompoundBorder(
        BorderFactory.createCompoundBorder(
          BorderFactory.createTitledBorder("Advanced Request"),
          BorderFactory.createEmptyBorder(5, 5, 5, 5)),
        adJPanel.getBorder()));

    d.weightx = 1.0;
    d.gridx = 0;
    d.gridy = 1;
    //d.gridwidth = 2;
    adJPanel.add(areaScrollPane, d);

    c.gridx = 1;
    c.gridy = 0;
    c.weightx = 1.0;
    c.weighty = 0;
    // c.gridheight = number of lines in left part (1st-line + Authentication... + empty line to allow the resize)
    c.gridheight = 2;
    pane.add(adJPanel, c);

    /* * standard output * */
    JTextArea guiOut = new JTextArea("");
    guiOut.setFont(new Font("Courier New", Font.ITALIC, 12));
    guiOut.setLineWrap(true);
    guiOut.setWrapStyleWord(true);
    JScrollPane srollPane = new JScrollPane();
    srollPane.setViewportView(guiOut);
    // anti-resizing bug
    //System.out.println(" . " + srollPane.getPreferredSize() );
    srollPane.setPreferredSize( new Dimension(110, 512) );

    srollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
    //srollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
    //JScrollPane srollPane = new JScrollPane(guiOut, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);

    c.weightx = 1.0;
    c.weighty = 1.0;
    c.gridx = 0;
    c.gridwidth = 2;
    c.gridy = 2;
    //c.anchor = GridBagConstraints.CENTER;
    c.fill = GridBagConstraints.BOTH;
    pane.add(srollPane, c);
    //add(new JScrollPane(tp), BorderLayout.SOUTH);


    add(pane);
    //setContentPane(pane);

    /* * initialize some default parameters and store in hGUI * */
    hGUI.put("-follow", false);
    ht = new Hashtable<String, Object>();
    ht.put("value", "");
    hGUI.put("ciphers", ht);
    ht = new Hashtable<String, Object>();
    ht.put("value", "");
    hGUI.put("sslprotocols", ht);
    ht = new Hashtable<String, Object>();
    ht.put("value", "SunJSSE_SSLv2Hello");
    hGUI.put("provider", ht);
    ht = new Hashtable<String, Object>();
    ht.put("value", new TrustManager[0]);
    hGUI.put("trustmanager", ht);
    ht = new Hashtable<String, Object>();
    ht.put("value", true);

    hGUI.put("netstamps", true);
    hGUI.put("htmlstamps", true);
    hGUI.put("resolvedns", true);
    hGUI.put("raw", false);

    ht = new Hashtable<String, Object>();
    hGUI.put("cookiesupport", ht);

    hGUI.put("unsecurerandom", false);

    // build the 'out' object
    JTextAreaOutputStream taos = new JTextAreaOutputStream(guiOut, 2048);
    MultiOutputStream mps = new MultiOutputStream(new OutputStream[] {taos});
    //System.setOut(mps);

    // assign the 'out' to all outputs
    hGUI.put("mps", new MultiOutputStream[] {mps, mps, mps});

    // we need to save the mps object or it could be lost by the GUi changes
    hGUI.put("mps-save", mps);

    // default bistreamhandle
    hGUI.put("bsh", new BiStreamHandle());
  }

  /**
   * Create the GUI and show it.  For thread safety,
   * this method should be invoked from the
   * event-dispatching thread.
   */
  private static void createAndShowGUI() {
    //Make sure we have nice window decorations.
    JFrame.setDefaultLookAndFeelDecorated(true);

    //Create and set up the window.
    JFrame frame = new JTouch("JTouch");
    frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

    // default LAF supports decorations
    frame.setUndecorated(true);

    //Create and set up the content pane.
    //JComponent newContentPane = new JTouch();
    //newContentPane.setOpaque(true); //content panes must be opaque
    //frame.setContentPane(newContentPane);

    //Display the window.
    frame.pack();
    frame.setVisible(true);
    // RFU JAVA 1.6 : transparency
    //com.sun.awt.AWTUtilities.setWindowOpacity(frame, 0.90f);
  }

  public static void main(String[] args)    {

    final StringBuffer SBUsage = new StringBuffer(512);
    SBUsage.append("\n\nusage: java -jar JTouch.jar -method:<method> -uri:<uri> -version:<version> -hostname:<hostname> -port:<port>");
    SBUsage.append(" -connect:<http|https> [-header:<<name>:<value>>:..] [-o:<file>] [-orequest:<file>:..] [-oheader:<file>:..] [-obody:<file>:..] [-ciphers:ssl_cipher:..]");
    SBUsage.append("[-sslversion:protocol1:..] [-provider:provider] [-instance:instance] [-truststore:<jks_file>] [-proxyname:proxyname] [-proxyport:proxyport] [-proxyuser:username] [-proxypass:password]");
    SBUsage.append("[-user:user] [-password:<password>] [-cookiestore:<cookie-type>] [-requestbody:<hex_file>] [-viewcookies_v1:file] [-viewcookies_netscape:file]");
    SBUsage.append("[--follow] [--sslservercheckup] [--basic] [--digest] [--ntlm] [--netstamps] [--htmlstamps] [--resolvedns] [--lf2crlf] [--crlf2lf] [--raw] [--exportcert]");
    SBUsage.append("\n\nTry `java -jar JTouch.jar --help' for more information\n\n");
    //RFU [--ntlm]
    final String Usage = SBUsage.toString();

    final StringBuffer SBHelp = new StringBuffer(2048);
    SBHelp.append("\nJTouch is a java browser running both in Swing GUI or command-line.\n\n");
    SBHelp.append("To run JTouch in GUI mode, just type java -jar JTouch.\n\n");
    SBHelp.append("Running JTouch in command-line is a little more difficult but it allows you to embed it in scripts and make complex scenarios.\n");
    SBHelp.append("Such scenarios are for example login pages needing cookie persistence.\n");
    SBHelp.append("The detail of all possible parameters and their meaning is :\n\n");
    SBHelp.append("-method: (mandatory) GET | POST | HEAD | PUT | DELETE | TRACE | CONNECT | OPTIONS.\n");
    SBHelp.append("-uri: (mandatory) a URI as defined in RFC2616 (typically /).\n");
    SBHelp.append("-hostname: (mandatory) a host identified by a name server or IP address.\n");
    SBHelp.append("-version: (mandatory) HTTP/1.0 | HTTP/1.1. By default, version 1.1 keeps the connection alive. Using 1.0 with extra header 'Connection: Keep-Alive' is at your own risk.\n");
    SBHelp.append("-port: (mandatory) typically 80 or 443, any integer value is possible.\n");
    SBHelp.append("-connect: (mandatory) http | https.\n");
    SBHelp.append("-header:header-name:header-value. Allows adding headers, such as User-Agent, Cache-Control,..\n");
    SBHelp.append("-o: System.out|output files. You can choose several outputs using -o:output1:output2:..\n");
    SBHelp.append("-orequest: System.out|output files. Cannot be used with -o.\n");
    SBHelp.append("-oheader: System.out|output files. Cannot be used with -o.\n");
    SBHelp.append("-obody: System.out|output files. Cannot be used with -o.\n");
    SBHelp.append("-user: login requested by the web site. Use with --basic or --digest or --ntlm.\n");
    SBHelp.append("-password: password requested by the web site. Use with --basic or --digest or --ntlm.\n");
    SBHelp.append("-domain: NTLM domain requested by the web site. Use with --ntlm.\n");
    SBHelp.append("-ciphers: cipher1:cipher2:.. Defines a list of cipher suites. For the complete list of cipher suites available, see below\n");
    SBHelp.append("-sslversion: SSLv2 | SSLv3 | TLSv1. It is possible to set 2 or more protocols.\n");
    SBHelp.append("-provider: SunJSSE | IBMJSSE. SUN allows only SSLv3, TLSv1, SSLv2Hello:SSLv3, SSLv2Hello:TLSv1 version, and IBM allow SSLv2, SSLv3, TLSv1\n");
    SBHelp.append("-truststore: all | jks file. When not specified, the system will choose the default truststore file. Value 'all' will accept all certificates.\n");
    SBHelp.append("-proxyname: the proxy host identified by a name server or IP address.\n");
    SBHelp.append("-proxyport: the proxy port identified by a integer value. Usually 8080, 3128,..\n");
    SBHelp.append("-proxyuser: login of the user who will be authenticated by the proxy.\n");
    SBHelp.append("-proxypass: password of the user who will be authenticated by the proxy.\n");
    SBHelp.append("-cookiestore: netscape | v1. The cookies are stored in a file called cookies_netscape or cookies_v1.\n");
    SBHelp.append("-requestbody: adds a body to the request from a hexadecimal file. The corresponding headers must be set.\n");
    SBHelp.append("-viewcookies_v1: prints the cookies v1 stored in a file.\n\n\n");
    SBHelp.append("-viewcookies_netscape: prints the cookies in netscape format stored in a file.\n\n\n");
    SBHelp.append("Special parameters.\n\n");
    SBHelp.append("--follow: follows redirects (301, 302,..).\n");
    SBHelp.append("--sslservercheckup: checks all cipher suites for all ssl versions and providers against a web site.\n");
    SBHelp.append("--basic: permits Basic authentication. Needs user and password parameters. Cannot be used with --digest or --ntlm\n");
    SBHelp.append("--digest: permits Digest authentication. Needs user and password parameters. Cannot be used with --basic or --ntlm\n");
    SBHelp.append("--ntlm: permits NTLM authentication. Needs user and password and domain parameters. Cannot be used with --basic or --digest\n");
    SBHelp.append("--netstamps: prints the network time stamps for the connection (socket opening, 1st byte received,..).\n");
    SBHelp.append("--htmlstamps: prints the HTTP time stamps (send request, parse response headers, parse response body.\n");
    SBHelp.append("--resolvedns: prints the time needed to resolve the server name.\n");
    SBHelp.append("--lf2crlf: translates the LF character into CRLF in response body messages.\n");
    SBHelp.append("--crlf2lf: translates the CRLF characters into LF in response body messages.\n");
    SBHelp.append("--raw: prints the response message in RAW format, displaying the chunk-length values in chunked responses.\n");
    SBHelp.append("--exportcert: export the certificate to file webcert.pem, and all intermediary ACs to AC_number.pem.\n\n\n");
    SBHelp.append("--unsecurerandom: uses a fast and unsecure random for SSL instead of the default.\n\n\n");
    SBHelp.append("Examples.\n\n");
    SBHelp.append("The smaller request possible looks like this :\n");
    SBHelp.append("java -jar JTouch -method:GET -hostname:google.com -uri:/ -version:1.1.\n\n");
    SBHelp.append("\n");
    SBHelp.append("Supported Cipher Suites.\n\n");
    SBHelp.append("(SUN) SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA\n");
    SBHelp.append("(SUN) SSL_DH_anon_EXPORT_WITH_RC4_40_MD5\n");
    SBHelp.append("(SUN) SSL_DH_anon_WITH_3DES_EDE_CBC_SHA\n");
    SBHelp.append("(SUN) SSL_DH_anon_WITH_DES_CBC_SHA\n");
    SBHelp.append("(SUN) SSL_DH_anon_WITH_RC4_128_MD5\n");
    SBHelp.append("(SUN) SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA\n");
    SBHelp.append("(SUN) SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA\n");
    SBHelp.append("(SUN) SSL_DHE_DSS_WITH_DES_CBC_SHA\n");
    SBHelp.append("(SUN) SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA\n");
    SBHelp.append("(SUN) SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA\n");
    SBHelp.append("(SUN) SSL_DHE_RSA_WITH_DES_CBC_SHA\n");
    SBHelp.append("(SUN) SSL_RSA_EXPORT_WITH_DES40_CBC_SHA\n");
    SBHelp.append("(SUN) SSL_RSA_EXPORT_WITH_RC4_40_MD5\n");
    SBHelp.append("(SUN) SSL_RSA_WITH_3DES_EDE_CBC_SHA\n");
    SBHelp.append("(SUN) SSL_RSA_WITH_DES_CBC_SHA\n");
    SBHelp.append("(SUN) SSL_RSA_WITH_NULL_MD5\n");
    SBHelp.append("(SUN) SSL_RSA_WITH_NULL_SHA\n");
    SBHelp.append("(SUN) SSL_RSA_WITH_RC4_128_MD5\n");
    SBHelp.append("(SUN) SSL_RSA_WITH_RC4_128_SHA\n");
    SBHelp.append("(SUN) TLS_DH_anon_WITH_AES_128_CBC_SHA\n");
    SBHelp.append("(SUN) TLS_DH_anon_WITH_AES_256_CBC_SHA\n");
    SBHelp.append("(SUN) TLS_DHE_DSS_WITH_AES_128_CBC_SHA\n");
    SBHelp.append("(SUN) TLS_DHE_DSS_WITH_AES_256_CBC_SHA\n");
    SBHelp.append("(SUN) TLS_DHE_RSA_WITH_AES_128_CBC_SHA\n");
    SBHelp.append("(SUN) TLS_DHE_RSA_WITH_AES_256_CBC_SHA\n");
    SBHelp.append("(SUN) TLS_RSA_WITH_AES_128_CBC_SHA\n");
    SBHelp.append("(SUN) TLS_RSA_WITH_AES_256_CBC_SHA\n");
    SBHelp.append("(IBM) SSL_DH_anon_WITH_AES_128_CBC_SHA\n");
    SBHelp.append("(IBM) SSL_DH_anon_WITH_AES_256_CBC_SHA\n");
    SBHelp.append("(IBM) SSL_DHE_DSS_WITH_AES_128_CBC_SHA\n");
    SBHelp.append("(IBM) SSL_DHE_DSS_WITH_AES_256_CBC_SHA\n");
    SBHelp.append("(IBM) SSL_DHE_RSA_WITH_AES_128_CBC_SHA\n");
    SBHelp.append("(IBM) SSL_DHE_RSA_WITH_AES_256_CBC_SHA\n");
    SBHelp.append("(IBM) SSL_RSA_WITH_AES_128_CBC_SHA\n");
    SBHelp.append("(IBM) SSL_RSA_WITH_AES_256_CBC_SHA\n");
    SBHelp.append("(IBM) SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA\n");
    SBHelp.append("(IBM) SSL_DH_anon_EXPORT_WITH_RC4_40_MD5\n");
    SBHelp.append("(IBM) SSL_DH_anon_WITH_3DES_EDE_CBC_SHA\n");
    SBHelp.append("(IBM) SSL_DH_anon_WITH_DES_CBC_SHA\n");
    SBHelp.append("(IBM) SSL_DH_anon_WITH_RC4_128_MD5\n");
    SBHelp.append("(IBM) SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA\n");
    SBHelp.append("(IBM) SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA\n");
    SBHelp.append("(IBM) SSL_DHE_DSS_WITH_DES_CBC_SHA\n");
    SBHelp.append("(IBM) SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA\n");
    SBHelp.append("(IBM) SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA\n");
    SBHelp.append("(IBM) SSL_DHE_RSA_WITH_DES_CBC_SHA\n");
    SBHelp.append("(IBM) SSL_RSA_EXPORT_WITH_DES40_CBC_SHA\n");
    SBHelp.append("(IBM) SSL_RSA_EXPORT_WITH_RC4_40_MD5\n");
    SBHelp.append("(IBM) SSL_RSA_WITH_3DES_EDE_CBC_SHA\n");
    SBHelp.append("(IBM) SSL_RSA_WITH_DES_CBC_SHA\n");
    SBHelp.append("(IBM) SSL_RSA_WITH_NULL_MD5\n");
    SBHelp.append("(IBM) SSL_RSA_WITH_NULL_SHA\n");
    SBHelp.append("(IBM) SSL_RSA_WITH_RC4_128_MD5\n");
    SBHelp.append("(IBM) SSL_RSA_WITH_RC4_128_SHA\n");
    SBHelp.append("(IBM) SSL_DHE_DSS_WITH_RC4_128_SHA\n");
    SBHelp.append("(IBM) SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5\n");
    SBHelp.append("(IBM) SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA\n");
    SBHelp.append("(IBM) SSL_RSA_FIPS_WITH_DES_CBC_SHA\n");
    SBHelp.append("\n\n");
    SBHelp.append("Troubleshooting.\n\n");
    SBHelp.append("Please see the TROUBLESHOOTING file to know more about troubleshooting.\n\n\n");
    SBHelp.append("Version.\n\n1.0.5\n\n\n");
    SBHelp.append("Support.\n\n");
    SBHelp.append("All support will be given from the JTouch team. See the official website to ask for support : http://sourceforge.net/projects/JTouch.\n\n\n");
    SBHelp.append("Donations.\n\n");
    SBHelp.append("See the official website to learn more about the donation process.\n\n\n");
    SBHelp.append("License.\n\n");
    SBHelp.append("JTouch  Copyright (C) 2009-2018  Contact : nephylim@users.sourceforge.net\n");
    SBHelp.append("Copyright (C) under Modified BSD License <2009-2018>");
    SBHelp.append("\n\n");
    SBHelp.append("Credits.\n\n");
    SBHelp.append("Robert Harder : Base64 encoding/decoding, under Public Domain license. http://iharder.net/base64.\n");
    SBHelp.append("Emil Ivov : Digest algorithm, under Apache Software license. http://sip-communicator.org/.\n");
    final String Help = SBHelp.toString();

    // 0 - type d'utilisation : ligne de commande ou GUi ?
    if(args.length == 0) {
      //Schedule a job for the event-dispatching thread:
      //creating and showing this application's GUI.
      javax.swing.SwingUtilities.invokeLater(new Runnable() {
        public void run() {
          createAndShowGUI();
        }
      });
    }
    else {

      // 1- command line args processing

      /*
       * define arg types
       * type can be : "UniqueObligatoire"   <=> mandatory and appears once
       *               "UniqueOptionnel"     <=> optional and appears once
       *               "MultipleOptionnel"   <=> optional and appears several times
       *               "MultipleObligatoire" <=> mandatory and appears several times (not used yet)
       *               "directive"           <=> optional and called with a double-dash '--'
       */

      Hashtable<String, String> typargs = new Hashtable<String, String>();
      typargs.put("method", new String("UniqueObligatoire"));
      typargs.put("uri", new String("UniqueObligatoire"));
      typargs.put("version", new String("UniqueObligatoire"));
      typargs.put("port", new String("UniqueObligatoire"));
      typargs.put("hostname", new String("UniqueObligatoire"));
      typargs.put("connect", new String("UniqueObligatoire"));

      typargs.put("header", new String("MultipleOptionnel"));
      typargs.put("o", new String("MultipleOptionnel"));
      typargs.put("orequest", new String("MultipleOptionnel"));
      typargs.put("oheader", new String("MultipleOptionnel"));
      typargs.put("obody", new String("MultipleOptionnel"));
      typargs.put("ciphers", new String("UniqueOptionnel"));
      typargs.put("sslversion", new String("UniqueOptionnel"));
      typargs.put("provider", new String("UniqueOptionnel"));
      typargs.put("instance", new String("UniqueOptionnel"));
      typargs.put("proxyname", new String("UniqueOptionnel"));
      typargs.put("proxyport", new String("UniqueOptionnel"));
      typargs.put("user", new String("UniqueOptionnel"));
      typargs.put("password", new String("UniqueOptionnel"));
      typargs.put("domain", new String("UniqueOptionnel"));
      typargs.put("truststore", new String("UniqueOptionnel"));
      typargs.put("proxyuser", new String("UniqueOptionnel"));
      typargs.put("proxypass", new String("UniqueOptionnel"));
      typargs.put("-follow", new String("directive"));
      typargs.put("-auto", new String("directive"));
      typargs.put("-sslservercheckup", new String("directive"));
      typargs.put("-basic", new String("directive"));
      typargs.put("-digest", new String("directive"));
      typargs.put("-ntlm", new String("directive"));
      typargs.put("-netstamps", new String("directive"));
      typargs.put("-htmlstamps", new String("directive"));
      typargs.put("-resolvedns", new String("directive"));
      typargs.put("cookiestore", new String("UniqueOptionnel"));
      typargs.put("requestbody", new String("UniqueOptionnel"));
      typargs.put("viewcookies_v1", new String("UniqueOptionnel"));
      typargs.put("viewcookies_netscape", new String("UniqueOptionnel"));
      typargs.put("-lf2crlf", new String("directive"));
      typargs.put("-crlf2lf", new String("directive"));
      typargs.put("-raw", new String("directive"));
      typargs.put("-exportcert", new String("directive"));
      typargs.put("-help", new String("directive"));
      typargs.put("-unsecurerandom", new String("directive"));

      // définition des htable pour chaque type
      // on délègue la vérification exhaustive vis-à-vis de la RFC dans l'implémentation des objets, donc pas fait ici
      // TO DO : détail des UObl
      Hashtable<String, String> UObl = new Hashtable<String, String>();
      UObl.put("method", "");
      UObl.put("uri", "");
      UObl.put("version", "");
      UObl.put("port", "");
      UObl.put("hostname", "");
      UObl.put("connect", "");
      Hashtable<String, String> UOpt = new Hashtable<String, String>();
      UOpt.put("ciphers", "");
      UOpt.put("sslversion", "");
      UOpt.put("provider", "");
      UOpt.put("instance", "");
      UOpt.put("proxyname", "");
      UOpt.put("proxyport", "");
      UOpt.put("user", "");
      UOpt.put("password", "");
      UOpt.put("domain", "");
      UOpt.put("truststore", "");
      UOpt.put("proxyuser", "");
      UOpt.put("proxypass", "");
      UOpt.put("cookiestore", "");
      UOpt.put("requestbody", "");
      UOpt.put("viewcookies_v1", "");
      UOpt.put("viewcookies_netscape", "");

      Hashtable<String, Boolean> UDir = new Hashtable<String, Boolean>();
      UDir.put("-follow", false);
      UDir.put("-auto", false);
      UDir.put("-sslservercheckup", false);
      UDir.put("-basic", false);
      UDir.put("-digest", false);
      UDir.put("-ntlm", false);
      UDir.put("-netstamps", new Boolean(false));
      UDir.put("-htmlstamps", new Boolean(false));
      UDir.put("-resolvedns", new Boolean(false));
      UDir.put("-lf2crlf", false);
      UDir.put("-crlf2lf", false);
      UDir.put("-raw", false);
      UDir.put("-exportcert", false);
      UDir.put("-help", false);
      UDir.put("-unsecurerandom", false);
      // ne pas déclarer la directive -proxyauth

      StringHashtable MObl = new StringHashtable();
      // TO DO : détail des MObl

      StringHashtable MOpt = new StringHashtable();

      // récupération des paramètres en ligne de commande
      String strkey, strval, strtyp ;

      for(int i = 0; i < args.length; i++) {
        int iindex = args[i].indexOf(":");

        if(iindex > 0) {
          strkey = args[i].substring(1, iindex);
          strval = args[i].substring(iindex + 1);

          if(typargs.containsKey(strkey)) {
            strtyp = (String)typargs.get(strkey);

            // ajout du paramètre dans la bonne htable avec vérification de type
            if(strtyp.equals("UniqueObligatoire")) {
              // UniqueObligatoire : on vérifie que l'élément n'est pas déjà configuré
              if( ((String)UObl.get(strkey)).equals("") )
                UObl.put(strkey, strval);
              else
                throw new RuntimeException("too many parameters of this type : " + strkey);
            }

            if(strtyp.equals("UniqueOptionnel")) {
              // UniqueOptionnel : on vérifie que l'élément n'est pas déjà configuré
              if( ((String)UOpt.get(strkey)).equals("") )
                UOpt.put(strkey, strval);
              else
                throw new RuntimeException("too many parameters of this type : " + strkey);
            }

            if(strtyp.equals("MultipleObligatoire")) {
              // le traitement sur strval sera effectué plus tard
              MObl.put(strkey, strval);
            }

            if(strtyp.equals("MultipleOptionnel")) {
              // le traitement sur strval sera effectué plus tard
              MOpt.put(strkey, strval);
            }
          }
          else
            throw new RuntimeException("unexpected parameter : " + args[i] + " " + Usage);
        }
        else {
          // s'agit-il d'une directive du running et non pas d'un paramètre ?
          strkey = args[i].substring(1);

          if(typargs.containsKey(strkey)) {
            UDir.put(strkey, true);
          }
          else
            throw new RuntimeException("unexpected parameter : " + args[i] + " " + Usage);
        }

      } // fin for-loop

      // unusual command-line args : help, view cookie files,..
      if((Boolean)UDir.get("-help"))
        System.out.println(Help);
      else {
        String sview1 = (String)UOpt.get("viewcookies_v1");
        String sview2 = (String)UOpt.get("viewcookies_netscape");

        // view cookie files (v1, or netscape, or both)
        if( !(sview1 + sview2).equals("") )
          System.out.println( (new CookieWrapper(sview2, sview1)).toString() );

        // normal run : go on checking the parameters and run
        else {
          // compulsory parameters are all here ?
          if(UObl.containsValue(""))
            throw new RuntimeException("compulsory parameter is missing :\n" + UObl.toString() + Usage);

          if(MObl.containsValue(new String[0]))
            throw new RuntimeException("compulsory parameter is missing :\n" + MObl.toString()   + Usage);

          // build hFast from parameters

          Hashtable<String, Object> htmp = new Hashtable<String, Object>();
          hFast.put("guiMethod", (String)UObl.get("method"));
          hFast.put("guiPath", (String)UObl.get("uri"));
          hFast.put("guiVersion", (String)UObl.get("version"));
          hFast.put("guiHost", (String)UObl.get("hostname"));
          hFast.put("guiPort", (String)UObl.get("port"));
          hFast.put("guiConnConnect", (String)UObl.get("connect"));
          hFast.put("guiProxyname", (String)UOpt.get("proxyname"));
          hFast.put("guiProxyport", (String)UOpt.get("proxyport"));
          hFast.put("ciphers", (String)UOpt.get("ciphers"));
          hFast.put("sslprotocols", (String)UOpt.get("sslversion"));
          hFast.put("provider", (String)UOpt.get("provider"));
          hFast.put("instance", (String)UOpt.get("instance"));
          //hFast.put("user", (String)UOpt.get("user"));
          //hFast.put("password", (String)UOpt.get("password"));
          hFast.put("-follow", (Boolean)UDir.get("-follow"));
          hFast.put("-sslservercheckup", (Boolean)UDir.get("-sslservercheckup"));
          hFast.put("-digest", (Boolean)UDir.get("-digest"));
          hFast.put("-ntlm", (Boolean)UDir.get("-ntlm"));

          // only one convert is possible
          if( (Boolean)UDir.get("-lf2crlf") && (Boolean)UDir.get("-crlf2lf"))
            throw new RuntimeException("only one convert is possible among --lf2crlf and --crlf2lf :\n" + Usage);
          else {
            hFast.put("-lf2crlf", (Boolean)UDir.get("-lf2crlf"));
            hFast.put("-crlf2lf", (Boolean)UDir.get("-crlf2lf"));
          }

          /*
           * Basic/Digest/NTLM are exclusive and work very differently
           *   Basic sets the Authorization header now
           *   Digest will do it later with the Scenario
           *   NTLM will do it later with the Scenario
           */
          if( (Boolean)UDir.get("-basic") ) {
            if( (Boolean)UDir.get("-digest") || (Boolean)UDir.get("-ntlm") )
              throw new RuntimeException("only one authorization type is possible among --basic and --digest:\n" + Usage);
            else {
              int iofs = 0;
              String[] newh;

              if(MOpt.get("header") != null) {
                String[] sTmp = (String[])MOpt.get("header");
                newh = new String[sTmp.length + 1];

                for(String s : sTmp)
                  newh[iofs++] = s;
              }
              else
                newh = new String[1];

              newh[iofs] = "Authorization: " + RFC2617.toBasicCredentials((String)UOpt.get("user"), (String)UOpt.get("password"));
              hFast.put("headers", newh);
            }
          }
          else {
            if( (Boolean)UDir.get("-digest") ) {
              if( (Boolean)UDir.get("-ntlm") )
                throw new RuntimeException("only one authorization type is possible among --basic and --digest:\n" + Usage);
              else {
                // recopy user + password
                hFast.put("user", (String)UOpt.get("user"));
                hFast.put("password", (String)UOpt.get("password"));
              }
            }
            else {
              if( (Boolean)UDir.get("-ntlm") ) {
                // recopy user + password
                hFast.put("ntlmuser", (String)UOpt.get("user"));
                hFast.put("ntlmpassword", (String)UOpt.get("password"));
                hFast.put("ntlmdomain", (String)UOpt.get("domain"));
              }
            }

          }

          if(MOpt.get("header") != null)
            hFast.put("headers", (String[])MOpt.get("header"));

          // traitement spécifique pour le request-body (attention les headers correspondant ne sont pas positionnés automatiquement !!..)
          String tmpRequestBody = (String)UOpt.get("requestbody");

          if(!tmpRequestBody.equals("")) {

            // ajout du request-body à partir d'un fichier .hex
            ByteArrayOutputStream baos = new ByteArrayOutputStream();

            try {
              FileInputStream file1 = new FileInputStream(tmpRequestBody);
              byte[] reads = new byte[4096];
              int nread;

              try {
                baos = new ByteArrayOutputStream();

                while ( (nread = file1.read( reads, 0, 4096 )) != -1 )
                  for ( int i = 0; i < nread; i++ )
                    baos.write(reads[i]);

              }
              catch(java.io.IOException e) {
                System.err.println("IOException : " + e);
              }
            }
            catch(java.io.FileNotFoundException e) {
              System.err.println("FileNotFoundException : " + e);
            }

            hFast.put("request-body", baos.toByteArray());
          }

          // traitement spécifique pour les html stamps
          hFast.put("-htmlstamps", (Boolean)UDir.get("-htmlstamps"));
          hFast.put("-netstamps", (Boolean)UDir.get("-netstamps"));
          hFast.put("-resolvedns", (Boolean)UDir.get("-resolvedns"));

          // traitement spécifique pour le RAW
          hFast.put("-raw", (Boolean)UDir.get("-raw"));

          // traitement spécifique pour le UnsecureRandom
          hFast.put("-useunsecurerandom", (Boolean)UDir.get("-unsecurerandom"));

          // export certificate to file ?
          hFast.put("-exportcert", (Boolean)UDir.get("-exportcert"));

          // traitement spécifique pour le truststore
          String tmpTrust = (String)UOpt.get("truststore");

          if(tmpTrust.equals("")) { // default value
            System.clearProperty("javax.net.ssl.trustStore");
            hFast.put("trustmanager", new TrustManager[0]);
          }
          else {
            if(tmpTrust.equals("all")) {
              System.clearProperty("javax.net.ssl.trustStore");
              hFast.put("trustmanager", new TrustManager[] {new X509TrustManagerTrustAll()});
            }
            else {
              System.setProperty("javax.net.ssl.trustStore", tmpTrust);
              hFast.put("trustmanager", new TrustManager[0]);
            }
          }

          // create a CookieWrapper if necessary (bug solved in v0.111b)
          CookieWrapper cw = null;
          String sttmp = ( (String)UOpt.get("cookiestore") ).toLowerCase();
          Hashtable<String, Object> ht = new Hashtable<String, Object>();

          if(!sttmp.equals("")) {
            if(sttmp.equals("v1") || sttmp.equals("netscape") ) {
              ht.put("use", "yes");
              cw = new CookieWrapper("cookies_netscape", "cookies_V1");
              ht.put("cookies", cw);
            }
            else
              ht.put("use", "none");
          }
          else {
            ht.put("use", "none");
          }

          hFast.put("cookiesupport", ht);

          // traitement spécifique pour l'authentification proxy
          // le -proxyauth n'étant pas une vraie directive (pas appelée directement en ligne de commande)
          String tmpPA = (String)UOpt.get("proxyuser") + (String)UOpt.get("proxypass");

          if(!tmpPA.equals("")) {
            hFast.put("guiProxyuser", (String)UOpt.get("proxyuser"));
            hFast.put("guiProxypass", (String)UOpt.get("proxypass"));
            hFast.put("-proxyauth", true);
          }
          else
            hFast.put("-proxyauth", false);

          /*
           * the outputs are of a big interest here, because they allow to separate the request, the response headers, and response body
           * these outputs are stored in the table theouts and will be used later, at the very end of the socket reading/writing
           */
          MultiOutputStream mprequest = null, mpheader = null, mpbody = null, mpall = null;
          MultiOutputStream[] theouts;

          /*
           * output : when -o parameter is given, all outputs will use the value indicated by -o
           * otherwise, the parameters -orequest -oheader -obody will be used
           * values can be System.out, or any file
           */
          String[] outs = (String[])MOpt.get("o");

          // une seule sortie commune ?
          if(outs != null) {
            for(int i = 0; i < outs.length; i++) {
              if(outs[i].equals("System.out")) {
                if(i != 0)
                  mpall.addOutputStream(System.out);
                else
                  mpall = new MultiOutputStream(new OutputStream[] {System.out});
              }
              else {
                try {
                  FileOutputStream fos = new FileOutputStream(outs[i]);

                  if(i != 0)
                    mpall.addOutputStream(fos);
                  else
                    mpall = new MultiOutputStream(new OutputStream[] {fos});
                }
                catch(FileNotFoundException fnfe) {
                  System.err.println(fnfe);
                }
              }
            }

            // store the outputs in the table
            theouts = new MultiOutputStream[] {mpall, mpall, mpall};
          }
          // les sorties sont différenciées
          else {
            outs = (String[])MOpt.get("orequest");

            if(outs != null) {
              for(int i = 0; i < outs.length; i++) {
                if(outs[i].equals("System.out")) {
                  if(i != 0)
                    mprequest.addOutputStream(System.out);
                  else
                    mprequest = new MultiOutputStream(new OutputStream[] {System.out});
                }
                else {
                  try {
                    FileOutputStream fos = new FileOutputStream(outs[i]);

                    if(i != 0)
                      mprequest.addOutputStream(fos);
                    else
                      mprequest = new MultiOutputStream(new OutputStream[] {fos});
                  }
                  catch(FileNotFoundException fnfe) {
                    System.err.println(fnfe);
                  }
                }
              }
            }

            outs = (String[])MOpt.get("oheader");

            if(outs != null) {
              for(int i = 0; i < outs.length; i++) {
                if(outs[i].equals("System.out")) {
                  if(i != 0)
                    mpheader.addOutputStream(System.out);
                  else
                    mpheader = new MultiOutputStream(new OutputStream[] {System.out});
                }
                else {
                  try {
                    FileOutputStream fos = new FileOutputStream(outs[i]);

                    if(i != 0)
                      mpheader.addOutputStream(fos);
                    else
                      mpheader = new MultiOutputStream(new OutputStream[] {fos});
                  }
                  catch(FileNotFoundException fnfe) {
                    System.err.println(fnfe);
                  }
                }
              }
            }

            outs = (String[])MOpt.get("obody");

            if(outs != null) {
              for(int i = 0; i < outs.length; i++) {
                if(outs[i].equals("System.out")) {
                  if(i != 0)
                    mpbody.addOutputStream(System.out);
                  else
                    mpbody = new MultiOutputStream(new OutputStream[] {System.out});
                }
                else {
                  try {
                    FileOutputStream fos = new FileOutputStream(outs[i]);

                    if(i != 0)
                      mpbody.addOutputStream(fos);
                    else
                      mpbody = new MultiOutputStream(new OutputStream[] {fos});
                  }
                  catch(FileNotFoundException fnfe) {
                    System.err.println(fnfe);
                  }
                }
              }
            }

            // store the outputs in the table
            theouts = new MultiOutputStream[] {mprequest, mpheader, mpbody};
          }

          // 3- on appelle le process de gestion commune GUi/cli

          //initHTTPProcess(new MultiPrintStream[] {new MultiPrintStream(System.err), mps, new MultiPrintStream(System.err)}, false, false);
          initHTTPProcess(new BiStreamHandle(), theouts, false, false);

          /*
           * save cookies to file when necessary (introduced in v0.111b)
           *
          if(cw != null)
            cw.saveAll();*/
        }
      }

      return;
    }
  }

  static SimpleScenario initHTTPProcess(BiStreamHandle zepipe, MultiOutputStream[] mps, boolean setBodyHeaders, boolean tryKA) {

    // vérification de l'utilisation de cookies ?
    /*String susecookies = (String)( ((Hashtable)hFast.get("cookiesupport")).get("use") );
    boolean usecookies = (susecookies != null) && ( susecookies.equals("v1") || susecookies.equals("netscape") );
    GenericCookie oCookie = (usecookies) ? (GenericCookie)( ((Hashtable)hFast.get("cookiesupport")).get("cookies") ) : null;*/
    String susecookies = (String)( ((Hashtable)hFast.get("cookiesupport")).get("use") );
    boolean usecookies = (susecookies != null) && ( susecookies.equals("yes") );

    CookieWrapper cookiewrapper = (usecookies) ? (CookieWrapper)( ((Hashtable)hFast.get("cookiesupport")).get("cookies") ) : null;

    // objets
    //RequestMessageHeader messageHeader = (RequestMessageHeader)(RequestMessageHeaderFactory.create(oCookie));
    //RequestMessage req = new RequestMessage(messageHeader);
    RequestMessage req = new RequestMessage(new ReqMessageHeader());

    // exporter le certificat en fin de scenario ?
    boolean blnExportCertificate = (Boolean)hFast.get("-exportcert");

    try {

      // positionnement des unique-obligatoire
      //req.setMethod( (String)((Hashtable)hFast.get("guiMethod")).get("value") );
      req.setMethod( (String)hFast.get("guiMethod") );
      //req.setHostname( (String)hFast.get("guiHost"), RFCUtil.getPath( (String)hFast.get("guiPath") ) );
      req.setHostname( (String)hFast.get("guiHost") );
      req.setPort( (String)hFast.get("guiPort") );
      req.setRequestURI( (String)hFast.get("guiPath") );
      req.setHTTPVersion( (String)hFast.get("guiVersion") );

      // TO DO : compléter les paramètres 'multiple' à lister 1 par 1 + boucle sur les valeurs

      // positionnement des headers
      if(hFast.containsKey("headers")) {
        String[] hders = (String[])hFast.get("headers");

        if(hders != null) {
          if(hders.length != 0) {
            for(int i = 0; i < hders.length; i++) {
              //System.err.println(" -> " + hders[i]);
              int iindex = hders[i].indexOf(":");
              String hkey = hders[i].substring(0, iindex);
              String hval = hders[i].substring(iindex + 1);
              req.addHeader(hkey, hval);
            }
          }
        }
      } // fin headers
    }
    catch(MalformedHeaderException e) {
      e.printStackTrace(System.out);
      System.err.println(e.toString());
    }

    // positionnement du body s'il existe
    if(hFast.containsKey("request-body")) {
      byte[] thebody = (byte[])hFast.get("request-body");
      req.setBody(thebody);

      // positionnement automatique des headers si demandé
      if(setBodyHeaders) {
        /*
        try {
          //req.addHeader("Content-Type", "application/x-www-form-urlencoded");
          //req.addHeader("Content-Type", "multipart/form-data; boundary=---------------------------7d613238440eb0");
          //req.addHeader("Content-Length", (new Integer(thebody.length)).toString() );
          // DEBUG cookie en dur
          //req.addHeader("Cookie", "ADMINCONSOLESESSION=GfRHMyTyvDwgLy1nYS5zTt9wdx1t37bJmRBqL48SjycTLcRJtGwk!412977612");
        }
        catch(MalformedHeaderException e) {
          e.printStackTrace(System.out);
          System.err.println(e.toString());
        }
        */
      }
    }

    // Création du BiStreamHandle pour le maintien de la connection
    //BiStreamHandle bsh = new BiStreamHandle();
    BiStreamHandle bsh = zepipe;

    //récupération du timestamps
    boolean netstamps = ( (Boolean)(hFast.get("-netstamps")) ).booleanValue();
    boolean htmlstamps = ( (Boolean)(hFast.get("-htmlstamps")) ).booleanValue();
    boolean resolvedns = ( (Boolean)(hFast.get("-resolvedns")) ).booleanValue();

    // mode raw
    boolean israw = ( (Boolean)(hFast.get("-raw")) ).booleanValue();

    // convert characters (consistency check was made during command-line parsing)
    Hashtable<Byte, String> hconv = null;

    if((Boolean)hFast.get("-lf2crlf")) {
      hconv = new Hashtable<Byte, String>();
      hconv.put(new Byte((byte)10), RFCUtil.CRLF);
    }

    if((Boolean)hFast.get("-crlf2lf")) {
      hconv = new Hashtable<Byte, String>();
      hconv.put(new Byte((byte)13), RFCUtil.NULL);
    }

    // Création du handle
    HTTPTransaction zhandle;

    if( ((String)hFast.get("guiConnConnect")).toLowerCase().equals("http") ) {

      // cas du proxy
      if( !(((String)hFast.get("guiProxyname"))).equals("") ) {
        //zhandle = new PlainTransactionViaProxy(bsh, mps, htmlstamps, netstamps, resolvedns, oCookie, hconv, israw);
        zhandle = new PlainTransactionViaProxy(bsh, mps, htmlstamps, netstamps, resolvedns, hconv, israw);
        // TO DO : vérifier pourquoi on ne passe pas ces paramètres dans le constructeur ????
        zhandle.setProxyName( (String)hFast.get("guiProxyname") );
        zhandle.setProxyPort( (new Integer(((String)hFast.get("guiProxyport")))).intValue() );
      }
      else {
        //zhandle = new PlainTransaction(bsh, mps, htmlstamps, netstamps, resolvedns, oCookie, hconv, israw);
        zhandle = new PlainTransaction(bsh, mps, htmlstamps, netstamps, resolvedns, hconv, israw);
      }
    }
    else {
      // récupération des ciphers s'il y a lieu
      String daProvider = (String)hFast.get("provider");
      String daInstance = (String)hFast.get("instance");
      String cipherlist = (String)hFast.get("ciphers");
      String[] daCiphz = (!cipherlist.equals("")) ? cipherlist.split(":") : new String[0];
      String protolist = (String)hFast.get("sslprotocols");
      String[] daProtz = (!protolist.equals("")) ? protolist.split(":") : new String[0];
      //TrustManager[] daTrustz = null;
      //TrustManager[] daTrustz = new TrustManager[] {new X509TrustManagerTrustAll()};
      TrustManager[] daTrustz = (TrustManager[])hFast.get("trustmanager");
      boolean useunsecurerandom = ( (Boolean)(hFast.get("-useunsecurerandom")) ).booleanValue();

      if( !(((String)hFast.get("guiProxyname"))).equals("") ) {
        // TO DO : vérifier pourquoi mm constructeurs ????
        if( (Boolean)hFast.get("-proxyauth") ) {
          //zhandle = new SSLTransactionViaProxy(bsh, mps, htmlstamps, netstamps, resolvedns, oCookie, daInstance, daProvider, daProtz, daCiphz, daTrustz, hconv, israw);
          zhandle = new SSLTransactionViaProxy(bsh, mps, htmlstamps, netstamps, resolvedns, daInstance, daProvider, daProtz, daCiphz, daTrustz, hconv, israw, useunsecurerandom);
        }
        else {
          //zhandle = new SSLTransactionViaProxy(bsh, mps, htmlstamps, netstamps, resolvedns, oCookie, daInstance, daProvider, daProtz, daCiphz, daTrustz, hconv, israw);
          zhandle = new SSLTransactionViaProxy(bsh, mps, htmlstamps, netstamps, resolvedns, daInstance, daProvider, daProtz, daCiphz, daTrustz, hconv, israw, useunsecurerandom);
        }

        zhandle.setProxyName(((String)hFast.get("guiProxyname")));
        zhandle.setProxyPort( (new Integer(((String)hFast.get("guiProxyport")))).intValue() );
      }
      else {
        //zhandle = new SSLTransaction(bsh, mps, htmlstamps, netstamps, resolvedns, oCookie, daInstance, daProvider, daProtz, daCiphz, daTrustz, hconv, israw);
        zhandle = new SSLTransaction(bsh, mps, htmlstamps, netstamps, resolvedns, daInstance, daProvider, daProtz, daCiphz, daTrustz, hconv, israw, useunsecurerandom);
      }
    }

    zhandle.setRequestMessage(req);

    // conversion des directives en int pour éviter les if/else imbriqués en faveur de switch/case
    int idir = 0;

    if( (Boolean)hFast.get("-follow") )
      idir = 1;

    if( (Boolean)hFast.get("-sslservercheckup") )
      idir = 2;

    if( (Boolean)hFast.get("-digest") )
      idir = 3;

    if( (Boolean)hFast.get("-ntlm") )
      idir = 4;

    if( (Boolean)hFast.get("-proxyauth") )
      if( (Boolean)hFast.get("-sslservercheckup") )
        idir = 5;
      else
        idir = 6;

    SimpleScenario ssrez = null;
    ScenarioTimerTask stt;

    // important : blnExportCertificate is not used in all scenarios, this means we won't save the certificate in all scenarios
    switch(idir) {
      case 0: // simple request
        //HTTPScenario scenario = new HTTPScenario(zhandle, tryKA, htmlstamps, blnExportCertificate, oCookie);
        HTTPScenario scenario = new HTTPScenario(zhandle, tryKA, htmlstamps, blnExportCertificate, cookiewrapper);

        scenario.start();
        ssrez = scenario;
        break;

      case 1: // follow
        FullScenario fs = new FullScenario(zhandle);
        fs.run();
        // TO DO : ssrez
        break;

      case 2: // sslservercheckup
        System.err.println("--sslservercheckup");
        ((EmptySSLTransaction)zhandle).setLogException(false);
        CheckUpScenario cus = new CheckUpScenario((EmptySSLTransaction)zhandle, htmlstamps);

        cus.start();
        ssrez = cus;
        break;

      case 3: // digest
        DigestScenario dig = new DigestScenario(zhandle, htmlstamps, (String)hFast.get("user"), (String)hFast.get("password"), blnExportCertificate);

        dig.start();
        ssrez = dig;
        break;

      case 4: // ntlm (disabled)
        NTLMScenario ntl = new NTLMScenario(zhandle, htmlstamps, (String)hFast.get("ntlmuser"), (String)hFast.get("ntlmpassword"), (String)hFast.get("ntlmdomain"), blnExportCertificate, tryKA, cookiewrapper);
        ntl.start();
        ssrez = ntl;
        break;

      case 5: // proxyauth & sslservercheckup
        System.err.println("--sslservercheckup & proxyauth");
        CheckUpScenario mus = new CheckUpScenario((EmptySSLTransaction)zhandle, htmlstamps, (String)hFast.get("guiProxyuser"), (String)hFast.get("guiProxypass") );

        mus.start();
        ssrez = mus;
        break;

      case 6: // proxyauth
        SimpleScenario pas;

        if ( (new SSLTransactionViaProxy()).getClass() == zhandle.getClass() )
          pas = new SSLProxyAuthScenario((SSLTransactionViaProxy)zhandle,
                                         htmlstamps,
                                         (String)hFast.get("guiProxyuser"),
                                         (String)hFast.get("guiProxypass"),
                                         blnExportCertificate,
                                         cookiewrapper );
        else
          pas = new ProxyAuthScenario((PlainTransactionViaProxy)zhandle,
                                      htmlstamps,
                                      (String)hFast.get("guiProxyuser"),
                                      (String)hFast.get("guiProxypass"),
                                      cookiewrapper );

        pas.start();
        ssrez = pas;
        break;
    }

    return ssrez;
  }

  public void swgQuitter() {
    System.exit(0);
  }

  public void swgAbort() {
    SimpleScenario ss = (SimpleScenario)hGUI.get("ss");

    if(ss != null) {
      ss.stopit();
    }
  }

  /*
   * update log settings
   * 1- the mps[] object
   * 2- the timestamps flag/directive
   * 3- the DNS flag/directive
   * 2- the RAW mode flag/directive
   */
  public void swgLogSettings() {

    // GUi components
    JCheckBox rbmi, rbmj, rbmk, rbml, rbmm, rbmn, rbmo;
    rbmi = new JCheckBox("request", ((MultiOutputStream[])(hGUI.get("mps")))[0] != null );
    rbmj = new JCheckBox("response header", ((MultiOutputStream[])(hGUI.get("mps")))[1] != null );
    rbmk = new JCheckBox("response body", ((MultiOutputStream[])(hGUI.get("mps")))[2] != null );
    rbml = new JCheckBox("htmlstamps", (Boolean)(hGUI.get("htmlstamps")) );
    rbmm = new JCheckBox("netstamps", (Boolean)(hGUI.get("netstamps")) );
    rbmn = new JCheckBox("DNS", (Boolean)(hGUI.get("resolvedns")) );
    rbmo = new JCheckBox("RAW mode", (Boolean)(hGUI.get("raw")) );
    //boolean blntmp = ( (HTMLStamps)(hGUI.get("htmlstamps")) != null);
    //rbml = new JCheckBox("htmlstamps", blntmp);

    // draw the pop-up
    int result = JOptionPane.showOptionDialog(this, new Object[] {rbmi, rbmj, rbmk, rbml, rbmm, rbmn, rbmo}, "Log Settings", JOptionPane.OK_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE, null, null, null);

    // results and update of the hGUI values
    if(result == JOptionPane.OK_OPTION) {
      Hashtable<String, Object> ht = new Hashtable<String, Object>();

      // remember the initial mos object was saved when creating the JTouch GUi
      MultiOutputStream mptmp = (MultiOutputStream)(hGUI.get("mps-save"));
      MultiOutputStream mp1 = rbmi.isSelected() ? mptmp : null;
      MultiOutputStream mp2 = rbmj.isSelected() ? mptmp : null;
      MultiOutputStream mp3 = rbmk.isSelected() ? mptmp : null;
      // store the new MOS[] object in hGUI
      hGUI.put("mps", new MultiOutputStream[] {mp1, mp2, mp3});

      // store timestamps value
      hGUI.put("htmlstamps", rbml.isSelected());
      hGUI.put("netstamps", rbmm.isSelected());
      hGUI.put("resolvedns", rbmn.isSelected());
      hGUI.put("raw", rbmo.isSelected());
      /*if(rbml.isSelected())
        hGUI.put("htmlstamps", StampsFactory.create("StdErr"));
      else
        hGUI.remove("htmlstamps");*/

    }
  }

  public void swgMethod() {
    //Hashtable<String, Object> vals = (Hashtable)hGUI.get("guiMethod");
    Hashtable<String, Object> vals = (Hashtable)hGUI.get("guiMethod");
    JComboBox jcb = (JComboBox)vals.get("objectID");
    vals.put("value", (String)jcb.getSelectedItem());
  }

  public void swgHost() {
    Hashtable<String, Object> vals = (Hashtable)hGUI.get("guiHost");
    JComboBox jcb = (JComboBox)vals.get("objectID");

    //System.err.println("-> " + jcb.getPreferredSize());
    //System.err.println("-> " + jcb.getSize());

    // récupérer la nouvelle valeur sélectionnée
    String newvalue = (String)jcb.getSelectedItem();

    // rechercher la nouvelle valeur dans l'historique
    List<String> list = (ArrayList<String>)vals.get("vals");
    boolean found = false;

    for(String st : list)
      if(st.equals(newvalue))
        found = true;

    // la valeur ne figure pas dans l'historique => il faut la sauvegarder
    if(!found) {
      // sauvegarde dans la liste
      list.add(newvalue);
      // sauvegarde dans la gui
      jcb.addItem(newvalue);
    }

    vals.put("value", newvalue);
  }

  public void swgPort() {
    Hashtable<String, Object> vals = (Hashtable<String, Object>)hGUI.get("guiPort");
    JComboBox jcb = (JComboBox)vals.get("objectID");

    // récupérer la nouvelle valeur sélectionnée
    String newvalue = (String)jcb.getSelectedItem();

    // rechercher la nouvelle valeur dans l'historique
    List<String> list = (ArrayList<String>)vals.get("vals");
    boolean found = false;

    for(String st : list)
      if(st.equals(newvalue))
        found = true;

    // la valeur ne figure pas dans l'historique => il faut la sauvegarder
    if(!found) {
      // sauvegarde dans la liste
      list.add(newvalue);
      // sauvegarde dans la gui
      jcb.addItem(newvalue);
    }

    vals.put("value", newvalue);
  }

  public void swgVersion() {
    Hashtable<String, Object> vals = (Hashtable)hGUI.get("guiVersion");
    JComboBox jcb = (JComboBox)vals.get("objectID");
    // on rajoute le préfixe "HTTP/" conformément à RFC 2616 §3.1
    vals.put( "value", "HTTP/".concat( (String)jcb.getSelectedItem() ) );
  }

  public void swgPath() {
    Hashtable<String, Object> vals = (Hashtable)hGUI.get("guiPath");
    JComboBox jcb = (JComboBox)vals.get("objectID");
    //System.err.println("-> " + jcb.getPreferredSize());
    //System.err.println("-> " + jcb.getSize());

    // récupérer la nouvelle valeur sélectionnée
    String newvalue = (String)jcb.getSelectedItem();

    // rechercher la nouvelle valeur dans l'historique
    List<String> list = (ArrayList<String>)vals.get("vals");
    boolean found = false;

    for(String st : list)
      if(st.equals(newvalue))
        found = true;

    // la valeur ne figure pas dans l'historique => il faut la sauvegarder
    if(!found) {
      // sauvegarde dans la liste
      list.add(newvalue);
      // sauvegarde dans la gui
      jcb.addItem(newvalue);
    }

    vals.put("value", newvalue);
  }

  public void swgSSLServerCheckUp() {

    System.err.println("SSLServerCheckUp");

    // préparation du hFast : les paramètres qu'il ne faut pas positionner
    hFast.put("-follow", false);
    hFast.put("-digest", false);
    hFast.put("-proxyauth", false);

    if(hFast.containsKey("headers"))
      hFast.remove("headers");

    if(hFast.containsKey("request-body"))
      hFast.remove("headers");

    hFast.put("-raw", false);
    hFast.put("-exportcert", false);

    // préparation du hFast : les paramètres indispensables
    hFast.put("guiMethod", (String)((Hashtable)hGUI.get("guiMethod")).get("value"));
    hFast.put("guiHost", (String)((Hashtable)hGUI.get("guiHost")).get("value"));
    hFast.put("guiPort", (String)((Hashtable)hGUI.get("guiPort")).get("value"));
    hFast.put("guiVersion", (String)((Hashtable)hGUI.get("guiVersion")).get("value"));
    hFast.put("guiPath", (String)((Hashtable)hGUI.get("guiPath")).get("value"));
    hFast.put("trustmanager", (TrustManager[])(((Hashtable)hGUI.get("trustmanager")).get("value")) );

    // récupération des timestamps si nécessaire (commun à tous les scénarios)
    //hFast.put("-htmlstamps", (HTMLStamps)(hGUI.get("htmlstamps")) );
    //hFast.put("-htmlstamps", (Boolean)(hGUI.get("htmlstamps")) );
    //hFast.put("-netstamps", (Boolean)(hGUI.get("netstamps")) );
    //hFast.put("-resolvedns", (Boolean)(hGUI.get("resolvedns")) );
    hFast.put("-htmlstamps", false );
    hFast.put("-netstamps", false );
    hFast.put("-resolvedns", false );

    // utilisation des cookies : on reprend la configuration indiquée par la GUi
    hFast.put("cookiesupport", (Hashtable)hGUI.get("cookiesupport"));

    // positionner le paramètre CRLF : aucun en mode GUI
    hFast.put("-lf2crlf", false);
    hFast.put("-crlf2lf", false);

    // suppression du résidu --ntlm si besoin
    hFast.put("-ntlm", false);

    // utilisation proxy ?
    Boolean blnProx = (Boolean)( (Hashtable)hGUI.get("guiProxOnOff") ).get("value");
    String spr1 = "", spr2 = "", spr3 = "", spr4 = "";

    if(blnProx) {
      JTextField jtf = (JTextField)( (Hashtable)hGUI.get("guiProxyname") ).get("objectID");
      spr1 = jtf.getText();
      jtf = (JTextField)( (Hashtable)hGUI.get("guiProxyport") ).get("objectID");
      spr2 = jtf.getText();
      jtf = (JTextField)( (Hashtable)hGUI.get("guiProxyuser") ).get("objectID");
      spr3 = jtf.getText();
      jtf = (JTextField)( (Hashtable)hGUI.get("guiProxypass") ).get("objectID");
      spr4 = jtf.getText();
    }

    hFast.put("guiProxyname", spr1);
    hFast.put("guiProxyport", spr2);
    hFast.put("guiProxyuser", spr3);
    hFast.put("guiProxypass", spr4);

    // directive pour le scenario d'authentification proxy
    if( !(spr3 + spr4).equals("") )
      hFast.put("-proxyauth", true);

    hFast.put("guiConnConnect", "https");

    hFast.put("provider", "IBMJSSE");
    hFast.put("instance", "TLS");
    hFast.put("ciphers", "");
    hFast.put("sslprotocols", "");
    hFast.put("-sslservercheckup", true);

    SimpleScenario ss = initHTTPProcess((BiStreamHandle)(hGUI.get("bsh")), (MultiOutputStream[])(hGUI.get("mps")), false, false);
    //System.err.println("-->" + ss.handle.getHandshakeInfo());
    hGUI.put("ss", ss);
  }

  // PLAF dialog pop-up
  public void swgSelectPLAF() {

    // get available LAFs
    final UIManager.LookAndFeelInfo[] info = UIManager.getInstalledLookAndFeels();
    final String old = UIManager.getLookAndFeel().getName();

    ButtonGroup bg = new ButtonGroup();
    JRadioButton[] jrba = new JRadioButton[info.length];

    for(int i = 0; i < info.length; i++) {
      // create buttons and select the current LAF

      JRadioButton jrb = (old.equals("GTK look and feel")) ? new JRadioButton( info[i].getName(), info[i].getName().equals("GTK+") )
                                                           : new JRadioButton(info[i].getName(), old.equals(info[i].getName()) ) ;

      bg.add(jrb);
      jrba[i] = jrb;
    }

    // create dialog pop-up
    int result = JOptionPane.showOptionDialog(this, (Object[])(jrba), "Select PLAF", JOptionPane.OK_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE, null, null, null);

    // update when the selection has changed ( = OK button + different selection)
    if(result == JOptionPane.OK_OPTION) {
      String className = "";

      // find the selected option
      for(int i = 0; i < info.length; i++) {
        if(jrba[i].isSelected())
          className = info[i].getClassName();
      }

      // apply changes finally
      if(!old.equals(className)) {
        try {
          UIManager.setLookAndFeel(className);
          SwingUtilities.invokeLater(new Runnable() {
            public void run() {

              JTouch.this.dispose();

              // window decorations when supported only
              if( ! UIManager.getLookAndFeel().getSupportsWindowDecorations( ) )
                JTouch.this.setUndecorated(false);
              else
                JTouch.this.setUndecorated(true);

              SwingUtilities.updateComponentTreeUI(JTouch.this);
              JTouch.this.pack();
              JTouch.this.setVisible(true);

            }
          });
        }
        catch(Exception e) {
          System.err.println(e);
        }
      }

    } // fin pop-up
  }

  // afficher la pop-up de configuration SSL
  public void swgConfigSSL() {

    // sauvegarde ancienne valeur GUi pour comparaison et affichage de l'élément sélectionné
    String oldpro = (String)( ((Hashtable)hGUI.get("provider")).get("value") );

    // création des buttons et du buttongroup
    ButtonGroup confSSL = new ButtonGroup();
    JRadioButton rbmi, rbmj, rbmk;
    rbmi = new JRadioButton("SunJSSE with SSLv2Hello", oldpro.equals("SunJSSE_SSLv2Hello"));
    confSSL.add(rbmi);
    rbmj = new JRadioButton("SunJSSE without SSLv2Hello", oldpro.equals("SunJSSE_Strict"));
    confSSL.add(rbmj);
    rbmk = new JRadioButton("IBMJSSE", oldpro.equals("IBMJSSE"));
    confSSL.add(rbmk);

    // création de la pop-up
    int result = JOptionPane.showOptionDialog(this, new Object[] {rbmi, rbmj, rbmk}, "Select provider", JOptionPane.OK_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE, null, null, null);

    // résultats & mise à jour de hGUI
    if(result == JOptionPane.OK_OPTION) {
      Hashtable<String, Object> ht = new Hashtable<String, Object>();
      String val = "";

      if(rbmi.isSelected())
        val = "SunJSSE_SSLv2Hello";

      if(rbmj.isSelected())
        val = "SunJSSE_Strict";

      if(rbmk.isSelected())
        val = "IBMJSSE";

      // mise à jour uniquement si modification de la valeur + dégager ancienne connexion
      if(!oldpro.equals(val)) {
        ht.put("value", val);
        hGUI.put("provider", ht);
        reuseConn = false;

        // mise à jour de la GUI (combobox de sélection du protocole SSL)
        Hashtable vals = (Hashtable)hGUI.get("guiConnConnect");
        JComboBox jcb = (JComboBox)vals.get("objectID");

        // suppression temporaire des actionlisteners
        ActionListener[] alis = jcb.getActionListeners();

        for(int i = 0; i < alis.length; i++)
          jcb.removeActionListener(alis[i]);

        jcb.removeAllItems();

        if(val.equals("IBMJSSE")) {
          jcb.addItem("http");
          jcb.addItem("SSL 2.0");
          jcb.addItem("SSL 3.0");
          jcb.addItem("TLS 1.0");
        }

        if(val.equals("SunJSSE_SSLv2Hello") || val.equals("SunJSSE_Strict") ) {
          jcb.addItem("http");
          jcb.addItem("SSL 3.0");
          jcb.addItem("TLS 1.0");
          switch(RuntimeUtil.getVersion()) {
            case 5:
            case 6:
            case 7:
              break;

            case 8: // starting from 8u261, TLS 1.3 is handled by JSSE
              jcb.addItem("TLS 1.1");
              jcb.addItem("TLS 1.2");

              if(RuntimeUtil.getMinorVersion() >= 261)
                jcb.addItem("TLS 1.3");
              break;

            default : // 9+ all handle TLS 1.3
              jcb.addItem("TLS 1.1");
              jcb.addItem("TLS 1.2");
              jcb.addItem("TLS 1.3");
              break;
          }
        }

        /* TO BE REMOVED *
        if(val.equals("SunJSSE_Strict")) {
          jcb.addItem("http");
          jcb.addItem("SSL 3.0");
          jcb.addItem("TLS 1.0");
          if(RuntimeUtil.getVersion()>=8) {
            jcb.addItem("TLS 1.1");
            jcb.addItem("TLS 1.2");
          }
        }*/

        // on remet les actionlisteners
        for(int i = 0; i < alis.length; i++)
          jcb.addActionListener(alis[i]);

        jcb.setSelectedIndex(0);
      }

    }
  }

  /*
   * displays pop-up for SSL Random settings
   * accessible with : Advanced -> SSL Random settings
   */
  public void swgSSLRandom() {

    // remember the previous values stored in hGUI
    Boolean oldpro = ( (Boolean)hGUI.get("unsecurerandom") == null ) ? false : (Boolean)hGUI.get("unsecurerandom");

    // 2 radio buttons
    ButtonGroup confSSL = new ButtonGroup();
    JRadioButton rbmi, rbmj;
    rbmi = new JRadioButton("No", oldpro == false);
    confSSL.add(rbmi);
    rbmj = new JRadioButton("Yes", oldpro == true);
    confSSL.add(rbmj);

    // pop-up
    int result = JOptionPane.showOptionDialog(this, new Object[] {rbmi, rbmj}, "Use unsecure random", JOptionPane.OK_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE, null, null, null);

    // results & hGUI update
    if(result == JOptionPane.OK_OPTION) {

      Boolean val = (rbmj.isSelected());

      if(val != oldpro) {
        Hashtable<String, Object> ht = new Hashtable<String, Object>();
        ht.put("use", val);

        hGUI.put("unsecurerandom", val);
      }
    }
    else {
      // nothing to do when cancelled
    }
  }

  /*
   * displays pop-up for cookie support
   * accessible with : Advanced -> Cookie Support
   */
  public void swgCookieSupport() {

    // remember the previous values stored in hGUI
    CookieWrapper previousCW;
    String oldpro = (String)( ((Hashtable)hGUI.get("cookiesupport")).get("use") );

    // initialize default values and create the first CookieWrapper object which will be stored, maybe.
    if(oldpro == null) {
      oldpro = "none";
      previousCW = new CookieWrapper();
    }
    else
      previousCW = (CookieWrapper)( ((Hashtable)hGUI.get("cookiesupport")).get("cookies") );

    // 2 radio buttons
    ButtonGroup confSSL = new ButtonGroup();
    JRadioButton rbmi, rbmj, rbmk;
    rbmi = new JRadioButton("No", oldpro.equals("none"));
    confSSL.add(rbmi);
    rbmj = new JRadioButton("Yes", oldpro.equals("yes"));
    confSSL.add(rbmj);

    // pop-up
    int result = JOptionPane.showOptionDialog(this, new Object[] {rbmi, rbmj}, "Cookie support", JOptionPane.OK_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE, null, null, null);

    // results & hGUI update
    if(result == JOptionPane.OK_OPTION) {

      String val = "";

      if(rbmi.isSelected())
        val = "none";

      if(rbmj.isSelected())
        val = "yes";

      if(val != oldpro) {
        Hashtable<String, Object> ht = new Hashtable<String, Object>();
        ht.put("use", val);
        // in all cases we store the previous cookies
        ht.put("cookies", previousCW);

        hGUI.put("cookiesupport", ht);
      }
    }
    else {
      // nothing to do when cancelled
    }
  }

  /*
   * displays pop-up showing all installed providers
   * Reserved for Future Usage
   */
  public void swgInstalledProviders() {

    StringBuffer sb = new StringBuffer();
    //Provider[] providerz = Security.getProviders("jsse");
    Provider[] providerz = Security.getProviders("JSSE.*");

    for(Provider p : providerz) {
      sb.append(p.getName() + "\n" + p.getVersion());
    }

    JOptionPane.showMessageDialog(this, sb.toString(), "info", JOptionPane.PLAIN_MESSAGE);
  }

  /*
   * takes an array of anything, and returns an array of String using object.toString()
   */
  public String[] arrayToStringArray(Object[] allO) {
    String[] rez = new String[allO.length];

    for(int i = 0; i < allO.length; i++)
      rez[i] = allO[i].toString();

    return rez;
  }

  /*
   * store the certificate in the file
   */
  public void swgExportCertificate(X509Certificate[] certs, String filename) {

    int i = 0;

    for(X509Certificate cert : certs) {
      if(CertificateUtil.exportToFile(cert, filename + i))
        System.err.println("exporting certificate to file : " + filename + i + " succesfully.");
      else
        System.err.println("exporting certificate to file : " + filename + i + " not successfully.");

      i++;
    }
  }

  /*
   * displays a pop-up with tabbed panes
   * -> cipher suite
   * -> peer certificate
   * -> certificate chain
   */
  public void swgLastCertificate() {

    SimpleScenario ss = (SimpleScenario)(hGUI.get("ss"));

    if(ss.handle.getHandshakeInfo() != null) {
      //JOptionPane.showMessageDialog(this, ss.handle.getHandshakeInfo(), "info", JOptionPane.PLAIN_MESSAGE);

      /*
       * build the panes
       */
      JTabbedPane[] allPanes;
      JTabbedPane tab1 = new JTabbedPane();
      JComponent panel1 = makeTextPanel((String)ss.handle.getHandshakeInfo().get("cipher"));
      tab1.addTab("CipherSuite", null, panel1, "CipherSuite");

      try {
        StringBuffer sb = new StringBuffer(24);

        // casting Certificate to X509Certificate
        X509Certificate[] chain = (X509Certificate[])ss.handle.getHandshakeInfo().get("peerCertificates");

        // for a complete list of available properties, see http://java.sun.com/javase/6/docs/api/java/security/cert/X509Certificate.html
        String[] strDetails = new String[] {
          "Version: V" + new Integer((chain[0]).getVersion()).toString(),
          "Signature algorithm: " + chain[0].getSigAlgName(),
          "Issuer: " + chain[0].getIssuerX500Principal().toString(),
          "Valid from: " + chain[0].getNotBefore().toString(),
          "Valid to: " + chain[0].getNotAfter().toString(),
          "Subject: " + chain[0].getSubjectX500Principal().toString()
        };

        // panel2 is made from several lines, and a button
        JPanel panel2 = new JPanel(false);
        panel2.setLayout(new GridLayout(strDetails.length + 1, 1));

        for(String text : strDetails) {
          JLabel filler = new JLabel(text.trim());
          filler.setHorizontalAlignment(JLabel.LEFT);
          panel2.add(filler);
        }

        JButton butt = new JButton("export certificate");
        butt.addActionListener(new swgExportCertificate(this, chain, "exported.pem"));
        panel2.add(butt);
        tab1.addTab("Details", null, panel2, "Details");

        // extract the chain from the chain array which is in reverse order
        int intA = 0;
        String[] strChain = new String[chain.length + 1];

        for(int i = chain.length - 1; i > 0; i--)
          strChain[intA++] = chain[i].getIssuerX500Principal().toString();

        strChain[intA++] = chain[0].getIssuerX500Principal().toString();
        strChain[intA] = chain[0].getSubjectX500Principal().toString();

        /* DEBUG
        for(String astr : strChain)
          System.err.println(astr);*/
        JComponent panel3 = makeTextPanel(strChain, true);
        tab1.addTab("Certification path", null, panel3, "Certification path");
      }
      catch(NullPointerException npe) {}

      /*
       * make the new window
       */
      JFrame popup = new JFrame("See last certificate");

      // close & free resources when closing
      popup.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
      //popup.getContentPane().add(emptyLabel, BorderLayout.CENTER);

      popup.getContentPane().add(tab1);

      popup.pack();
      popup.setVisible(true);
    }
    else {
    }
  }

  /*
   * code from TabbedPaneDemo.java
   * builds a text panel
   */
  protected JComponent makeTextPanel(String text) {
    JPanel panel = new JPanel(false);
    JLabel filler = new JLabel(text);
    filler.setHorizontalAlignment(JLabel.LEFT);
    filler.setVerticalAlignment(JLabel.TOP);
    panel.setLayout(new GridLayout(1, 1));
    panel.add(filler);
    return panel;
  }
  protected JComponent makeTextPanel(String[] texts, boolean blnTrim) {
    JPanel panel = new JPanel(false);
    panel.setLayout(new GridLayout(texts.length, 1));

    for(String text : texts) {
      // DEBUG      System.err.println("-" + text);
      JLabel filler = blnTrim ? new JLabel(text.trim()) : new JLabel(text);
      filler.setHorizontalAlignment(JLabel.LEFT);
      panel.add(filler);
    }

    return panel;
  }

  /*
   * displays the About pop-up with tabbed panes
   * -> about
   * -> license
   * -> credits
   */
  public void swgAbout() {

    // contains all panes
    JTabbedPane[] allPanes;

    String isLimited = (RuntimeUtil.restrictedCryptography()) ? "SSL limited, consider installing JCE unlimited" : "SSL unlimited";
    // prepare 1st pane
    String[] strAbout = new String[] {
      "JTouch 1.0.5 Copyright (C) 2009-2022 under Modified BSD License",
      "website: http://sourceforge.net/projects/JTouch",
      "Contact: nephylim@users.sourceforge.net",
      "Java Version: " + RuntimeUtil.getVersion() + "u" + RuntimeUtil.getMinorVersion(),
      isLimited
    };

    JTabbedPane tab1 = new JTabbedPane();
    JComponent panel1 = makeTextPanel(strAbout, true);
    tab1.addTab("About", null, panel1, "About");

    // 2nd pane
    StringBuffer sbDetails = new StringBuffer(4096);
    sbDetails.append("* JTouch 1.0.5 Copyright (C) 2009-2018 under Modified BSD License");

    String strDetails = "";

    JTextArea extArea = new JTextArea(sbDetails.toString(), 8, 80);
    extArea.setFont(new Font("Courier New", Font.ITALIC, 10));
    extArea.setLineWrap(false);
    extArea.setWrapStyleWord(false);
    extArea.setEnabled(true);
    JScrollPane areaScrollPane = new JScrollPane(extArea,
        ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
        ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED );

    JComponent panel2 = makeTextPanel(strDetails);
    tab1.addTab("License", null, areaScrollPane, "License");

    // 3rd pane
    String[] strCredits = new String[] {
      "This product includes software developed by the Apache Software Foundation (http://www.apache.org/).",
      "",
      "Credits to:",
      "Robert Harder : Base64 encoding/decoding, under Public Domain license. http://iharder.net/base64",
      "Emil Ivov : Digest algorithm, under Apache Software license. http://sip-communicator.org/"
    };
    JComponent panel3 = makeTextPanel(strCredits, true);
    tab1.addTab("Credits", null, panel3, "Credits");

    /*
     * make the new window
     */
    JFrame popup = new JFrame("About");

    // close & free resources when closing
    popup.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);

    popup.getContentPane().add(tab1);

    popup.pack();
    popup.setVisible(true);

  } // end Aboutt

  /*
   * displays pop-up showing the TrustStore to choose
   * accessible with : Advanced -> Select Truststore
   */
  public void swgSSLTruststore() {

    // remember the previous values stored in hGUI
    String oldpro = (String)( ((Hashtable)hGUI.get("trustmanager")).get("name") );

    if(oldpro == null)
      oldpro = "systemdefault";

    // 3 radio buttons
    ButtonGroup confSSL = new ButtonGroup();
    JRadioButton rbmi, rbmj, rbmk;
    rbmi = new JRadioButton("System default CAs", oldpro.equals("systemdefault"));
    confSSL.add(rbmi);
    rbmj = new JRadioButton("Trust all CAs", oldpro.equals("allca"));
    confSSL.add(rbmj);
    rbmk = new JRadioButton("Local cacerts file", oldpro.equals("mycerts"));
    confSSL.add(rbmk);

    // pop-up
    int result = JOptionPane.showOptionDialog(this, new Object[] {rbmi, rbmj, rbmk}, "Select truststore", JOptionPane.OK_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE, null, null, null);

    // results & hGUI update
    if(result == JOptionPane.OK_OPTION) {

      String val = "";

      if(rbmi.isSelected()) {
        val = "systemdefault";
      }

      if(rbmj.isSelected()) {
        val = "allca";
      }

      if(rbmk.isSelected()) {
        val = "mycerts";
      }

      if(!oldpro.equals(val)) {
        Hashtable<String, Object> ht = new Hashtable<String, Object>();
        TrustManager[] trustmanager;

        /*
         * in order to choose the truststore, we must set 2 values :
         *  -javax.net.ssl.trustStore system property (saved by the system)
         *  -TrustManager[] (saved in the hGUI, and later called for hFast)
         */
        if(val.equals("systemdefault")) { //System default CAs
          System.clearProperty("javax.net.ssl.trustStore");
          ht.put("value", new TrustManager[0]);

          // 'name' is stored to remember the current value
          ht.put("name", "systemdefault");
        }

        if(val.equals("allca")) { //ALL CAs
          System.clearProperty("javax.net.ssl.trustStore");
          ht.put("value", new TrustManager[] {new X509TrustManagerTrustAll()});
          ht.put("name", "allca");
        }

        if(val.equals("mycerts")) { // CAs from file 'mycerts' in local directory (TO DO : select file)
          System.setProperty("javax.net.ssl.trustStore", "mycerts");
          ht.put("value", new TrustManager[0]);
          ht.put("name", "mycerts");
        }

        hGUI.put("trustmanager", ht);

        // important : force a new connection when SSL parameters are changed (though in this precise case I'm not sure this is necessary)
        reuseConn = false;
      }
      else {
        // nothing to do when cancelled
      }
    }
  }

  /*
   * behaviour of the Authentication part
   */
  public void swgAuthMethod() {
    Hashtable<String, Object> vals = (Hashtable)hGUI.get("guiAuthMethod");
    JComboBox jcb = (JComboBox)vals.get("objectID");
    String sval = (String)jcb.getSelectedItem();

    // no authentication, disable the two other boxes
    if(sval.equals("Anonymous")) {
      JTextField jtf = (JTextField)( (Hashtable)hGUI.get("guiAuthUser") ).get("objectID");
      jtf.setEnabled(false);
      jtf = (JTextField)( (Hashtable)hGUI.get("guiAuthPassword") ).get("objectID");
      jtf.setEnabled(false);
      jtf = (JTextField)( (Hashtable)hGUI.get("guiAuthDomain") ).get("objectID");
      jtf.setEnabled(false);
    }

    // Basic : nothing special
    if(sval.equals("Basic")) {
      JTextField jtf = (JTextField)( (Hashtable)hGUI.get("guiAuthUser") ).get("objectID");
      jtf.setEnabled(true);
      jtf = (JTextField)( (Hashtable)hGUI.get("guiAuthPassword") ).get("objectID");
      jtf.setEnabled(true);
      jtf = (JTextField)( (Hashtable)hGUI.get("guiAuthDomain") ).get("objectID");
      jtf.setEnabled(false);
    }

    // Digest : nothing special
    if(sval.equals("Digest")) {
      JTextField jtf = (JTextField)( (Hashtable)hGUI.get("guiAuthUser") ).get("objectID");
      jtf.setEnabled(true);
      jtf = (JTextField)( (Hashtable)hGUI.get("guiAuthPassword") ).get("objectID");
      jtf.setEnabled(true);
      jtf = (JTextField)( (Hashtable)hGUI.get("guiAuthDomain") ).get("objectID");
      jtf.setEnabled(false);
    }

    // NTLM : Reserved for Future Usage, this doesn't work... :(
    if(sval.equals("NTLM")) {
      JTextField jtf = (JTextField)( (Hashtable)hGUI.get("guiAuthUser") ).get("objectID");
      jtf.setEnabled(true);
      jtf = (JTextField)( (Hashtable)hGUI.get("guiAuthPassword") ).get("objectID");
      jtf.setEnabled(true);
      jtf = (JTextField)( (Hashtable)hGUI.get("guiAuthDomain") ).get("objectID");
      jtf.setEnabled(true);
    }

    vals.put("value", (String)jcb.getSelectedItem());
  }

  public void swgProxOnOff() {
    Hashtable<String, Object> vals = (Hashtable)hGUI.get("guiProxOnOff");
    JCheckBox jcb = (JCheckBox)vals.get("objectID");
    vals.put("value", (Boolean)jcb.isSelected());

    if(jcb.isSelected()) {  // activer les autres composants proxy

      JTextField jtf = (JTextField)( (Hashtable)hGUI.get("guiProxyname") ).get("objectID");
      jtf.setEnabled(true);
      jtf = (JTextField)( (Hashtable)hGUI.get("guiProxyport") ).get("objectID");
      jtf.setEnabled(true);
      jtf = (JTextField)( (Hashtable)hGUI.get("guiProxyuser") ).get("objectID");
      jtf.setEnabled(true);
      jtf = (JTextField)( (Hashtable)hGUI.get("guiProxypass") ).get("objectID");
      jtf.setEnabled(true);

      // cas du Raw-Request -> (des)activer le Host et le Port
      String stm = (String)( (Hashtable)hGUI.get("guiAdvancedRequest") ).get("value");

      if(stm.equals("Raw Request")) {
        JComboBox jcbb = (JComboBox)( (Hashtable)hGUI.get("guiHost") ).get("objectID") ;
        jcbb.setEnabled(false);
        jcbb = (JComboBox)( (Hashtable)hGUI.get("guiPort") ).get("objectID") ;
        jcbb.setEnabled(false);
      }
    }
    else {  // masquer les autres composants proxy

      JTextField jtf = (JTextField)( (Hashtable)hGUI.get("guiProxyname") ).get("objectID");
      jtf.setEnabled(false);
      jtf = (JTextField)( (Hashtable)hGUI.get("guiProxyport") ).get("objectID");
      jtf.setEnabled(false);
      jtf = (JTextField)( (Hashtable)hGUI.get("guiProxyuser") ).get("objectID");
      jtf.setEnabled(false);
      jtf = (JTextField)( (Hashtable)hGUI.get("guiProxypass") ).get("objectID");
      jtf.setEnabled(false);

      // cas du Raw-Request -> (des)activer le Host et le Port
      String stm = (String)( (Hashtable)hGUI.get("guiAdvancedRequest") ).get("value");

      if(stm.equals("Raw Request")) {
        JComboBox jcbb = (JComboBox)( (Hashtable)hGUI.get("guiHost") ).get("objectID") ;
        jcbb.setEnabled(true);
        jcbb = (JComboBox)( (Hashtable)hGUI.get("guiPort") ).get("objectID") ;
        jcbb.setEnabled(true);
      }
    }

  }

  /*
   * swgConnConnect vérifie le type de connexion HTTP ou HTTPS et ajuste les paramètres SSL
   * le paramétrage avancé est effectué par la pop-up FILL-IN
   * la gui SSL est différente selon le provider (ex : pas de SSLv2 pour SUN, Cipher Suites..)
   * l'ajustement des paramètres dépend de ce qui est saisi dans la pop-up et du provider
   * toutes les explications relatives aux providers sont en annexe
   */
  public void swgConnConnect() {

    // sauvegarde ancienne valeur GUi pour comparaison
    String oldconn = (String)( ((Hashtable)hGUI.get("guiConnConnect")).get("value") );

    Hashtable<String, Object> vals = (Hashtable)hGUI.get("guiConnConnect");
    JComboBox jcb = (JComboBox)vals.get("objectID");
    String sBef = (String)jcb.getSelectedItem();

    // conversion de la valeur combobox -> version SSL réelle
    String sAft = "http";

    if(!sBef.equals("http"))
      sAft = CipherSuiteUtil.convertGUIConnConnect(sBef);

    /* TO BE REMOVED
if(sBef.equals("SSL 2.0"))
      sAft = "SSLv2";

    if(sBef.equals("SSL 3.0"))
      sAft = "SSLv3";

    if(sBef.equals("TLS 1.0"))
      sAft = "TLSv1";

    if(sBef.equals("TLS 1.1"))
      sAft = "TLSv1.1";

    if(sBef.equals("TLS 1.2"))
      sAft = "TLSv1.2";*/

    /*
     * petit rappel sur les valeur de hGUI
     * hGUI.guiConnConnect = "http" || "https"
     * hGUI.provider = "IBMJSSE" || "SunJSSE_SSLv2Hello" || "SunJSSE_Strict"
     * hGUI.instance = "SSL" || "TLS" || "SSLv2" || "SSLv3" || "TLSv1"
     * hGUI.sslprotocols = "" || "SSLv2" || "SSLv3" || "TLSv1" mais pourrait contenir "SSLv2:SSLv3:TLSv1"
     */

    // mise à jour uniquement si modification de la valeur + dégager ancienne connexion
    if(!sAft.equals(oldconn)) {

      // récupération de l'objet combobox Cipher qui sera mis à jour plus tard
      Hashtable ciphz = (Hashtable)hGUI.get("guiConnCipher");
      JComboBox jciphz = (JComboBox)ciphz.get("objectID");

      if(!sAft.equals("http")) {

        // stocker les différentes cipher suites
        String[] myd = new String[0];

        // récupération du provider
        String spro = (String)( ((Hashtable)hGUI.get("provider")).get("value") );

        // cas ibm (sslinstance = sslprotocol, mais on ne doit pas spécifier le protocole)
        if(spro.equals("IBMJSSE")) {
          Hashtable<String, Object> ht = new Hashtable<String, Object>();
          ht.put("value", sAft);
          hGUI.put("instance", ht);

          ht = new Hashtable<String, Object>();
          ht.put("value", "");
          hGUI.put("sslprotocols", ht);

          //myd = CipherSuiteUtil.getCiphersByProvider("IBM");
          myd = CipherSuiteUtil.getCiphersByProvider("IBM", sAft);
        }

        // cas sun (instance=TLS, spécifier le protocole)
        if(spro.equals("SunJSSE_SSLv2Hello")) {
          Hashtable<String, Object> ht = new Hashtable<String, Object>();
          ht.put("value", "TLS");
          hGUI.put("instance", ht);

          ht = new Hashtable<String, Object>();
          ht.put("value", sAft + ":" + "SSLv2Hello");
          hGUI.put("sslprotocols", ht);

          //myd = CipherSuiteUtil.getCiphers("Sun_SSLv2Hello");
          // myd = CipherSuiteUtil.getCiphersByProvider("SUN");
          myd = CipherSuiteUtil.getCiphersByProvider("SUN", sAft);
        }

        if(spro.equals("SunJSSE_Strict")) {
          Hashtable<String, Object> ht = new Hashtable<String, Object>();
          ht.put("value", "TLS");
          hGUI.put("instance", ht);

          ht = new Hashtable<String, Object>();
          ht.put("value", sAft);
          hGUI.put("sslprotocols", ht);

          //myd = CipherSuiteUtil.getCiphers("Sun_Strict");
          // myd = CipherSuiteUtil.getCiphersByProvider("SUN");
          myd = CipherSuiteUtil.getCiphersByProvider("SUN", sAft);
        }

        // suppression temporaire des actionlisteners
        ActionListener[] alis = jciphz.getActionListeners();

        for(int i = 0; i < alis.length; i++)
          jciphz.removeActionListener(alis[i]);

        // mise à jour de la combobox
        jciphz.removeAllItems();
        // ajout de la cipher ALL en dur ici
        jciphz.addItem("ALL");

        for(int i = 0; i < myd.length; i++)
          jciphz.addItem(myd[i]);

        // remise en route de actionlistener
        for(int i = 0; i < alis.length; i++)
          jciphz.addActionListener(alis[i]);

        jciphz.setSelectedIndex(0);
        jciphz.setEnabled(true);
      }
      else {
        jciphz.setEnabled(false);
      }

      vals.put("value", sAft);
      reuseConn = false;
    }
  }

  /*
   *  gestion du combobox CipherSuite
   */
  public void swgConnCipher() {

    /*
     * 1 - WORK on the CONNECT
     * Necessary as we need to know the SSL or TLS version
     */
    Hashtable<String, Object> vals = (Hashtable)hGUI.get("guiConnConnect");
    JComboBox jcb = (JComboBox)vals.get("objectID");
    String sBef = (String)jcb.getSelectedItem();

    // conversion de la valeur combobox -> version SSL réelle
    String sslversion = "http";

    if(!sBef.equals("http"))
      sslversion = CipherSuiteUtil.convertGUIConnConnect(sBef);

    /* 2 - WORK on the cipher itself, did it change ? */
    //Hashtable<String, Object> vals = (Hashtable)hGUI.get("guiConnCipher");
    //JComboBox jcb = (JComboBox)vals.get("objectID");
    vals = (Hashtable)hGUI.get("guiConnCipher");
    jcb = (JComboBox)vals.get("objectID");

    // récupérer l'ancienne valeur sélectionnée et la nouvelle pour le filtrage suivant
    String oldciph = (String)(vals.get("value"));
    String sVal = (String)jcb.getSelectedItem();

    // filtrage des événements où il n'y a pas eu de changement réel de la sélection
    if(!oldciph.equals(sVal)) {
      // cas où on l'on veut toutes les ciphers ( = "ALL" ), il faut créer la String avec le séparateur ":"
      if(sVal.equals("ALL")) {
        String[] myd = new String[0];
        // récupération du provider
        String spro = (String)( ((Hashtable)hGUI.get("provider")).get("value") );

        if(spro.equals("SunJSSE_Strict"))
          myd = CipherSuiteUtil.getCiphersByProvider("SUN", sslversion);

        if(spro.equals("SunJSSE_SSLv2Hello"))
          myd = CipherSuiteUtil.getCiphersByProvider("SUN", sslversion);

        if(spro.equals("IBMJSSE"))
          myd = CipherSuiteUtil.getCiphersByProvider("IBM", sslversion);

        // construction de la chaîne "ciph1:..:ciphN"
        sVal = "";
        StringBuffer sbuf = new StringBuffer();

        for(int i = 0; i < myd.length - 1; i++)
          sbuf.append(myd[i] + ":");

        sbuf.append(myd[myd.length - 1]);
        sVal = sbuf.toString();
      }

      vals.put("value", sVal);
      reuseConn = false;
    }
  }

  /*
   * la combobox 'paramètres avancés' interagit avec les autres composants de la GUi
   * selon le cas on doit (dés)activer certains composants
   */
  public void swgAdvList() {
    Hashtable<String, Object> vals = (Hashtable)hGUI.get("guiAdvancedRequest");
    JComboBox jcb = (JComboBox)vals.get("objectID");
    String sVal = (String)jcb.getSelectedItem();
    vals.put("value", sVal);

    // EN COURS

    // (des)activation des composants de la GUi
    if(sVal.equals("Disabled")) {
      JTextArea jta = (JTextArea)( (Hashtable)hGUI.get("guiAdvanced") ).get("objectID") ;
      jta.setEnabled(false);
      JComboBox jcbb = (JComboBox)( (Hashtable)hGUI.get("guiMethod") ).get("objectID") ;
      jcbb.setEnabled(true);
      jcbb = (JComboBox)( (Hashtable)hGUI.get("guiHost") ).get("objectID") ;
      jcbb.setEnabled(true);
      jcbb = (JComboBox)( (Hashtable)hGUI.get("guiPort") ).get("objectID") ;
      jcbb.setEnabled(true);
      jcbb = (JComboBox)( (Hashtable)hGUI.get("guiVersion") ).get("objectID") ;
      jcbb.setEnabled(true);
      jcbb = (JComboBox)( (Hashtable)hGUI.get("guiPath") ).get("objectID") ;
      jcbb.setEnabled(true);
      jcbb = (JComboBox)( (Hashtable)hGUI.get("guiAuthMethod") ).get("objectID") ;
      jcbb.setEnabled(true);
    }

    if(sVal.equals("Add Headers")) {
      JTextArea jta = (JTextArea)( (Hashtable)hGUI.get("guiAdvanced") ).get("objectID") ;
      jta.setEnabled(true);
      JComboBox jcbb = (JComboBox)( (Hashtable)hGUI.get("guiMethod") ).get("objectID") ;
      jcbb.setEnabled(true);
      jcbb = (JComboBox)( (Hashtable)hGUI.get("guiHost") ).get("objectID") ;
      jcbb.setEnabled(true);
      jcbb = (JComboBox)( (Hashtable)hGUI.get("guiPort") ).get("objectID") ;
      jcbb.setEnabled(true);
      jcbb = (JComboBox)( (Hashtable)hGUI.get("guiVersion") ).get("objectID") ;
      jcbb.setEnabled(true);
      jcbb = (JComboBox)( (Hashtable)hGUI.get("guiPath") ).get("objectID") ;
      jcbb.setEnabled(true);
      jcbb = (JComboBox)( (Hashtable)hGUI.get("guiAuthMethod") ).get("objectID") ;
      jcbb.setEnabled(true);
    }

    if(sVal.equals("Add Body")) {
      JTextArea jta = (JTextArea)( (Hashtable)hGUI.get("guiAdvanced") ).get("objectID") ;
      jta.setEnabled(true);
      JComboBox jcbb = (JComboBox)( (Hashtable)hGUI.get("guiMethod") ).get("objectID") ;
      jcbb.setEnabled(true);
      jcbb = (JComboBox)( (Hashtable)hGUI.get("guiHost") ).get("objectID") ;
      jcbb.setEnabled(true);
      jcbb = (JComboBox)( (Hashtable)hGUI.get("guiPort") ).get("objectID") ;
      jcbb.setEnabled(true);
      jcbb = (JComboBox)( (Hashtable)hGUI.get("guiVersion") ).get("objectID") ;
      jcbb.setEnabled(true);
      jcbb = (JComboBox)( (Hashtable)hGUI.get("guiPath") ).get("objectID") ;
      jcbb.setEnabled(true);
      jcbb = (JComboBox)( (Hashtable)hGUI.get("guiAuthMethod") ).get("objectID") ;
      jcbb.setEnabled(true);
    }

    if(sVal.equals("Add Headers & Body")) {
      JTextArea jta = (JTextArea)( (Hashtable)hGUI.get("guiAdvanced") ).get("objectID") ;
      jta.setEnabled(true);
      JComboBox jcbb = (JComboBox)( (Hashtable)hGUI.get("guiMethod") ).get("objectID") ;
      jcbb.setEnabled(true);
      jcbb = (JComboBox)( (Hashtable)hGUI.get("guiHost") ).get("objectID") ;
      jcbb.setEnabled(true);
      jcbb = (JComboBox)( (Hashtable)hGUI.get("guiPort") ).get("objectID") ;
      jcbb.setEnabled(true);
      jcbb = (JComboBox)( (Hashtable)hGUI.get("guiVersion") ).get("objectID") ;
      jcbb.setEnabled(true);
      jcbb = (JComboBox)( (Hashtable)hGUI.get("guiPath") ).get("objectID") ;
      jcbb.setEnabled(true);
      jcbb = (JComboBox)( (Hashtable)hGUI.get("guiAuthMethod") ).get("objectID") ;
      jcbb.setEnabled(true);
    }

    if(sVal.equals("Raw Request")) {
      JTextArea jta = (JTextArea)( (Hashtable)hGUI.get("guiAdvanced") ).get("objectID") ;
      jta.setEnabled(true);
      JComboBox jcbb = (JComboBox)( (Hashtable)hGUI.get("guiMethod") ).get("objectID") ;
      jcbb.setEnabled(false);
      jcbb = (JComboBox)( (Hashtable)hGUI.get("guiHost") ).get("objectID") ;
      jcbb.setEnabled(true);
      jcbb = (JComboBox)( (Hashtable)hGUI.get("guiPort") ).get("objectID") ;
      jcbb.setEnabled(true);
      jcbb = (JComboBox)( (Hashtable)hGUI.get("guiVersion") ).get("objectID") ;
      jcbb.setEnabled(false);
      jcbb = (JComboBox)( (Hashtable)hGUI.get("guiPath") ).get("objectID") ;
      jcbb.setEnabled(false);
      jcbb = (JComboBox)( (Hashtable)hGUI.get("guiAuthMethod") ).get("objectID") ;
      jcbb.setEnabled(false);

      // vérification sur l'utilisation du proxy
      Boolean bProxy = (Boolean)( (Hashtable)hGUI.get("guiProxOnOff") ).get("value");

      if(bProxy) {
        jcbb = (JComboBox)( (Hashtable)hGUI.get("guiHost") ).get("objectID") ;
        jcbb.setEnabled(false);
        jcbb = (JComboBox)( (Hashtable)hGUI.get("guiPort") ).get("objectID") ;
        jcbb.setEnabled(false);
      }
      else {
        jcbb = (JComboBox)( (Hashtable)hGUI.get("guiHost") ).get("objectID") ;
        jcbb.setEnabled(true);
        jcbb = (JComboBox)( (Hashtable)hGUI.get("guiPort") ).get("objectID") ;
        jcbb.setEnabled(true);
      }
    }

  }

  // EN COURS : gestion de la gui ici pour griser/valider le "see last cert"
  public void swgGo() {

    // booleen indiquant si les headers liés au body doivent être positionnés automatiquement
    boolean setBodyHeaders = false;

    // booleen indiquant si la gui indique de reutiliser la dernière connexion
    // si utilisation d'un proxy -> aucune modif proxy, si pas de proxy -> aucune modif serveur
    boolean reuseConn2 = true;

    // le GO dépend d'abord des options de 'AdvancedRequest'
    String sAdv = (String)( (Hashtable)hGUI.get("guiAdvancedRequest") ).get("value");

    // suppression du résidu --sslservercheckup si besoin
    hFast.put("-sslservercheckup", false);
    // suppression du résidu --digest si besoin
    hFast.put("-digest", false);
    // suppression du résidu --ntlm si besoin
    hFast.put("-ntlm", false);
    // récupération des timestamps si nécessaire (commun à tous les scénarios)
    hFast.put("-htmlstamps", (Boolean)(hGUI.get("htmlstamps")) );
    hFast.put("-netstamps", (Boolean)(hGUI.get("netstamps")) );
    hFast.put("-resolvedns", (Boolean)(hGUI.get("resolvedns")) );

    hFast.put("-raw", (Boolean)(hGUI.get("raw")) );

    hFast.put("-exportcert", false);

    // TO REMOVE hFast.put("-netstamps", (Boolean)(hGUI.get("netstamps")) );
    // suppression du résidu --proxyauth si besoin
    hFast.put("-proxyauth", false);
    // positionner le paramètre CRLF : aucun en mode GUI
    hFast.put("-lf2crlf", false);
    hFast.put("-crlf2lf", false);

    // flag pour activer/desactiver la GUI 'ssl last certificate'
    boolean flagSSL = false;

    // use UnsecureRandom ?
    hFast.put("-useunsecurerandom", (Boolean)(hGUI.get("unsecurerandom")) );

    // cas 'Disabled' (il y a encore des choses qui restent simples ;)
    if(sAdv.equals("Disabled")) {

      // suppression des résidus provenant des requêtes précédentes si besoin
      hFast.put("headers", new String[0]);

      // utilisation des cookies : on reprend la configuration indiquée par la GUi
      hFast.put("cookiesupport", (Hashtable)hGUI.get("cookiesupport"));

      // mémorisation des headers éventuels (Authorization,..)
      String tmpHeaders = "";
      // iCaseH indique la configuration des headers qui sera positionnée
      int iCaseH = 0;

      if( ((String)((Hashtable)hGUI.get("guiVersion")).get("value")).equals("HTTP/1.1") )
        iCaseH += 1;

      // supprimer les autres résidus lorsque nécessaire (body..)
      if(hFast.containsKey("request-body"))
        hFast.remove("request-body");

      if(hFast.containsKey("user"))
        hFast.remove("user");

      if(hFast.containsKey("password"))
        hFast.remove("password");

      if(hFast.containsKey("ntlmuser"))
        hFast.remove("ntlmuser");

      if(hFast.containsKey("ntlmpassword"))
        hFast.remove("ntlmpassword");

      if(hFast.containsKey("ntlmdomain"))
        hFast.remove("ntlmdomain");

      Boolean bFol = (Boolean)( hGUI.get("-follow") );
      hFast.put("-follow", bFol);

      hFast.put("guiMethod", (String)((Hashtable)hGUI.get("guiMethod")).get("value"));

      hFast.put("guiHost", (String)((Hashtable)hGUI.get("guiHost")).get("value"));

      hFast.put("guiPort", (String)((Hashtable)hGUI.get("guiPort")).get("value"));

      hFast.put("guiVersion", (String)((Hashtable)hGUI.get("guiVersion")).get("value"));

      hFast.put("guiPath", (String)((Hashtable)hGUI.get("guiPath")).get("value"));

      // authentification client ?
      String sAuth = (String)( (Hashtable)hGUI.get("guiAuthMethod") ).get("value");

      if(sAuth.equals("Basic")) {
        String sDomain, sLogin, sPassword;
        JTextField jtf;
        JPasswordField jpf;

        // récupération des champs dans la GUi
        jtf = (JTextField)( (Hashtable)hGUI.get("guiAuthUser") ).get("objectID");
        sLogin = jtf.getText();
        jpf = (JPasswordField)( (Hashtable)hGUI.get("guiAuthPassword") ).get("objectID");
        sPassword = new String(jpf.getPassword());

        // encodage Base64
        tmpHeaders += RFC2617.toBasicCredentials(sLogin, sPassword);
        iCaseH += 2;
      }

      if(sAuth.equals("Digest")) {
        String sLogin, sPassword;
        JTextField jtf;
        JPasswordField jpf;

        // récupération des champs dans la GUi
        jtf = (JTextField)( (Hashtable)hGUI.get("guiAuthUser") ).get("objectID");
        sLogin = jtf.getText();
        jpf = (JPasswordField)( (Hashtable)hGUI.get("guiAuthPassword") ).get("objectID");
        sPassword = new String(jpf.getPassword());

        // store in hFast & set directive -digest
        hFast.put("user", sLogin);
        hFast.put("password", sPassword);
        hFast.put("-digest", true);
      }

      if(sAuth.equals("NTLM")) {
        String sLogin, sPassword, sDomain;
        JTextField jtf;
        JPasswordField jpf;

        // récupération des champs dans la GUi
        jtf = (JTextField)( (Hashtable)hGUI.get("guiAuthUser") ).get("objectID");
        sLogin = jtf.getText();
        jpf = (JPasswordField)( (Hashtable)hGUI.get("guiAuthPassword") ).get("objectID");
        sPassword = new String(jpf.getPassword());
        jtf = (JTextField)( (Hashtable)hGUI.get("guiAuthDomain") ).get("objectID");
        sDomain = new String(jtf.getText());

        // store in hFast & set directive -ntlm
        hFast.put("ntlmuser", sLogin);
        hFast.put("ntlmpassword", sPassword);
        hFast.put("ntlmdomain", sDomain);
        hFast.put("-ntlm", true);
      }

      // type de connexion ?
      String sConn = (String)( (Hashtable)hGUI.get("guiConnConnect") ).get("value");
      hFast.put("guiConnConnect", sConn);

      if(!sConn.equals("http")) {
        // traitement des sslprotocols
        hFast.put("sslprotocols", (String)( (Hashtable)hGUI.get("sslprotocols") ).get("value") );

        // traitement des ciphers
        hFast.put("ciphers", (String)( (Hashtable)hGUI.get("guiConnCipher") ).get("value"));

        // config SSL
        String spro = (String)( (Hashtable)hGUI.get("provider") ).get("value");

        if(spro.equals("SunJSSE_Strict"))
          hFast.put("provider", "SunJSSE");

        if(spro.equals("SunJSSE_SSLv2Hello"))
          hFast.put("provider", "SunJSSE");

        if(spro.equals("IBMJSSE"))
          hFast.put("provider", "IBMJSSE");

        String sinstance = (String)( (Hashtable)hGUI.get("instance") ).get("value");
        hFast.put("instance", sinstance);

        // trustmanager
        hFast.put("trustmanager", (TrustManager[])(((Hashtable)hGUI.get("trustmanager")).get("value")) );

        flagSSL = true;

        // TO DO : traitement cert client
      }

      // utilisation proxy ?
      Boolean blnProx = (Boolean)( (Hashtable)hGUI.get("guiProxOnOff") ).get("value");
      String spr1 = "", spr2 = "", spr3 = "", spr4 = "";

      if(blnProx) {
        JTextField jtf = (JTextField)( (Hashtable)hGUI.get("guiProxyname") ).get("objectID");
        spr1 = jtf.getText();
        jtf = (JTextField)( (Hashtable)hGUI.get("guiProxyport") ).get("objectID");
        spr2 = jtf.getText();
        jtf = (JTextField)( (Hashtable)hGUI.get("guiProxyuser") ).get("objectID");
        spr3 = jtf.getText();
        JPasswordField jpf = (JPasswordField)( (Hashtable)hGUI.get("guiProxypass") ).get("objectID");
        spr4 = new String(jpf.getPassword());

        // lastHost mémorise les paramètres proxy ET serveur
        reuseConn2 = (lastHost.equals("PROXY_" + spr1 + spr2 + "_SERVER_" + (String)hFast.get("guiHost") + (String)hFast.get("guiPort"))) ? true : false;
        lastHost = "PROXY_" + spr1 + spr2 + "_SERVER_" + (String)hFast.get("guiHost") + (String)hFast.get("guiPort");
      }
      else {
        // lastHost mémorise les paramètres serveur
        reuseConn2 = (lastHost.equals("SERVER_" + (String)hFast.get("guiHost") + (String)hFast.get("guiPort"))) ? true : false;
        lastHost = "SERVER_" + (String)hFast.get("guiHost") + (String)hFast.get("guiPort");
      }

      hFast.put("guiProxyname", spr1);
      hFast.put("guiProxyport", spr2);
      hFast.put("guiProxyuser", spr3);
      hFast.put("guiProxypass", spr4);

      // directive pour le scenario d'authentification proxy
      if( !(spr3 + spr4).equals("") )
        hFast.put("-proxyauth", true);

      // rajout des headers récoltés pendant le traitement précédent
      switch(iCaseH) {
        case 1:
          hFast.put("headers", new String[] {"Host: " + (String)((Hashtable)hGUI.get("guiHost")).get("value") } );
          break;

        case 2:
          hFast.put("headers", new String[] {"Authorization: " + tmpHeaders } );
          //hFast.put("headers", new String[] {"Authorization: " + tmpHeaders + "==" } );
          break;

        case 3:
          hFast.put("headers", new String[] {"Host: " + (String)((Hashtable)hGUI.get("guiHost")).get("value"), "Authorization: " + tmpHeaders } );
          //hFast.put("headers", new String[] {"Host: " + (String)((Hashtable)hGUI.get("guiHost")).get("value"), "Authorization: " + tmpHeaders + "==" } );
          break;
      }

    }

    // cas 'Add Headers'
    // traitement identique au cas précédent + traitement des headers supplémentaires
    if(sAdv.equals("Add Headers")) {

      // suppression des résidus provenant des requêtes précédentes si besoin
      hFast.put("headers", new String[0]);

      // utilisation des cookies : inhibition de la configuration indiquée par la GUi, mais on préserve les cookies pour les requêtes ultérieures
      hFast.put("cookiesupport", (Hashtable)hGUI.get("cookiesupport"));

      // mémorisation des headers éventuels (Authorization,..)
      String tmpHeaders = "";
      // iCaseH indique la configuration des headers qui sera positionnée
      int iCaseH = 0;

      if( ((String)((Hashtable)hGUI.get("guiVersion")).get("value")).equals("HTTP/1.1") )
        iCaseH += 1;

      // supprimer les autres résidus lorsque nécessaire (body..)
      if(hFast.containsKey("request-body"))
        hFast.remove("request-body");

      if(hFast.containsKey("user"))
        hFast.remove("user");

      if(hFast.containsKey("password"))
        hFast.remove("password");

      if(hFast.containsKey("ntlmuser"))
        hFast.remove("ntlmuser");

      if(hFast.containsKey("ntlmpassword"))
        hFast.remove("ntlmpassword");

      if(hFast.containsKey("ntlmdomain"))
        hFast.remove("ntlmdomain");

      Boolean bFol = (Boolean)( hGUI.get("-follow") );
      hFast.put("-follow", bFol);

      hFast.put("guiMethod", (String)((Hashtable)hGUI.get("guiMethod")).get("value"));

      hFast.put("guiHost", (String)((Hashtable)hGUI.get("guiHost")).get("value"));

      hFast.put("guiPort", (String)((Hashtable)hGUI.get("guiPort")).get("value"));

      hFast.put("guiVersion", (String)((Hashtable)hGUI.get("guiVersion")).get("value"));

      hFast.put("guiPath", (String)((Hashtable)hGUI.get("guiPath")).get("value"));

      // authentification client ?
      String sAuth = (String)( (Hashtable)hGUI.get("guiAuthMethod") ).get("value");

      if(sAuth.equals("Basic")) {
        String sDomain, sLogin, sPassword;
        JTextField jtf;
        JPasswordField jpf;

        // récupération des champs dans la GUi
        jtf = (JTextField)( (Hashtable)hGUI.get("guiAuthUser") ).get("objectID");
        sLogin = jtf.getText();
        jpf = (JPasswordField)( (Hashtable)hGUI.get("guiAuthPassword") ).get("objectID");
        sPassword = new String(jpf.getPassword());

        // encodage Base64
        tmpHeaders += RFC2617.toBasicCredentials(sLogin, sPassword);
        iCaseH += 2;
      }

      if(sAuth.equals("Digest")) {
        String sLogin, sPassword;
        JTextField jtf;
        JPasswordField jpf;
        // récupération des champs dans la GUi
        jtf = (JTextField)( (Hashtable)hGUI.get("guiAuthUser") ).get("objectID");
        sLogin = jtf.getText();
        jpf = (JPasswordField)( (Hashtable)hGUI.get("guiAuthPassword") ).get("objectID");
        sPassword = new String(jpf.getPassword());
        // store in hFast & set directive -digest
        hFast.put("user", sLogin);
        hFast.put("password", sPassword);
        hFast.put("-digest", true);
      }

      if(sAuth.equals("NTLM")) {
        String sLogin, sPassword, sDomain;
        JTextField jtf;
        JPasswordField jpf;
        // récupération des champs dans la GUi
        jtf = (JTextField)( (Hashtable)hGUI.get("guiAuthUser") ).get("objectID");
        sLogin = jtf.getText();
        jpf = (JPasswordField)( (Hashtable)hGUI.get("guiAuthPassword") ).get("objectID");
        sPassword = new String(jpf.getPassword());
        jtf = (JTextField)( (Hashtable)hGUI.get("guiAuthDomain") ).get("objectID");
        sDomain = jtf.getText();
        // store in hFast & set directive -digest
        hFast.put("ntlmuser", sLogin);
        hFast.put("ntlmpassword", sPassword);
        hFast.put("ntlmdomain", sDomain);
        hFast.put("-ntlm", true);
      }

      // type de connexion ?
      String sConn = (String)( (Hashtable)hGUI.get("guiConnConnect") ).get("value");
      hFast.put("guiConnConnect", sConn);

      if(!sConn.equals("http")) {
        // traitement des sslprotocols
        hFast.put("sslprotocols", (String)( (Hashtable)hGUI.get("sslprotocols") ).get("value") );

        // traitement des ciphers
        hFast.put("ciphers", (String)( (Hashtable)hGUI.get("guiConnCipher") ).get("value"));

        // config SSL
        String spro = (String)( (Hashtable)hGUI.get("provider") ).get("value");

        if(spro.equals("SunJSSE_Strict"))
          hFast.put("provider", "SunJSSE");

        if(spro.equals("SunJSSE_SSLv2Hello"))
          hFast.put("provider", "SunJSSE");

        if(spro.equals("IBMJSSE"))
          hFast.put("provider", "IBMJSSE");

        String sinstance = (String)( (Hashtable)hGUI.get("instance") ).get("value");
        hFast.put("instance", sinstance);

        // trustmanager
        hFast.put("trustmanager", (TrustManager[])(((Hashtable)hGUI.get("trustmanager")).get("value")) );

        flagSSL = true;
        // TO DO : traitement cert client
      }

      // utilisation proxy ?
      Boolean blnProx = (Boolean)( (Hashtable)hGUI.get("guiProxOnOff") ).get("value");
      String spr1 = "", spr2 = "", spr3 = "", spr4 = "";

      if(blnProx) {
        JTextField jtf = (JTextField)( (Hashtable)hGUI.get("guiProxyname") ).get("objectID");
        spr1 = jtf.getText();
        jtf = (JTextField)( (Hashtable)hGUI.get("guiProxyport") ).get("objectID");
        spr2 = jtf.getText();
        jtf = (JTextField)( (Hashtable)hGUI.get("guiProxyuser") ).get("objectID");
        spr3 = jtf.getText();
        JPasswordField jpf = (JPasswordField)( (Hashtable)hGUI.get("guiProxypass") ).get("objectID");
        spr4 = new String(jpf.getPassword());

        // lastHost mémorise les paramètres proxy ET serveur
        reuseConn2 = (lastHost.equals("PROXY_" + spr1 + spr2 + "_SERVER_" + (String)hFast.get("guiHost") + (String)hFast.get("guiPort"))) ? true : false;
        lastHost = "PROXY_" + spr1 + spr2 + "_SERVER_" + (String)hFast.get("guiHost") + (String)hFast.get("guiPort");
      }
      else {
        // lastHost mémorise les paramètres serveur
        reuseConn2 = (lastHost.equals("SERVER_" + (String)hFast.get("guiHost") + (String)hFast.get("guiPort"))) ? true : false;
        lastHost = "SERVER_" + (String)hFast.get("guiHost") + (String)hFast.get("guiPort");
      }

      hFast.put("guiProxyname", spr1);
      hFast.put("guiProxyport", spr2);
      hFast.put("guiProxyuser", spr3);
      hFast.put("guiProxypass", spr4);

      // directive pour le scenario d'authentification proxy
      if( !(spr3 + spr4).equals("") )
        hFast.put("-proxyauth", true);

      // spécifité de ce cas : traitement des headers
      JTextArea jta = (JTextArea)( (Hashtable)hGUI.get("guiAdvanced") ).get("objectID");
      String shea = jta.getText();

      // remarque importante : on considère que la String saisie contient un name/value par ligne
      // pour les cas plus complexes, l'util devra utiliser l'option 'Raw Request'
      // rappel : lors de la saisie, la nouvelle ligne correspond à \n quelque soit la plateforme
      String[] sh = shea.split("\n");
      String cleanSH = "";

      for(int i = 0; i < sh.length; i++) {
        int iindex = sh[i].indexOf(":");

        /* on effectue un minimum de vérification syntaxique
         *  1 - présence de ":"
         *  2 - supression des lignes vides
         */
        if(iindex > 0) {
          cleanSH += sh[i] + RFCUtil.CRLF;
        }
      }

      // rajout des headers récoltés pendant le traitement précédent
      switch(iCaseH) {
        case 1:
          cleanSH += "Host: " + (String)((Hashtable)hGUI.get("guiHost")).get("value") + RFCUtil.CRLF;
          break;

        case 2:
          cleanSH += "Authorization: " + tmpHeaders + RFCUtil.CRLF;
          //cleanSH += "Authorization: " + tmpHeaders + "=="  + RFCUtil.  ;
          break;

        case 3:
          cleanSH += "Host: " + (String)((Hashtable)hGUI.get("guiHost")).get("value") + RFCUtil.CRLF;
          cleanSH += "Authorization: " + tmpHeaders + RFCUtil.CRLF;
          //cleanSH += "Authorization: " + tmpHeaders + "==" + RFCUtil.CRLF;
          break;
      }

      // store the headers in hFast (String[])
      if(cleanSH.length() > 0)
        hFast.put("headers", cleanSH.split(RFCUtil.CRLF));

    }

    // cas 'Add Body'
    if(sAdv.equals("Add Body")) {

      // suppression des résidus provenant des requêtes précédentes si besoin
      hFast.put("headers", new String[0]);

      // utilisation des cookies : on reprend la configuration indiquée par la GUi
      hFast.put("cookiesupport", (Hashtable)hGUI.get("cookiesupport"));

      // supprimer les autres résidus lorsque nécessaire (body..)
      if(hFast.containsKey("request-body"))
        hFast.remove("request-body");

      if(hFast.containsKey("user"))
        hFast.remove("user");

      if(hFast.containsKey("password"))
        hFast.remove("password");

      if(hFast.containsKey("ntlmuser"))
        hFast.remove("ntlmuser");

      if(hFast.containsKey("ntlmpassword"))
        hFast.remove("ntlmpassword");

      if(hFast.containsKey("ntlmdomain"))
        hFast.remove("ntlmdomain");

      // mémorisation des headers éventuels (Authorization,..)
      String tmpHeaders = "";
      // iCaseH indique la configuration des headers qui sera positionnée
      int iCaseH = 0;

      if( ((String)((Hashtable)hGUI.get("guiVersion")).get("value")).equals("HTTP/1.1") )
        iCaseH += 1;

      // partie commune à la gestion des headers
      Boolean bFol = (Boolean)( hGUI.get("-follow") );
      hFast.put("-follow", bFol);

      hFast.put("guiMethod", (String)((Hashtable)hGUI.get("guiMethod")).get("value"));

      hFast.put("guiHost", (String)((Hashtable)hGUI.get("guiHost")).get("value"));

      hFast.put("guiPort", (String)((Hashtable)hGUI.get("guiPort")).get("value"));

      hFast.put("guiVersion", (String)((Hashtable)hGUI.get("guiVersion")).get("value"));

      hFast.put("guiPath", (String)((Hashtable)hGUI.get("guiPath")).get("value"));

      // authentification client ?
      String sAuth = (String)( (Hashtable)hGUI.get("guiAuthMethod") ).get("value");

      if(sAuth.equals("Basic")) {
        String sDomain, sLogin, sPassword;
        JTextField jtf;
        JPasswordField jpf;

        // récupération des champs dans la GUi
        jtf = (JTextField)( (Hashtable)hGUI.get("guiAuthUser") ).get("objectID");
        sLogin = jtf.getText();
        jpf = (JPasswordField)( (Hashtable)hGUI.get("guiAuthPassword") ).get("objectID");
        sPassword = new String(jpf.getPassword());

        // encodage Base64
        tmpHeaders += RFC2617.toBasicCredentials(sLogin, sPassword);
        iCaseH += 2;
      }

      if(sAuth.equals("Digest")) {
        String sLogin, sPassword;
        JTextField jtf;
        JPasswordField jpf;

        // récupération des champs dans la GUi
        jtf = (JTextField)( (Hashtable)hGUI.get("guiAuthUser") ).get("objectID");
        sLogin = jtf.getText();
        jpf = (JPasswordField)( (Hashtable)hGUI.get("guiAuthPassword") ).get("objectID");
        sPassword = new String(jpf.getPassword());

        // store in hFast & set directive -digest
        hFast.put("user", sLogin);
        hFast.put("password", sPassword);
        hFast.put("-digest", true);
      }

      if(sAuth.equals("NTLM")) {
        String sLogin, sPassword, sDomain;
        JTextField jtf;
        JPasswordField jpf;
        // récupération des champs dans la GUi
        jtf = (JTextField)( (Hashtable)hGUI.get("guiAuthUser") ).get("objectID");
        sLogin = jtf.getText();
        jpf = (JPasswordField)( (Hashtable)hGUI.get("guiAuthPassword") ).get("objectID");
        sPassword = new String(jpf.getPassword());
        jtf = (JTextField)( (Hashtable)hGUI.get("guiAuthDomain") ).get("objectID");
        sDomain = jtf.getText();
        // store in hFast & set directive -digest
        hFast.put("ntlmuser", sLogin);
        hFast.put("ntlmpassword", sPassword);
        hFast.put("ntlmdomain", sDomain);
        hFast.put("-ntlm", true);
      }

      // type de connexion ?
      String sConn = (String)( (Hashtable)hGUI.get("guiConnConnect") ).get("value");
      hFast.put("guiConnConnect", sConn);

      if(!sConn.equals("http")) {
        // traitement des sslprotocols
        hFast.put("sslprotocols", (String)( (Hashtable)hGUI.get("sslprotocols") ).get("value") );

        // traitement des ciphers
        hFast.put("ciphers", (String)( (Hashtable)hGUI.get("guiConnCipher") ).get("value"));

        // config SSL
        String spro = (String)( (Hashtable)hGUI.get("provider") ).get("value");

        if(spro.equals("SunJSSE_Strict"))
          hFast.put("provider", "SunJSSE");

        if(spro.equals("SunJSSE_SSLv2Hello"))
          hFast.put("provider", "SunJSSE");

        if(spro.equals("IBMJSSE"))
          hFast.put("provider", "IBMJSSE");

        String sinstance = (String)( (Hashtable)hGUI.get("instance") ).get("value");
        hFast.put("instance", sinstance);

        // trustmanager
        hFast.put("trustmanager", (TrustManager[])(((Hashtable)hGUI.get("trustmanager")).get("value")) );

        flagSSL = true;
        // TO DO : traitement cert client
      }

      // utilisation proxy ?
      Boolean blnProx = (Boolean)( (Hashtable)hGUI.get("guiProxOnOff") ).get("value");
      String spr1 = "", spr2 = "", spr3 = "", spr4 = "";

      if(blnProx) {
        JTextField jtf = (JTextField)( (Hashtable)hGUI.get("guiProxyname") ).get("objectID");
        spr1 = jtf.getText();
        jtf = (JTextField)( (Hashtable)hGUI.get("guiProxyport") ).get("objectID");
        spr2 = jtf.getText();
        jtf = (JTextField)( (Hashtable)hGUI.get("guiProxyuser") ).get("objectID");
        spr3 = jtf.getText();
        JPasswordField jpf = (JPasswordField)( (Hashtable)hGUI.get("guiProxypass") ).get("objectID");
        spr4 = new String(jpf.getPassword());

        // lastHost mémorise les paramètres proxy ET serveur
        reuseConn2 = (lastHost.equals("PROXY_" + spr1 + spr2 + "_SERVER_" + (String)hFast.get("guiHost") + (String)hFast.get("guiPort"))) ? true : false;
        lastHost = "PROXY_" + spr1 + spr2 + "_SERVER_" + (String)hFast.get("guiHost") + (String)hFast.get("guiPort");
      }
      else {
        // lastHost mémorise les paramètres serveur
        reuseConn2 = (lastHost.equals("SERVER_" + (String)hFast.get("guiHost") + (String)hFast.get("guiPort"))) ? true : false;
        lastHost = "SERVER_" + (String)hFast.get("guiHost") + (String)hFast.get("guiPort");
      }

      hFast.put("guiProxyname", spr1);
      hFast.put("guiProxyport", spr2);
      hFast.put("guiProxyuser", spr3);
      hFast.put("guiProxypass", spr4);

      // directive pour le scenario d'authentification proxy
      if( !(spr3 + spr4).equals("") )
        hFast.put("-proxyauth", true);

      // partie spécifique à la gestion du body
      // vérification du paramétrage du header Content-Length en automatique ?

      // positionnement du header Content-Type => en dur dans initHTTPProcess()

      // récupération du request-body indiqué dans la GUi et conversion des \n => \r\n
      JTextArea jta = (JTextArea)( (Hashtable)hGUI.get("guiAdvanced") ).get("objectID");
      String shea = jta.getText();
      String cleanSH = shea.replace("\n", RFCUtil.CRLF);

      // positionnement du body en question
      hFast.put("request-body", cleanSH.getBytes());

      // rajout des headers récoltés pendant le traitement précédent
      cleanSH = "";

      switch(iCaseH) {
        case 1:
          cleanSH += "Host: " + (String)((Hashtable)hGUI.get("guiHost")).get("value") + RFCUtil.CRLF;
          break;

        case 2:
          cleanSH += "Authorization: " + tmpHeaders + RFCUtil.CRLF;
          //cleanSH += "Authorization: " + tmpHeaders + "=="  + RFCUtil.CRLF;
          break;

        case 3:
          cleanSH += "Host: " + (String)((Hashtable)hGUI.get("guiHost")).get("value") + RFCUtil.CRLF;
          cleanSH += "Authorization: " + tmpHeaders + RFCUtil.CRLF;
          //cleanSH += "Authorization: " + tmpHeaders + "==" + RFCUtil.CRLF;
          break;
      }

      // store the headers in hFast (String[])
      if(cleanSH.length() > 0) {
        hFast.put("headers", cleanSH.split(RFCUtil.CRLF));
        // positionnement des headers liés à la présence du body par défaut
        // Content-Length + Content-Type
        setBodyHeaders = true;
      }
    }

    // cas 'Add Headers & Body'
    if(sAdv.equals("Add Headers & Body")) {

      // suppression des résidus provenant des requêtes précédentes si besoin
      hFast.put("headers", new String[0]);

      // utilisation des cookies : inhibition de la configuration indiquée par la GUi, mais on préserve les cookies pour les requêtes ultérieures
      hFast.put("cookiesupport", (Hashtable)hGUI.get("cookiesupport"));

      // supprimer les autres résidus lorsque nécessaire (body..)
      if(hFast.containsKey("request-body"))
        hFast.remove("request-body");

      if(hFast.containsKey("user"))
        hFast.remove("user");

      if(hFast.containsKey("password"))
        hFast.remove("password");

      if(hFast.containsKey("ntlmuser"))
        hFast.remove("ntlmuser");

      if(hFast.containsKey("ntlmpassword"))
        hFast.remove("ntlmpassword");

      if(hFast.containsKey("ntlmdomain"))
        hFast.remove("ntlmdomain");

      // mémorisation des headers éventuels (Authorization,..)
      String tmpHeaders = "";
      // iCaseH indique la configuration des headers qui sera positionnée
      int iCaseH = 0;

      if( ((String)((Hashtable)hGUI.get("guiVersion")).get("value")).equals("HTTP/1.1") )
        iCaseH += 1;

      // partie commune à la gestion des headers
      Boolean bFol = (Boolean)( hGUI.get("-follow") );
      hFast.put("-follow", bFol);

      hFast.put("guiMethod", (String)((Hashtable)hGUI.get("guiMethod")).get("value"));

      hFast.put("guiHost", (String)((Hashtable)hGUI.get("guiHost")).get("value"));

      hFast.put("guiPort", (String)((Hashtable)hGUI.get("guiPort")).get("value"));

      hFast.put("guiVersion", (String)((Hashtable)hGUI.get("guiVersion")).get("value"));

      hFast.put("guiPath", (String)((Hashtable)hGUI.get("guiPath")).get("value"));

      // authentification client ?
      String sAuth = (String)( (Hashtable)hGUI.get("guiAuthMethod") ).get("value");

      if(sAuth.equals("Basic")) {
        String sDomain, sLogin, sPassword;
        JTextField jtf;
        JPasswordField jpf;

        // récupération des champs dans la GUi
        jtf = (JTextField)( (Hashtable)hGUI.get("guiAuthUser") ).get("objectID");
        sLogin = jtf.getText();
        jpf = (JPasswordField)( (Hashtable)hGUI.get("guiAuthPassword") ).get("objectID");
        sPassword = new String(jpf.getPassword());

        // encodage Base64
        tmpHeaders += RFC2617.toBasicCredentials(sLogin, sPassword);
        iCaseH += 2;
      }

      if(sAuth.equals("Digest")) {
        String sLogin, sPassword;
        JTextField jtf;
        JPasswordField jpf;

        // récupération des champs dans la GUi
        jtf = (JTextField)( (Hashtable)hGUI.get("guiAuthUser") ).get("objectID");
        sLogin = jtf.getText();
        jpf = (JPasswordField)( (Hashtable)hGUI.get("guiAuthPassword") ).get("objectID");
        sPassword = new String(jpf.getPassword());

        // store in hFast & set directive -digest
        hFast.put("user", sLogin);
        hFast.put("password", sPassword);
        hFast.put("-digest", true);
      }

      if(sAuth.equals("NTLM")) {
        String sLogin, sPassword, sDomain;
        JTextField jtf;
        JPasswordField jpf;
        // récupération des champs dans la GUi
        jtf = (JTextField)( (Hashtable)hGUI.get("guiAuthUser") ).get("objectID");
        sLogin = jtf.getText();
        jpf = (JPasswordField)( (Hashtable)hGUI.get("guiAuthPassword") ).get("objectID");
        sPassword = new String(jpf.getPassword());
        jtf = (JTextField)( (Hashtable)hGUI.get("guiAuthDomain") ).get("objectID");
        sDomain = jtf.getText();
        // store in hFast & set directive -digest
        hFast.put("ntlmuser", sLogin);
        hFast.put("ntlmpassword", sPassword);
        hFast.put("ntlmdomain", sDomain);
        hFast.put("-ntlm", true);
      }

      // type de connexion ?
      String sConn = (String)( (Hashtable)hGUI.get("guiConnConnect") ).get("value");
      hFast.put("guiConnConnect", sConn);

      if(!sConn.equals("http")) {
        // traitement des sslprotocols
        hFast.put("sslprotocols", (String)( (Hashtable)hGUI.get("sslprotocols") ).get("value") );

        // traitement des ciphers
        hFast.put("ciphers", (String)( (Hashtable)hGUI.get("guiConnCipher") ).get("value"));

        // config SSL
        String spro = (String)( (Hashtable)hGUI.get("provider") ).get("value");

        if(spro.equals("SunJSSE_Strict"))
          hFast.put("provider", "SunJSSE");

        if(spro.equals("SunJSSE_SSLv2Hello"))
          hFast.put("provider", "SunJSSE");

        if(spro.equals("IBMJSSE"))
          hFast.put("provider", "IBMJSSE");

        String sinstance = (String)( (Hashtable)hGUI.get("instance") ).get("value");
        hFast.put("instance", sinstance);

        // trustmanager
        hFast.put("trustmanager", (TrustManager[])(((Hashtable)hGUI.get("trustmanager")).get("value")) );

        flagSSL = true;
        // TO DO : traitement cert client
      }

      // utilisation proxy ?
      Boolean blnProx = (Boolean)( (Hashtable)hGUI.get("guiProxOnOff") ).get("value");
      String spr1 = "", spr2 = "", spr3 = "", spr4 = "";

      if(blnProx) {
        JTextField jtf = (JTextField)( (Hashtable)hGUI.get("guiProxyname") ).get("objectID");
        spr1 = jtf.getText();
        jtf = (JTextField)( (Hashtable)hGUI.get("guiProxyport") ).get("objectID");
        spr2 = jtf.getText();
        jtf = (JTextField)( (Hashtable)hGUI.get("guiProxyuser") ).get("objectID");
        spr3 = jtf.getText();
        JPasswordField jpf = (JPasswordField)( (Hashtable)hGUI.get("guiProxypass") ).get("objectID");
        spr4 = new String(jpf.getPassword());

        // lastHost mémorise les paramètres proxy ET serveur
        reuseConn2 = (lastHost.equals("PROXY_" + spr1 + spr2 + "_SERVER_" + (String)hFast.get("guiHost") + (String)hFast.get("guiPort"))) ? true : false;
        lastHost = "PROXY_" + spr1 + spr2 + "_SERVER_" + (String)hFast.get("guiHost") + (String)hFast.get("guiPort");
      }
      else {
        // lastHost mémorise les paramètres serveur
        reuseConn2 = (lastHost.equals("SERVER_" + (String)hFast.get("guiHost") + (String)hFast.get("guiPort"))) ? true : false;
        lastHost = "SERVER_" + (String)hFast.get("guiHost") + (String)hFast.get("guiPort");
      }

      hFast.put("guiProxyname", spr1);
      hFast.put("guiProxyport", spr2);
      hFast.put("guiProxyuser", spr3);
      hFast.put("guiProxypass", spr4);

      // directive pour le scenario d'authentification proxy
      if( !(spr3 + spr4).equals("") )
        hFast.put("-proxyauth", true);

      JTextArea jta = (JTextArea)( (Hashtable)hGUI.get("guiAdvanced") ).get("objectID");
      String she = jta.getText();
      String[] she1 = she.split("\n\n");

      // vérification du format (on doit avoir au minimum 2 sauts de ligne entre le header et le body)
      if(she1.length < 2)
        System.err.println("erreur de format");
      else {
        // rappel : lors de la saisie, la nouvelle ligne correspond à \n quelque soit la plateforme
        String[] sh = she1[0].split("\n");
        String cleanSH = "";

        for(int i = 0; i < sh.length; i++) {
          int iindex = sh[i].indexOf(":");

          /* on effectue un minimum de vérification syntaxique
           *  1 - présence de ":"
           *  2 - supression des lignes vides
           */
          if(iindex > 0) {
            cleanSH += sh[i] + RFCUtil.CRLF;
          }
        }

        // rajout des headers récoltés pendant le traitement précédent
        switch(iCaseH) {
          case 1:
            cleanSH += "Host: " + (String)((Hashtable)hGUI.get("guiHost")).get("value") + RFCUtil.CRLF;
            break;

          case 2:
            cleanSH += "Authorization: " + tmpHeaders + RFCUtil.CRLF;
            //cleanSH += "Authorization: " + tmpHeaders + "=="  + RFCUtil.CRLF;
            break;

          case 3:
            cleanSH += "Host: " + (String)((Hashtable)hGUI.get("guiHost")).get("value") + RFCUtil.CRLF;
            cleanSH += "Authorization: " + tmpHeaders + RFCUtil.CRLF;
            //cleanSH += "Authorization: " + tmpHeaders + "==" + RFCUtil.CRLF;
            break;
        }

        // store the headers in hFast (String[])
        if(cleanSH.length() > 0)
          hFast.put("headers", cleanSH.split(RFCUtil.CRLF));

        // partie body
        cleanSH = "";

        for(int i = 1; i < she1.length - 1; i++) { // cas où body sur plusieurs lignes
          cleanSH += she1[i] + RFCUtil.DCRLF;
        }

        // dernière ligne du body
        cleanSH += she1[she1.length - 1];

        // positionnement du body en question
        System.err.println(cleanSH);
        hFast.put("request-body", cleanSH.getBytes());

        // positionnement des headers liés à la présence du body par défaut
        // Content-Length + Content-Type
        setBodyHeaders = true;
      }
    }

    // cas 'Raw Request'
    // TEST : latvian proxy 84.237.220.18:8080
    // TEST : proxy erroné avec encodage asiatique : 218.108.64.166:80
    // TEST proxy plutôt lent 201.34.32.44:3128 (brazil)
    if(sAdv.equals("Raw Request")) {

      // suppression des résidus provenant des requêtes précédentes si besoin
      hFast.put("headers", new String[0]);

      // utilisation des cookies : inhibition de la configuration indiquée par la GUi, mais on préserve les cookies pour les requêtes ultérieures
      hFast.put("cookiesupport", (Hashtable)hGUI.get("cookiesupport"));

      // supprimer les autres résidus lorsque nécessaire (body..)
      if(hFast.containsKey("request-body"))
        hFast.remove("request-body");

      if(hFast.containsKey("user"))
        hFast.remove("user");

      if(hFast.containsKey("password"))
        hFast.remove("password");

      if(hFast.containsKey("ntlmuser"))
        hFast.remove("ntlmuser");

      if(hFast.containsKey("ntlmpassword"))
        hFast.remove("ntlmpassword");

      if(hFast.containsKey("ntlmdomain"))
        hFast.remove("ntlmdomain");

      // partie commune à la gestion des headers
      Boolean bFol = (Boolean)( hGUI.get("-follow") );
      hFast.put("-follow", bFol);

      // type de connexion ?
      String sConn = (String)( (Hashtable)hGUI.get("guiConnConnect") ).get("value");
      hFast.put("guiConnConnect", sConn);

      if(!sConn.equals("http")) {
        // TO DO : on met quoi ici ?
        //flagSSL = true;
        // traitement des sslprotocols
        hFast.put("sslprotocols", (String)( (Hashtable)hGUI.get("sslprotocols") ).get("value") );

        // traitement des ciphers
        hFast.put("ciphers", (String)( (Hashtable)hGUI.get("guiConnCipher") ).get("value"));

        // config SSL
        String spro = (String)( (Hashtable)hGUI.get("provider") ).get("value");

        if(spro.equals("SunJSSE_Strict"))
          hFast.put("provider", "SunJSSE");

        if(spro.equals("SunJSSE_SSLv2Hello"))
          hFast.put("provider", "SunJSSE");

        if(spro.equals("IBMJSSE"))
          hFast.put("provider", "IBMJSSE");

        String sinstance = (String)( (Hashtable)hGUI.get("instance") ).get("value");
        hFast.put("instance", sinstance);

        // trustmanager
        hFast.put("trustmanager", (TrustManager[])(((Hashtable)hGUI.get("trustmanager")).get("value")) );

        // TO DO : traitement cert client
      }

      // récupération de la donnée saisie dans la GUi
      JTextArea jta = (JTextArea)( (Hashtable)hGUI.get("guiAdvanced") ).get("objectID");
      String sraw = jta.getText();

      // valeur de contrôle indiquant si la Raw-Request est correctement formatée
      // on n'effectue qu'un contrôle basique sur le format de la request
      boolean blnError = false;

      // récupération 1st-line
      int iindex = sraw.indexOf("\n");

      if(iindex > 0) {
        String firstline = sraw.substring(0, iindex);
        int iMet = firstline.indexOf(" ");
        String sMet = firstline.substring(0, iMet);
        hFast.put("guiMethod", sMet);

        firstline = firstline.substring(iMet + 1);
        iMet = firstline.indexOf(" ");
        sMet = firstline.substring(0, iMet);

        /* récupération des champs host port path à partir de Request-URI */


        /* si la connection est faite à un proxy ou à un serveur, Request-URI est différent */
        Boolean blnProx = (Boolean)( (Hashtable)hGUI.get("guiProxOnOff") ).get("value");
        String spr1 = "", spr2 = "", spr3 = "", spr4 = "";

        if(blnProx) {
          JTextField jtf = (JTextField)( (Hashtable)hGUI.get("guiProxyname") ).get("objectID");
          spr1 = jtf.getText();
          jtf = (JTextField)( (Hashtable)hGUI.get("guiProxyport") ).get("objectID");
          spr2 = jtf.getText();
          jtf = (JTextField)( (Hashtable)hGUI.get("guiProxyuser") ).get("objectID");
          spr3 = jtf.getText();
          JPasswordField jpf = (JPasswordField)( (Hashtable)hGUI.get("guiProxypass") ).get("objectID");
          spr4 = new String(jpf.getPassword());

          if(RFC2396.isAbsoluteURI(sMet)) {
            Hashtable hParts = RFCUtil.splitAbsoluteURI(sMet);
            hFast.put("guiHost", (String)hParts.get("host"));
            String sPort = (String)hParts.get("port");

            if(sPort.equals("")) {  // port par défaut si non renseigné
              if(sConn.equals("http"))
                hFast.put("guiPort", "80");
              else
                hFast.put("guiPort", "443");
            }
            else
              hFast.put("guiPort", (String)hParts.get("port"));

            hFast.put("guiPath", (String)hParts.get("path_query"));
          }
          else {
            System.err.println("requête via proxy doit être de type absolute-URI");
            blnError = true;
          }

          // lastHost mémorise les paramètres proxy ET serveur
          reuseConn2 = (lastHost.equals("PROXY_" + spr1 + spr2 + "_SERVER_" + (String)hFast.get("guiHost") + (String)hFast.get("guiPort"))) ? true : false;
          lastHost = "PROXY_" + spr1 + spr2 + "_SERVER_" + (String)hFast.get("guiHost") + (String)hFast.get("guiPort");
        }
        else {  // pas de proxy, request-URI de type '* | abs_path | authority' mais jamais absoluteURI
          hFast.put("guiPath", sMet);
          hFast.put("guiHost", (String)((Hashtable)hGUI.get("guiHost")).get("value"));
          hFast.put("guiPort", (String)((Hashtable)hGUI.get("guiPort")).get("value"));
          // lastHost mémorise les paramètres serveur
          reuseConn2 = (lastHost.equals("SERVER_" + (String)hFast.get("guiHost") + (String)hFast.get("guiPort"))) ? true : false;
          lastHost = "SERVER_" + (String)hFast.get("guiHost") + (String)hFast.get("guiPort");
        }

        hFast.put("guiProxyname", spr1);
        hFast.put("guiProxyport", spr2);
        hFast.put("guiProxyuser", spr3);
        hFast.put("guiProxypass", spr4);

        // directive pour le scenario d'authentification proxy
        if( !(spr3 + spr4).equals("") )
          hFast.put("-proxyauth", true);

        firstline = firstline.substring(iMet + 1);
        hFast.put("guiVersion", firstline);
      }
      else
        blnError = true;

      // récupération headers
      if(!blnError) {
        String theheaders = sraw.substring(iindex + 1);
        int ilast = theheaders.indexOf("\n\n");

        if(ilast > 0) {
          theheaders = theheaders.substring(0, ilast);
          hFast.put("headers", theheaders.split("\n"));

          // récupération body
          String thebody = sraw.substring(iindex + ilast + 3);

          if(!thebody.equals("")) {
            String rbody = thebody.replace("\n", RFCUtil.CRLF);
            hFast.put("request-body", rbody.getBytes());
          }
        }
      }
    }

    //DEBUG
    //System.err.println(hFast.toString());

    // vérifier si on doit essayer d'utiliser la dernière connection (changement de protocole ou hostname => NON)
    boolean reuseConn1 = reuseConn;
    SimpleScenario ss = initHTTPProcess((BiStreamHandle)(hGUI.get("bsh")), (MultiOutputStream[])(hGUI.get("mps")), setBodyHeaders, (reuseConn1 && reuseConn2));

    // show/hide 'ssl last certificate' menu
    final boolean boo = flagSSL;
    Runnable aRunnable = new Runnable() {
      public void run() {
        JTouch.this.getJMenuBar().getMenu(2).getMenuComponent(1).setEnabled(boo);
      }
    };
    SwingUtilities.invokeLater(aRunnable);

    hGUI.put("ss", ss);
    reuseConn = true;
  }

}

/*
 * NTLMScenario class
 * unlike Basic and Digest, NTLM authenticates a connection and not a request
 * after authentication, keeping the connection alive will avoid the authentication overhead
 * this implementation uses openjdk NTLM classes
 */
class NTLMScenario extends SimpleScenario {

  private boolean reuse;

  private String ntlmuser = "";
  private String ntlmpassword = "";
  private String ntlmdomain = "";

  private boolean blnFound = false;
  private boolean blnExportCert = false;

  public NTLMScenario(HTTPTransaction handle,
                      boolean logtime,
                      String ntlmuser,
                      String ntlmpassword,
                      String ntlmdomain,
                      boolean blnExportCert,
                      boolean reuse,
                      CookieWrapper cookiewrapper) {
    super(handle, logtime, cookiewrapper);
    this.blnExportCert = blnExportCert;
    this.reuse = reuse;
    this.ntlmuser = ntlmuser;
    this.ntlmpassword = ntlmpassword;
    this.ntlmdomain = ntlmdomain;
  }

  public void run() {

    Date startDate1 = new Date();
    ScenarioResult sr = handle.runScenario(reuse, wrapper);
    boolean keepalive = sr.getKeepAlive();

    // when 'reuse' was false we're expecting a 401 with 'WWW-Authenticate' header and the value should start with 'NTLM '
    if(handle.getResponseMessage().getStatusCode().equals("401")) {
      if(keepalive) {
        try {

          Client client = new Client(null, handle.getRequestMessage().getHostname(), ntlmuser, ntlmdomain, ntlmpassword.toCharArray());
          String bt1 = (Base64.encodeBytes(client.type1()));
          handle.getRequestMessage().addHeader("Authorization", "NTLM " + bt1);

          sr = handle.runScenario(true, wrapper);

          String[] strWWWA = handle.getResponseMessage().getHeader("WWW-Authenticate");

          byte[] bt2 = new byte[0];
          byte[] nonce = new byte[0];

          boolean blnFound = false;
          int iHVal = 0;

          while(!blnFound && iHVal < strWWWA.length) {
            if(strWWWA[iHVal++].startsWith("NTLM ")) {
              bt2 = Base64.decode(strWWWA[0].substring(5).getBytes());
              nonce = new byte[8];
              System.arraycopy(bt2, 24, nonce, 0, 8);
              blnFound = true;
            }
          }

          if(blnFound) {
            //System.err.println("NTLM authentication header  found");
            byte[] bt3 = client.type3(bt2, nonce);
            handle.getRequestMessage().setHeader("Authorization", "NTLM " + Base64.encodeBytes(bt3), false);

            sr = handle.runScenario(true, wrapper);
            saveCookies( sr.getCookieNetscape(), sr.getCookieV1() );

          }
          else {
            System.err.println("NTLM authentication header not found");
          }

        }
        catch(NTLMException ntlme) {
          System.err.println(ntlme);
        }
        catch(MalformedHeaderNameException mhne) {
          System.err.println(mhne);
        }
        catch(MalformedHeaderValueException mhve) {
          System.err.println(mhve);
        }
        catch(UndefinedHeaderException uhe) {
          System.err.println(uhe);
        }
      }
      else {
        System.err.println("NTLM must use keepalive connections, something went wrong !");
      }
    }
    // when 'reuse' was true we're expecting a 200
    else {
      if(handle.getResponseMessage().getStatusCode().equals("200")) {
        saveCookies( sr.getCookieNetscape(), sr.getCookieV1() );
      }
    }

    Date endDate1 = new Date();

    if(logtime)
      System.err.println("total time " + (endDate1.getTime() - startDate1.getTime()) + " ms");

  }

}

/*
 * classe implémentant le DigestScenario
 * celui-ci se compose d'une 1ère requête sans authentification afin d'obtenir le challenge
 * et d'une seconde requête avec les credentials calculés avec le challenge reçu précedemment
 */
class DigestScenario extends SimpleScenario {

  private boolean reuse = false;

  private String user = "";
  private String passwd = "";

  private boolean blnFound = false;
  private boolean blnExportCert;


  public DigestScenario(HTTPTransaction handle) {
    super(handle);
  }
  public DigestScenario(HTTPTransaction handle, boolean logtime, String user, String passwd) {
    super(handle, logtime);
    this.user = user;
    this.passwd = passwd;
  }
  public DigestScenario(HTTPTransaction handle, boolean logtime, String user, String passwd, boolean blnExportCert) {
    super(handle, logtime);
    this.user = user;
    this.passwd = passwd;
    this.blnExportCert = blnExportCert;
  }
  public DigestScenario(HTTPTransaction handle, boolean logtime, String user, String passwd, boolean blnExportCert, GenericCookie cookies) {
    super(handle, logtime, cookies);
    this.user = user;
    this.passwd = passwd;
    this.blnExportCert = blnExportCert;
  }

  public void run() {
    System.err.println("running Digest");
    Date startDate1 = new Date();
    // TO DO : check cette valeur
    //boolean[] brez = handle.runScenario(reuse, null);
    //keepalive = brez[0];
    ScenarioResult sr = handle.runScenario(reuse, null);
    keepalive = sr.getKeepAlive();
    //IOState = brez[1];

    // check the 1st response : it should return a 401 with "WWW-Authenticate: Digest challenge" header line
    if(handle.getResponseMessage().getStatusCode().equals("401")) {
      Hashtable<String, String> h = new Hashtable<String, String>();

      // optional Authentication-Info header (see RFC2617 §3.2.3) (but could be in the trailer when chunked is used)
      try {
        String[] strAInfo = handle.getResponseMessage().getHeader("Authentication-Info");
        // TO DO
      }
      catch(UndefinedHeaderException uhe) {}

      try {
        String[] strDig = handle.getResponseMessage().getHeader("WWW-Authenticate");

        // there should be only ONE header, but in case there are several we keep the first without any warning/error
        int i = 0;

        while(i < strDig.length && (!blnFound)) {
          String strVal = strDig[i].trim();

          if(strVal.toLowerCase().startsWith("digest")) {
            int challenge_index = strVal.indexOf(" ");

            if(challenge_index > 0)
              h = DigestChallenge.extractDirectives(strVal.substring(challenge_index + 1), false);

            if(h.size() > 0) {
              blnFound = true;
            }
          }

          i++;
        }

        if(blnFound) {
          String entitybody = "";

          if( !((String)h.get("qop-options")).equals("") ) {
            h.put("ncvalue", "00000001"); // we suppose it is always the 1st request with that nonce
            h.put("cnonce", "abcd5678");
            String[] qopz = ((String)h.get("qop-options")).split(",");
            boolean blnaut = false, blnint = false;

            for(int iqo = 0; iqo < qopz.length; iqo++) {
              if(qopz[iqo].equals("auth"))
                blnaut = true;

              if(qopz[iqo].equals("auth-int"))
                blnint = true;
            }

            // "auth" has more priority than "auth-int", and "auth-int" more than any other
            if(blnaut)
              h.put("qop-options", "");
            else {
              if(blnint) {
                h.put("qop-options", "auth-int");
                // we suppose RequestMessage.body is stored without any transfer-coding applied, otherwise change this code
                entitybody = handle.getRequestMessage().getBody();
              }
              else {
                System.err.println("shouldn't happen : " + h.get("qop-options"));
                // TO DO : RFU ?
              }
            }
          }
          else {
            h.put("ncvalue", "");
            h.put("cnonce", "");
          }

          String digest = RFC2617.toDigestCredentials((String)h.get("algorithm"),
                          user, (String)h.get("realm"), passwd, (String)h.get("nonce"),
                          (String)h.get("ncvalue"), (String)h.get("cnonce"),
                          handle.getRequestMessage().getMethod(),
                          handle.getRequestMessage().getRequestURI(),
                          entitybody,
                          (String)h.get("qop-options"),
                          (String)h.get("opaque") );

          // the 2nd request is now ready !!
          try {
            handle.getRequestMessage().addHeader("Authorization", digest);
            //brez = handle.runScenario(reuse, null);
            //keepalive = brez[0];
            sr = handle.runScenario(reuse, null);
            keepalive = sr.getKeepAlive();
            //IOState = brez[1];
          }
          catch(MalformedHeaderNameException mhne) {}
          catch(MalformedHeaderValueException mhve) {}

          //System.err.println("debug digest : " + digest);
          //from RFC2616 String digestCHECK = RFC2617.toDigestCredentials("MD5", "Mufasa", "testrealm@host.com", "Circle Of Life", "dcd98b7102dd2f0e8b11d0f600bfb0c093", "00000001", "0a4f113b", "GET", "/dir/index.html", "", "auth", "5ccc069c403ebaf9f0171e9517f40e41");

        }
      }
      catch(UndefinedHeaderException uhe) {}
    }

    Date endDate1 = new Date();

    if(logtime)
      System.err.println("total time " + (endDate1.getTime() - startDate1.getTime()) + " ms");

    // export certificate to file if requested in command-line
    if(blnExportCert) {
      Hashtable h = handle.getHandshakeInfo();

      try {
        // Get the encoded form which is suitable for exporting
        X509Certificate[] certs = (X509Certificate[])h.get("peerCertificates");

        // write to the file
        int i = 0;
        String stmp;

        while(i < certs.length) {
          stmp = (i == 0) ? "webcert.pem" : "AC_" + i + ".pem" ;
          CertificateUtil.exportToFile(certs[i++], stmp);
        }
      }
      catch(NullPointerException npe) {
        // happens for DH_ANON or KERBEROS ciphersuites, do nothing
      }
    } // end export

  }

}

/*
 * classe implémentant le SSLServerCheckUp Scenario
 */
class CheckUpScenario extends SimpleScenario {
  //private EmptySSLTransaction handle;
  private boolean stopit = false;

  private String user = "";
  private String passwd = "";

  /*
   * constructeur : nécessite un HTTPTransaction pour initialiser le process
   */
  public CheckUpScenario(EmptySSLTransaction handle, boolean logtime) {
    super((HTTPTransaction)handle, logtime);
  }

  public CheckUpScenario(EmptySSLTransaction handle, boolean logtime, String user, String passwd) {
    super((HTTPTransaction)handle, logtime);
    this.user = user;
    this.passwd = passwd;
  }
  public CheckUpScenario(EmptySSLTransaction handle, HTMLStamps logtime) {
    super((HTTPTransaction)handle, logtime);
  }

  public CheckUpScenario(EmptySSLTransaction handle, HTMLStamps logtime, String user, String passwd) {
    super((HTTPTransaction)handle, logtime);
    this.user = user;
    this.passwd = passwd;
  }


  public void setRequestMessage(RequestMessage rm) {
    handle.setRequestMessage(rm);
  }

  public void stopit() {
    stopit = true;
    // TO DO : propager le stop au HTTPScenario courant
  }

  public void run() {

    /* mémorisation du temps de traitement */
    Date startDate1 = new Date();

    // la série des ciphers à tester
    String[] myd = new String[0];
    String[][] mydd = new String[147][4];
    myd = CipherSuiteUtil.getCiphersByProvider("SUN");

    for(int i = 0; i < 27; i++) {
      mydd[i][0] = "SunJSSE";
      mydd[i][1] = "TLS";
      mydd[i][2] = "SSLv3:SSLv2Hello";
      mydd[i][3] = myd[i];
    }

    for(int i = 0; i < 27; i++) {
      mydd[i + 27][0] = "SunJSSE";
      mydd[i + 27][1] = "TLS";
      mydd[i + 27][2] = "TLSv1:SSLv2Hello";
      mydd[i + 27][3] = myd[i];
    }

    myd = CipherSuiteUtil.getCiphersByProvider("IBM");

    for(int i = 0; i < 31; i++) {
      mydd[i + 54][0] = "IBMJSSE";
      mydd[i + 54][1] = "SSLv2";
      mydd[i + 54][2] = "";
      mydd[i + 54][3] = myd[i];
    }

    for(int i = 0; i < 31; i++) {
      mydd[i + 85][0] = "IBMJSSE";
      mydd[i + 85][1] = "SSLv3";
      mydd[i + 85][2] = "";
      mydd[i + 85][3] = myd[i];
    }

    for(int i = 0; i < 31; i++) {
      mydd[i + 116][0] = "IBMJSSE";
      mydd[i + 116][1] = "TLSv1";
      mydd[i + 116][2] = "";
      mydd[i + 116][3] = myd[i];
    }

    /* traitement */
    int ind = 0;

    while(ind < 147 && !stopit) {
      ((EmptySSLTransaction)handle).setSSLProvider(mydd[ind][0]);
      ((EmptySSLTransaction)handle).setSSLInstance(mydd[ind][1]);

      String[] st = (mydd[ind][2].length() > 0) ? (mydd[ind][2]).split(":") : new String[0];
      ((EmptySSLTransaction)handle).setSSLProtocols(st);

      ((EmptySSLTransaction)handle).setSSLCipherSuites(new String[] {mydd[ind][3]} );

      String stmp = "";

      if(mydd[ind][0].equals("SunJSSE"))
        stmp = mydd[ind][2];
      else
        stmp = mydd[ind][1];

      System.err.print(mydd[ind][0] + "/" + stmp + "/" + mydd[ind][3] + " ");

      // on lance la requête sans maintenir la connexion et sans logger
      //HTTPScenario scenario = new HTTPScenario(handle, false, false);
      SimpleScenario scenario;

      if(!(user + passwd).equals(""))
        scenario = new SSLProxyAuthScenario((SSLTransactionViaProxy)handle, logtime, user, passwd );
      else
        scenario = new HTTPScenario(handle, logtime, false);

      scenario.start();

      try {
        scenario.join();

        if(scenario.IOState)
          System.err.println("OK");
        else
          System.err.println("NOK");
      }
      catch(InterruptedException ie) {}

      ind++;
    }

    // calcul du temps de traitement
    Date endDate1 = new Date();

    if(logtime)
      System.err.println("total time " + (endDate1.getTime() - startDate1.getTime()) + " ms");
  }

}

/*
 * classe implémentant un scénario "1ère requête + suivi des redirections"
 */
class FullScenario {
  private HTTPTransaction handle;

  /*
   * constructeur : nécessite un HTTPTransaction pour initialiser le process
   */
  public FullScenario(HTTPTransaction handle) {
    this.handle = handle;
  }

  public void setRequestMessage(RequestMessage rm) {
    handle.setRequestMessage(rm);
  }

  /*
   *
   */
  public void run() {
    boolean blnFirst = true;
    boolean blnBreak = false;
    String strSC = "";

    while( !blnBreak && (blnFirst || strSC.equals("301") || strSC.equals("302") || strSC.equals("303") || strSC.equals("307")) ) {

      // blnKeepAlive utilisé pour le maintien de la connexion (uniquement par proxy ou en redirection relative, TO DO : redirection absolue)
      boolean blnKeepAlive = false;

      if(blnFirst)
        blnFirst = false;
      else {  // construction de la requête suivante (information contenue dans header Location)
        try {
          String[] newLocation = handle.getResponseMessage().getHeader("Location");

          if(newLocation.length != 1) // erreur de formatage de la réponse
            blnBreak = true;
          else {
            String strTmp = newLocation[0];

            // TO DO : liste d'exception du proxy + password du site

            //RequestMessageHeader messageHeader = new RequestMessageHeader();
            RequestMessageHeader messageHeader = (RequestMessageHeader)(RequestMessageHeaderFactory.create(null));

            //RequestMessage req = new RequestMessage(messageHeader);
            RequestMessage req = new RequestMessage(new ReqMessageHeader());
            Hashtable hSplit = new Hashtable();
            HTTPTransaction nhandle = null;

            // redirection avec URL absolue ?
            if(RFC2396.isAbsoluteURI(strTmp)) {
              hSplit = RFCUtil.splitAbsoluteURI(strTmp);

              try {
                req.setMethod("GET");
                req.setRequestURI((String)hSplit.get("path_query"));
                req.setHTTPVersion(handle.getRequestMessage().getHTTPVersion());
                req.setHostname((String)hSplit.get("host"));
                //req.setPort((String)hSplit.get("port"));
                req.addHeader("Host", (String)hSplit.get("host"));
              }
              catch(InvalidMethodException ime) {}
              catch(InvalidRequestURIException irue) {}
              catch(InvalidHTTPVersionException ihve) {}
              catch(MalformedHeaderNameException mhne) {}
              catch(MalformedHeaderValueException mhve) {}

              boolean blnScheme = false;

              // on vérifie si on doit passer par un proxy
              if( ((new PlainTransactionViaProxy()).getClass() == handle.getClass() ) || ((new SSLTransactionViaProxy()).getClass() == handle.getClass()) ) {
                blnKeepAlive = true;

                if("http".equals((String)hSplit.get("scheme"))) {
                  blnScheme = true;

                  if("".equals((String)hSplit.get("port")))
                    req.setPort("80");
                  else
                    req.setPort((String)hSplit.get("port"));

                  nhandle = new PlainTransactionViaProxy(handle.bsh, handle.mos);
                  nhandle.setProxyName(handle.getProxyName());
                  nhandle.setProxyPort( handle.getProxyPort() );
                }

                if("https".equals((String)hSplit.get("scheme"))) {
                  blnScheme = true;

                  if("".equals((String)hSplit.get("port")))
                    req.setPort("443");
                  else
                    req.setPort((String)hSplit.get("port"));

                  nhandle = new SSLTransactionViaProxy(handle.bsh, handle.mos, new String[0], new String[0]);
                  nhandle.setProxyName(handle.getProxyName());
                  nhandle.setProxyPort( handle.getProxyPort() );
                }
              }
              else {  // pas de proxy
                if("http".equals((String)hSplit.get("scheme"))) {
                  blnScheme = true;

                  if("".equals((String)hSplit.get("port")))
                    req.setPort("80");
                  else
                    req.setPort((String)hSplit.get("port"));

                  nhandle = new PlainTransaction(handle.bsh, handle.mos);
                }

                if("https".equals((String)hSplit.get("scheme"))) {
                  blnScheme = true;

                  if("".equals((String)hSplit.get("port")))
                    req.setPort("443");
                  else
                    req.setPort((String)hSplit.get("port"));

                  nhandle = new SSLTransaction(handle.bsh, handle.mos, new String[0], new String[0]);
                }
              }

              System.err.println(hSplit.get("path_query"));

              if(!blnScheme) {
                System.err.println("scheme unknown : " + hSplit.get("scheme"));
                blnBreak = true;
              }

              handle = nhandle;
            }

            // redirection relative => cas le plus simple car on peut conserver le HTTPTransaction et le KA
            if(RFC2396.isRelativeURI(strTmp)) {
              blnKeepAlive = true;
              hSplit = new Hashtable();

              try {
                req.setMethod("GET");
                req.setRequestURI(strTmp);
                // on reporte les paramètres de Request
                req.setHTTPVersion(handle.getRequestMessage().getHTTPVersion());
                req.setHostname(handle.getRequestMessage().getHostname());
                req.addHeader("Host", handle.getRequestMessage().getHeader("Host")[0]);
                req.setPort(handle.getRequestMessage().getPort());
              }
              catch(InvalidMethodException ime) {
                System.err.println(ime);
              }
              catch(InvalidRequestURIException irue) {
                System.err.println(irue);
              }
              catch(InvalidHTTPVersionException ihve) {
                System.err.println(ihve);
              }
              catch(MalformedHeaderNameException mhne) {
                System.err.println(mhne);
              }
              catch(MalformedHeaderValueException mhve) {
                System.err.println(mhve);
              }
            }

            handle.setRequestMessage(req);
          }
        }
        catch(UndefinedHeaderException uhe) {
          // redirection sans header Location : cela n'est pas sensé arriver mais 'paranoïa is good'
          blnBreak = true;
        }
      }

      if(!blnBreak) {
        HTTPScenario scenario = new HTTPScenario(handle, blnKeepAlive, false);
        scenario.start();

        try {
          scenario.join();
        }
        catch(InterruptedException ie) {}

        strSC = handle.getResponseMessage().getStatusCode();
      }
    }

    // TO DO : reporter certains headers de requête en requête (identier dans RFCUtil les headers propres à une requête ou généraux)

    return;
  }

} // end class

class HeaderException extends Exception {
  public HeaderException() {}
  public HeaderException(String s) {
    super(s);
  }
}

class MalformedHeaderException extends HeaderException {
  public MalformedHeaderException() {}
  public MalformedHeaderException(String s) {
    super(s);
  }
}

class MalformedHeaderValueException extends MalformedHeaderException {
  public MalformedHeaderValueException() {}
  public MalformedHeaderValueException(String s) {
    super(s);
  }
}

class MalformedCookieException extends MalformedHeaderValueException {
  public MalformedCookieException(String s) {
    super(s);
  }
}

class MalformedHeaderNameException extends MalformedHeaderException {
  public MalformedHeaderNameException() {}
  public MalformedHeaderNameException(String s) {
    super(s);
  }
}

class UndefinedHeaderException extends MalformedHeaderException {
}

class InvalidRequestURIException extends MalformedHeaderException {
}

class InvalidMethodException extends MalformedHeaderException {
}

class InvalidReasonPhraseException extends MalformedHeaderException {
}

class InvalidStatusCodeException extends MalformedHeaderException {
}

class InvalidHTTPVersionException extends MalformedHeaderException {
}

class HeaderExtraDataException extends HeaderException {
}

class UncompletedReadingException extends Exception {
  public UncompletedReadingException() {}
  public UncompletedReadingException(String s) {
    super(s);
  }
}

/*
 * classe RequestMessageHeader qui implémente la partie header d'une requête HTTP
 */
abstract class RequestMessageHeader extends MessageHeader {

  private String Method = "";
  protected String RequestURI = "";
  private String HTTPVersion = "";
  protected String hostname = "";
  private String port = "";

  /*
   * constructeur par défaut
   */
  public RequestMessageHeader() { }

  /*
   * constructeur à partir d'une String => voir la classe mère
   */
  public RequestMessageHeader(String str) {

    try {

      // 1- définition du start-line
      String sLine = str.substring(0, str.indexOf(RFCUtil.CRLF));
      setStartLine(sLine);

      // 2- définition et ajout des headers
      if(sLine.length() < str.length()) {
        addHeaders(str.substring(str.indexOf(RFCUtil.CRLF) + 2));
      }
    }
    catch(MalformedHeaderException e) {
      System.err.println(e);
    }
  }

  public final void addHeader(String headerName, String headerValue) throws MalformedHeaderNameException, MalformedHeaderValueException {
    addHeader(headerName, headerValue, true);
  }

  public final void addHeader(String headerName, String headerValue, boolean merge) throws MalformedHeaderNameException, MalformedHeaderValueException {

    if( isCorrectHeaderName(headerName) ) {
      try {
        String strCleanedVal = getCleanedHeaderVal(headerValue);

        if(merge) {
          boolean isFound = false;

          // parse the existing headers
          for (Enumeration e = headers.elements(); e.hasMoreElements();) {

            String[] headerNameAndValue = (String[]) e.nextElement();

            if( headerName.toLowerCase().equals(headerNameAndValue[0].toLowerCase()) ) {

              // build the new element : add this value to the previous ones
              String[] s = new String[headerNameAndValue.length + 1];
              System.arraycopy(headerNameAndValue, 0, s, 0, headerNameAndValue.length);
              s[headerNameAndValue.length] = strCleanedVal;

              // replace the element in the vector
              isFound = true;
              this.headers.remove(headerNameAndValue);
              this.headers.add(s);
            }
          }

          if(!isFound)
            this.headers.add( new String[] {headerName, strCleanedVal} );
        }
        else {
          // just add another one in the vector
          this.headers.add(new String[] { headerName, strCleanedVal } );
        }
      }
      catch (MalformedHeaderValueException e) {
        e.printStackTrace(System.out);
        throw(e);
      }
    }
    else {
      throw(new MalformedHeaderNameException(headerName));
    }
  }

  /*
   * positionner un header (le remplacer s'il existe, l'ajouter s'il n'existe pas)
   * cette méthode n'a de sens que pour les requêtes, donc elle n'est pas implémentée dans la classe mère MessageHeader ou les ResponseMessageHeader****
   */
  /*public final void setHeader(String headerName, String headerValue, boolean toclean) throws MalformedHeaderNameException, MalformedHeaderValueException {

    // vérification du headerValue
      String strCleanedVal = (toclean) ? getCleanedHeaderVal(headerValue) : headerValue;

    if(this.headers.containsKey(headerName) != false) {
      // écraser avec la nouvelle valeur
      headers.put(headerName, new String[] {strCleanedVal});
    }
    else {
      // le header n'existe pas => l'ajout est délégué aux méthodes filles addHeader
      addHeader(headerName, strCleanedVal);
    }
  }*/

  /*
   * positionne le champ Method
   */
  public final void setMethod(String method) throws InvalidMethodException {
    boolean blnRez = false;

    if(RFCUtil.isCorrectMethod(method)) {
      Method = method;
    }
    else
      throw new InvalidMethodException();
  }

  /*
   * positionne le champ Request-URI
   */
  public final void setRequestURI(String uri) throws InvalidRequestURIException {

    if(RFCUtil.isCorrectRequestURI(uri)) {

      // TO DO : encodage de l'URL au format UTF-8
      //RequestURI = URLEncoder.encode(uri, "UTF-8");
      RequestURI = uri;
    }
    else
      throw new InvalidRequestURIException();

  }

  /*
   * positionne le champ HTTP-Version
   */
  public final void setHTTPVersion(String version) throws InvalidHTTPVersionException {

    if(RFCUtil.isCorrectHTTPVersion(version))
      HTTPVersion = version;
    else
      throw(new InvalidHTTPVersionException());
  }


  /*
   * positionne le champ port
   */
  public final void setPort(String port) {
    this.port = port;
  }

  public abstract void setHostname(String s);
  public abstract void setHostname(String s, String t);
  public abstract void refreshCookies();

  public final String getHostname() {
    return hostname;
  }

  public final String getPort() {
    return port;
  }

  public final String getMethod() {
    return Method;
  }

  public final String getRequestURI() {
    return RequestURI;
  }

  public final String getHTTPVersion() {
    return HTTPVersion;
  }

  /*
   * retourne la 1ère ligne du message : pour une request ce sera la request-line
   */
  public final String getStartLine() {
    return(getRequestLine());
  }
  public final String getStartLine(boolean absoluteURI) {
    return(getRequestLine(absoluteURI));
  }

  /*
   * positionne la 1ère ligne du message : pour une request il s'agit de request-line
   */
  public final void setStartLine(String sLine) throws MalformedHeaderException {
    String[] parts = sLine.split("\\s");

    try {
      setMethod(parts[0]);
      setHTTPVersion(parts[2]);
      setRequestURI(parts[1]);
    }
    catch(InvalidMethodException e) {
      throw (MalformedHeaderException)e;
    }
    catch(InvalidHTTPVersionException e) {
      throw (MalformedHeaderException)e;
    }
    catch(InvalidRequestURIException e) {
      throw (MalformedHeaderException)e;
    }
  }

  /*
   * retourne la request-line (définie à RFC2616 §5.1)
   */
  // cas par défaut : Request-URI sous la forme de abs_path
  private final String getRequestLine() {
    return(Method.concat(RFCUtil.SP).concat(RequestURI).concat(RFCUtil.SP).concat(HTTPVersion).concat(RFCUtil.CRLF));
  }
  // cas où l'on distingue le format de la request-line
  private final String getRequestLine(boolean absoluteURI) {
    if(!absoluteURI)
      return(Method.concat(RFCUtil.SP).concat(RequestURI).concat(RFCUtil.SP).concat(HTTPVersion).concat(RFCUtil.CRLF));
    else
      return(Method.concat(RFCUtil.SP).concat("http://").concat(hostname).concat(":").concat(port).concat(RequestURI).concat(RFCUtil.SP).concat(HTTPVersion).concat(RFCUtil.CRLF));
  }

  /*
   * indique si le client demande la fermeture de la connexion
   */
  public final boolean connMustBeClosed() {
    boolean rez = false;

    if(getHTTPVersion().equals("HTTP/1.1")) {
      try {
        if(hasHeaderValue("connection", "close"))
          rez = true;
      }
      catch(UndefinedHeaderException uhe) {}

      try {
        if(hasHeaderValue("proxy-connection", "close"))
          rez = true;
      }
      catch(UndefinedHeaderException uhe) {}
    }
    else
      rez = true;

    return rez;
  }

}

/*
 * classe ResponseMessageHeader qui implémente la partie header d'une réponse HTTP
 */
abstract class ResponseMessageHeader extends MessageHeader {
  private String HTTPVersion = "";
  private String StatusCode = "";
  private String ReasonPhrase = "";

  protected byte[] daByte;

  /*
   * constructeur par défaut
   */
  public ResponseMessageHeader() {
  }

  /*
   * constructeur à partir d'un ByteArrayOutputStream
   */
  public ResponseMessageHeader(ByteArrayOutputStream daIn) {
    daByte = daIn.toByteArray();
  }
  /*
   *  parse the header response as described in RFC 2616, 100% compliant except the following reasons :
   *    -Status-Code is sometimes not coded with 3 DIGITS (example : we see 502.1, 403.1 errors on some IIS..)
   *    -LWS
   */
  public final void parse() throws MalformedHeaderException, HeaderExtraDataException {
    int AEFstate = 0;
    int i = 0, car = 0;
    boolean blnError = false;

    // we need 2 buffers maximum
    ByteArrayOutputStream[] baos = new ByteArrayOutputStream[] {new ByteArrayOutputStream(16), new ByteArrayOutputStream(16)};

    // parse the credentials
    while( (i < daByte.length) && !blnError) {

      car = daByte[i];

      // TO DO : case 4 (reason phrase cas normal, ou bien un jump si CRLF est détecté)

      switch(car) {

        case 10:  // LF
          switch(AEFstate) {
            case 6: // step_10
              baos[0] = new ByteArrayOutputStream(16);
              baos[1] = new ByteArrayOutputStream(16);
              AEFstate++;
              break;

            case 12:
              AEFstate++;
              break;

            case 15:  // final_2 reached !!
              AEFstate++;
              break;

            case 17:  // final_1 reached !!
              AEFstate++;
              break;

            default:
              blnError = true;
              break;
          }

          break;

        case 13:  // CR
          switch(AEFstate) {
            case 3:
              try {
                setStatusCode(baos[1].toString());
              }
              catch(InvalidStatusCodeException e) {
                throw (MalformedHeaderException)e;
              }

              AEFstate = 6;
              break;

            case 4:
              try {
                setStatusCode(baos[1].toString());
              }
              catch(InvalidStatusCodeException e) {
                throw (MalformedHeaderException)e;
              }

              AEFstate = 6;
              break;

            case 5: // step_9 : end of first line
              try {
                setReasonPhrase(baos[0].toString());
              }
              catch(InvalidReasonPhraseException e) {
                throw (MalformedHeaderException)e;
              }

              AEFstate++;
              break;

            case 7: // jump to final_1
              AEFstate = 17;
              break;

            case 9:
              AEFstate = 12;
              break;

            case 10:
              AEFstate = 12;
              break;

            case 11:
              AEFstate++;
              break;

            case 13:
              try {
                addHeader(baos[0].toString(), baos[1].toString());
              }
              catch(MalformedHeaderNameException e) {
                throw( (MalformedHeaderException) e);
              }
              catch(MalformedHeaderValueException e) {
                throw( (MalformedHeaderException) e);
              }

              AEFstate = 15;
              break;

            case 14:
              AEFstate = 12;
              break;

            default:
              blnError = true;
              break;
          }

          break;

        case 32:  // SP
          switch(AEFstate) {
            case 1: // step_3 : HTTP Version finished
              try {
                setHTTPVersion(baos[0].toString());
              }
              catch(InvalidHTTPVersionException e) {
                throw (MalformedHeaderException)e;
              }

              AEFstate++;
              break;

            case 3: // step_6 : HTTP Version finished
              try {
                setStatusCode(baos[1].toString());
                baos[0] = new ByteArrayOutputStream(16);
              }
              catch(InvalidStatusCodeException e) {
                throw (MalformedHeaderException)e;
              }

              AEFstate++;
              break;

            case 4: // SP allowed when starting reason phrase
              baos[0].write(car);
              AEFstate++;
              break;

            case 5: // SP allowed in the reason phrase of course
              baos[0].write(car);
              break;

            case 9: // step_14
              AEFstate++;
              break;

            case 10:
              baos[1].write(car);
              AEFstate++;
              break;

            case 11:
              baos[1].write(car);
              break;

            case 13:
              AEFstate++;
              break;

            default:
              blnError = true;
              break;
          }

          break;

        case 9:  // HT
          switch(AEFstate) {
            case 13:
              AEFstate++;
              break;

            default:
              blnError = true;
              break;
          }

          break;

        case 58:  // ":" séparateur des headers
          switch(AEFstate) {
            case 8: // step_13
              AEFstate++;
              break;

            case 11:
              baos[1].write(car);
              break;

            default:
              blnError = true;
              break;
          }

          break;

        default:  // char
          switch(AEFstate) {
            case 0: // step_1 : start the HTTP Version
              baos[0].write(car);
              AEFstate++;
              break;

            case 1: // step_2 : complete the HTTP Version
              baos[0].write(car);
              break;

            case 2: // step_4 : start the Status Code
              baos[1].write(car);
              AEFstate++;
              break;

            case 3: // step_5 : complete the Status Code
              baos[1].write(car);
              break;

            case 4: // step_7 : start the Reason Phrase
              baos[0].write(car);
              AEFstate++;
              break;

            case 5: // step_8 : complete the Reason Phrase
              baos[0].write(car);
              break;

            case 7: // step_11 : start header-name
              baos[0].write(car);
              AEFstate++;
              break;

            case 8: // step_12 : complete header-name
              baos[0].write(car);
              break;

            case 10: // step_15 : start header-value
              baos[1].write(car);
              AEFstate++;
              break;

            case 11: // step_16 : complete header-value
              baos[1].write(car);
              break;

            case 13:
              try {
                addHeader(baos[0].toString(), baos[1].toString());
              }
              catch(MalformedHeaderNameException e) {
                throw( (MalformedHeaderException) e);
              }
              catch(MalformedHeaderValueException e) {
                throw( (MalformedHeaderException) e);
              }

              baos[0] = new ByteArrayOutputStream(16);
              baos[0].write(car);
              baos[1] = new ByteArrayOutputStream(16);
              AEFstate = 8;
              break;

            case 14:
              baos[1].write(car);
              AEFstate = 11;
              break;

            default:
              blnError = true;
              break;
          }

          break;
      }

      //DEBUG System.err.println(daByte[i]);
      i++;
    } // end while

    // check if parsing was finished cleanly
    boolean blnJobOK = ( AEFstate == 16 || AEFstate == 18 );

    if(!blnJobOK)
      //System.err.println("header parsing failed, returning with code: " + AEFstate + " " + baos[0].toString() + "," + baos[1].toString());
      throw new MalformedHeaderException("header parsing failed, returning with code: " + AEFstate);

  } // end parse



  /*
   * cette méthode doit être implémentée dans les 2 classes filles, afin d'intercepter la valeur du cookie si nécessaire
   */
  public abstract void addHeader(String s, String ss)  throws MalformedHeaderNameException, MalformedHeaderValueException;

  /*
   * positionne le champ HTTP-Version
   */
  public final void setHTTPVersion(String version) throws InvalidHTTPVersionException {
    //System.out.print(version + " ");

    if(RFCUtil.isCorrectHTTPVersion(version))
      HTTPVersion = version;
    else
      throw(new InvalidHTTPVersionException());
  }

  /*
   * positionne le champ Status-Code
   */
  public final void setStatusCode(String status) throws InvalidStatusCodeException {
//    System.out.print(status + " ");

    if(RFCUtil.isCorrectStatusCode(status))
      StatusCode = status;
    else
      throw(new InvalidStatusCodeException());
  }

  /*
   * positionne le champ Reason-phrase
   */
  public final void setReasonPhrase(String reason) throws InvalidReasonPhraseException {
//    System.err.println(reason);

    if(RFCUtil.isCorrectReasonPhrase(reason))
      ReasonPhrase = reason;
    else
      throw(new InvalidReasonPhraseException());
  }

  public void debug() {
    //System.err.println(HTTPVersion + ", " + StatusCode + ", " + ReasonPhrase);
    System.err.println("HTTPVersion: " + HTTPVersion);
    System.err.println("StatusCode: " + StatusCode);
    System.err.println("ReasonPhrase: " + ReasonPhrase);
  }

  /*
   * méthode rédéfinissant le start-line : pour une réponse c'est le status-line
   */
  public final String getStartLine() {
    return(getStatusLine());
  }
  public final String getStartLine(boolean b) {
    return(getStatusLine());
  }

  /*
   * retourne le status-line
   */
  private final String getStatusLine() {
    return(HTTPVersion.concat(RFCUtil.SP).concat(StatusCode).concat(RFCUtil.SP).concat(ReasonPhrase).concat(RFCUtil.CRLF));
  }

  /*
   * renvoie le HTTP Version
   */
  public final String getHTTPVersion() {
    return HTTPVersion;
  }

  /*
   * renvoie le StatusCode
   */
  public final String getStatusCode() {
    return(StatusCode);
  }

  /*
   * renvoie le Reason-Phrase
   */
  public final String getReasonPhrase() {
    return(ReasonPhrase);
  }

  /*
   * indique si le serveur demande la fermeture de la connexion
   */
  public final boolean connMustBeClosed() {
    // Keep-Alive par défaut en 1.1 et Close pour 0.9 et 1.0
    boolean rez = false;

    if(getHTTPVersion().equals("HTTP/1.1")) {
      // liste des cas 1.1 où il faut fermer la socket
      try {
        if(hasHeaderValue("connection", "close"))
          rez = true;
      }
      catch(UndefinedHeaderException uhe) {}

      try {
        if(hasHeaderValue("proxy-connection", "close"))
          rez = true;
      }
      catch(UndefinedHeaderException uhe) {}
    }
    else {
      rez = true;
    }

    return rez;
  }

}

class ResponseMessage {
  //private ResponseMessageHeader header = new ResponseMessageHeader();
  public ResMessageHeader header;
  private MessageBody body;

  /*
   * constructeur par défaut
   */
  public ResponseMessage() { }

  public ResponseMessage(ResMessageHeader rmh) {
    header = rmh;
  }

  /*
   * fonctions décorateur de ResponseMessageHeader
   */
  public String getHTTPVersion() {
    return header.getHTTPVersion();
  }
  public String getStatusCode() {
    return header.getStatusCode();
  }
  public String getReasonPhrase() {
    return header.getReasonPhrase();
  }
  public String[] getHeader(String s) throws UndefinedHeaderException {
    return header.getHeader(s);
  }

  // TO DO : supprimer
  public void debug() {
    String str = header.getMessage();
    System.err.println(str);
  }

  public String getMessage() {
    return(header.getMessage().concat(body.getMessage()));
  }

}

/*
 *  interface définissant les différents types de RequestMessage :
 *  RawRequestMessage (données brutes sous forme de byte[])
 *  RequestMessage (données structurées et modifiables)
 */
interface ifaceRequestMessage {
  byte[] getMessageInBytes();
}

/*
 * classe implémentant une requête HTTP RAW (c'est à dire un byte[])
 * la requête est uniquement un byte[] avec aucune vérification de syntaxe
 * elle peut être conforme aux spécifications ou pas ; si besoin de conformité utiliser classe RequestMessage
 */
class RawRequestMessage implements ifaceRequestMessage {
  private byte[] rawrequest = new byte[0];

  /*
   *  constructeur
   */
  public RawRequestMessage(byte[] asis) {
    this.rawrequest = asis;
  }

  /*
   * renvoie le message HTTP sous forme de byte[]
   */
  public byte[] getMessageInBytes() {
    return rawrequest;
  }

}


/*
 * classe implémentant une requête HTTP : elle englobe les parties header et body
 */
class RequestMessage implements ifaceRequestMessage {
  private ReqMessageHeader header;
  private MessageBody body = new MessageBody();

  /*
   * Constructeurs
   */
  public RequestMessage() { }

  public RequestMessage(ReqMessageHeader header) {
    this.header = header;
  }

  /*
   * fonctions décorateur de RequestMessageHeader et MessageBody
   */
  public void setMethod(String s) throws InvalidMethodException {
    header.setMethod(s);
  }
  public void setRequestURI(String s) throws InvalidRequestURIException {
    header.setRequestURI(s);
  }
  public void setHTTPVersion(String s) throws InvalidHTTPVersionException {
    header.setHTTPVersion(s);
  }
  public void setHostname(String s) {
    header.setHostname(s);
  }
  public void setHostname(String s, String t) {
    header.setHostname(s);
  }/*
  public void setHostname(String s, String t) {
    header.setHostname(s, t);
  }*/
  public void setPort(String s) {
    header.setPort(s);
  }
  public void addHeader(String hn, String hv) throws MalformedHeaderNameException, MalformedHeaderValueException {
    header.addHeader(hn, hv);
  }
  public void setHeader(String hn, String hv, boolean b) throws MalformedHeaderNameException, MalformedHeaderValueException {
    header.setHeader(hn, hv, b);
  }
  public void addHeader(String hn, String[] hv) throws MalformedHeaderNameException, MalformedHeaderValueException {
    header.addHeader(hn, hv);
  }
  // since v0.117b
  public void addHeader(String hn, String[] hv, boolean b) throws MalformedHeaderNameException, MalformedHeaderValueException {
    header.addHeader(hn, hv, b);
  }
  public void removeHeader(String s) {
    header.removeHeader(s);
  }
  public String getHostname() {
    return header.getHostname();
  }
  public String getPort() {
    return header.getPort();
  }
  public String getHTTPVersion() {
    return header.getHTTPVersion();
  }
  public String getRequestURI() {
    return header.getRequestURI();
  }
  public String[] getHeader(String headerName) throws UndefinedHeaderException {
    return header.getHeader(headerName);
  }
  public void setBody(byte[] b) {
    body.setBody(b);
  }
  public String getBody() {
    return body.getMessage();
  }

  /*
   * renvoie le message HTTP sous forme de String
   */
  public String getMessage() {
    StringBuffer sb = new StringBuffer();

    sb.append(header.getMessage());
    sb.append(body.getMessage());

    return(new String(sb));
  }

  /*
   * renvoie le message HTTP sous forme de byte[]
   */
  public byte[] getMessageInBytes() {
    byte[] bHeader = header.getMessage().getBytes();
    byte[] bb = new byte[bHeader.length + body.length()];

    System.arraycopy(bHeader, 0, bb, 0, bHeader.length);

    if(body.length() != 0) {
      System.arraycopy(body.getMessageInBytes(), 0, bb, bHeader.length, body.length());
    }

    return(bb);
  }

  /*
   * renvoie le message HTTP sous forme de byte[], mais la 1ère ligne diffère selon que l'on utilise un proxy ou pas
   */
  public byte[] getMessageInBytes(boolean absoluteURI) {
    byte[] bHeader = header.getMessage(absoluteURI).getBytes();
    byte[] bb = new byte[bHeader.length + body.length()];

    System.arraycopy(bHeader, 0, bb, 0, bHeader.length);

    if(body.length() != 0) {
      System.arraycopy(body.getMessageInBytes(), 0, bb, bHeader.length, body.length());
    }

    return(bb);
  }

  /*
   * retourne le champ Method du header
   */
  public String getMethod() {
    return header.getMethod();
  }

  /*
   * écrit le message HTTP sur un stream de sortie
   */
  public void writeMessageToStream() {
  }

  /*
   * retourne le boolean correspondant au maintien de la session
   */
  public boolean connMustBeClosed() {
    return header.connMustBeClosed();
  }

}

abstract class MessageHeader {
  private String startLine = "";
  protected Vector<String[]> headers = new Vector<String[]>();

  /*
   * returns the start-line as defined in RFC 2616
   * the implementation is done by the child classes (request-line | status-line)
   */
  public abstract String getStartLine();

  //public abstract String getStartLine(boolean absoluteURI);
  public abstract String getStartLine(boolean b);


  /*
   * header management methods
   */

  /*
   * add headers found in a multi-line String
   */
  public final void addHeaders(String sLine) throws MalformedHeaderException {
    String[] headerFields = sLine.split(RFCUtil.CRLF);
    String hName, hValue;

    try {
      for(int i = 0; i < headerFields.length; i++) {
        hName = headerFields[i].substring(0, headerFields[i].indexOf(":"));
        hValue = headerFields[i].substring(headerFields[i].indexOf(":") + 1);
        addHeader(hName, hValue, true);
      }
    }
    catch(IndexOutOfBoundsException e) {
      throw new MalformedHeaderException();
    }
    catch(MalformedHeaderNameException e) {
      throw (MalformedHeaderException) e;
    }
    catch(MalformedHeaderValueException e) {
      throw (MalformedHeaderException) e;
    }
  }

  /*
   * add header, implementation by child classes
   */
  public abstract void addHeader(String name, String value)  throws MalformedHeaderNameException, MalformedHeaderValueException;
  public abstract void addHeader(String headerName, String headerValue, boolean merge)  throws MalformedHeaderNameException, MalformedHeaderValueException;

  /*
   * add an header with several values (by default merge the values on the same line)
   */
  public final void addHeader(String headerName, String[] headerValues) throws MalformedHeaderNameException, MalformedHeaderValueException {
    for(int i = 0; i < headerValues.length; i++) {
      addHeader(headerName, headerValues[i], true);
    }
  }

  /*
   * since v0.117b
   * add an header without merging values on the same line
   */
  public final void addHeader(String headerName, String[] headerValues, boolean mergeValuesInOneLine) throws MalformedHeaderNameException, MalformedHeaderValueException {
    for(int i = 0; i < headerValues.length; i++) {
      addHeader(headerName, headerValues[i], mergeValuesInOneLine);
    }
  }

  /*
   * returns the header-values corresponding to a header-name, as a String[]
   * RFC2616 §4.2 says that header-name must not be case sensitive
   */
  public final String[] getHeader(String headerName) throws UndefinedHeaderException {

    Vector<String> vecResults = new Vector<String>(2);

    for (Enumeration e = headers.elements(); e.hasMoreElements();) {

      String[] headerNameAndValue = (String[]) e.nextElement();

      if( headerName.toLowerCase().equals(headerNameAndValue[0].toLowerCase()) ) {
        for(int i = 0; i < headerNameAndValue.length - 1; i++)
          vecResults.addElement(headerNameAndValue[i + 1]);
      }
    }

    if(vecResults.size() > 0)
      return vecResults.toArray(new String[0]);
    else
      throw new UndefinedHeaderException();
  }

  /*
   * checks if a header contains a particular value
   * name & value are not case sensitive
   * exception is thrown when the header name is not found
   */
  public final boolean hasHeaderValue(String headerName, String headerValue) throws UndefinedHeaderException {
    boolean blnRez = false;

    for (Enumeration e = headers.elements(); e.hasMoreElements();) {

      String[] headerNameAndValue = (String[]) e.nextElement();

      if( headerName.toLowerCase().equals(headerNameAndValue[0].toLowerCase()) ) {
        for(int i = 0; i < headerNameAndValue.length - 1; i++)
          if( headerValue.toLowerCase().equals(headerNameAndValue[i + 1].toLowerCase()) )
            blnRez = true;
      }
    }

    if(blnRez)
      return true;
    else
      throw new UndefinedHeaderException();
  }

  /*
   * checks if a header contains a particular string in its value
   */
  public final boolean appearsInHeaderValue(String headerName, String headerValue) throws UndefinedHeaderException {
    boolean blnRez = false;

    for (Enumeration e = headers.elements(); e.hasMoreElements();) {

      String[] headerNameAndValue = (String[]) e.nextElement();

      if( headerName.toLowerCase().equals(headerNameAndValue[0].toLowerCase()) ) {
        for(int i = 0; i < headerNameAndValue.length - 1; i++)
          if( headerValue.toLowerCase().indexOf(headerNameAndValue[i + 1].toLowerCase()) != -1 )
            blnRez = true;
      }
    }

    if(blnRez)
      return true;
    else
      throw new UndefinedHeaderException();
  }

  /*
   * remove all headers matching a header-name
   */
  public final void removeHeader(String headerName) {

    for (Enumeration e = headers.elements(); e.hasMoreElements();) {
      String[] headerNameAndValue = (String[]) e.nextElement();

      if( headerName.toLowerCase().equals(headerNameAndValue[0].toLowerCase()) )
        headers.remove(headerNameAndValue);
    }
  }

  /*
   * returns the HTTP Message
   */
  public final String getMessage() {
    StringBuffer strResult = new StringBuffer(256);

//System.err.println("getMessage()" + headers.size() );

    // 1- start-line
    strResult.append(getStartLine());

    // 2- the headers
    for (Enumeration e = headers.elements(); e.hasMoreElements();) {
      String[] headerNameAndValue = (String[]) e.nextElement();

      strResult.append(headerNameAndValue[0]);
      strResult.append(": ");

      for(int i = 0; i < headerNameAndValue.length - 2; i++)
        strResult.append(headerNameAndValue[i + 1]).append(",");

      strResult.append(headerNameAndValue[headerNameAndValue.length - 1]);

      strResult.append(RFCUtil.CRLF);
    }

    // 3- final CRLF
    strResult.append(RFCUtil.CRLF);

    return(new String(strResult));
  }

  /*
   * returns the HTTP Message with an absolute start-line style
   */
  public final String getMessage(boolean absoluteURI) {
    StringBuffer strResult = new StringBuffer(256);

    // 1- start-line
    strResult.append(getStartLine(absoluteURI));

    // 2- the headers
    for (Enumeration e = headers.elements(); e.hasMoreElements();) {
      String[] headerNameAndValue = (String[]) e.nextElement();

      strResult.append(headerNameAndValue[0]);
      strResult.append(": ");

      for(int i = 0; i < headerNameAndValue.length - 2; i++)
        strResult.append(headerNameAndValue[i + 1]).append(",");

      strResult.append(headerNameAndValue[headerNameAndValue.length - 1]);

      strResult.append(RFCUtil.CRLF);
    }

    // 3- final CRLF
    strResult.append(RFCUtil.CRLF);

    return(new String(strResult));
  }

  /*
   * cleans and returns a header-value as described in RFC 2616  §4.2 (something like String.trim() but more perfectionate)
   * beginning SPaces removed (TO DO : ending SPaces )
   * beginning and ending LWS removed
   * 'middle' LWS replaced by 1*SP
   * throws an exception when a non conform character is detected (TO DO : this should be an option)
   * TEST : www.paypal.com sometimes returns a bad 'Server' header
   *
   * @param str the String to clean
   * @return String
   */
  protected final String getCleanedHeaderVal(String str) throws MalformedHeaderValueException {
    byte[] arr;
    boolean blnCR = false, blnLF = false, blnLWS = false, blnStart = true;
    StringBuffer sb = new StringBuffer();

    arr = str.getBytes();

    for(int i = 0; i < arr.length; i++) {
      // attention : un byte a une valeur [-128; +127] qu'il faut donc complémenter à 256
      int intj = (arr[i] > 0) ? arr[i] : arr[i] + 256;

      switch(intj) {
        case 13:
          if(blnLWS) {  // plusieurs LWS consécutifs
            blnLF = false;
            blnLWS = false;
            // blnCR == true
          }
          else {
            if(!blnCR && !blnLF)
              blnCR = true;
            else
              throw new MalformedHeaderValueException("type 1, with the following data: \n\t" + str + "\n\tdecimal character: " + intj);
          }

          break;

        case 10:
          if(blnCR && !blnLF && !blnLWS)
            blnLF = true;
          else
            throw new MalformedHeaderValueException("type 2, with the following data: \n\t" + str + "\n\tdecimal character: " + intj);

          break;

        case 9:
          if(blnCR && blnLF && !blnLWS)
            blnLWS = true;
          else
            throw new MalformedHeaderValueException("type 3, with the following data: \n\t" + str + "\n\tdecimal character: " + intj);

          break;

        case 32:
          if(blnCR) {
            if(blnLF) {
              if(!blnLWS)
                blnLWS = true;
              else
                throw new MalformedHeaderValueException("type 4, with the following data: \n\t" + str + "\n\tdecimal character: " + intj);
            }
            else
              throw new MalformedHeaderValueException("type 5, with the following data: \n\t" + str + "\n\tdecimal character: " + intj);
          }
          else {
            if(!blnStart)
              sb.append(new String(new byte[] {arr[i]}));
          }

          break;

        default :
          if( (32 < intj) && (intj != 127) ) { // CHAR is not CTL
            if(blnLWS) {
              blnCR = false;
              blnLF = false;
              blnLWS = false;

              if(!blnStart)
                sb.append(" " + new String(new byte[] {arr[i]}));
              else
                blnStart = false;
            }
            else {
              if(blnCR || blnLF)
                throw new MalformedHeaderValueException("type 6, with the following data: \n\t" + str + "\n\tdecimal character: " + intj);
              else {
                sb.append(new String(new byte[] {arr[i]}));
                blnStart = false;
              }
            }
          }
          else {
            throw new MalformedHeaderValueException("type 7, with the following data: \n\t" + str + "\n\tdecimal character: " + intj);
          }

          break;
      }
    }

    return new String(sb);
  }

  /*
   * verifier la validité de header-name (RFC2616 §2.6 token definition)
   */
  protected final boolean isCorrectHeaderName(String strHeader) {
    boolean blnRez = true;
    int intI = 0;
    byte[] bytArr = strHeader.getBytes();

    while( (blnRez == true) && (intI < bytArr.length) ) {
      if(!RFCUtil.isTokenChar(bytArr[intI])) {
        blnRez = false;
      }

      intI++;
    }

    return blnRez;
  }

}

/*
 * classe implémentant un BODY HTTP
 */
class MessageBody {
  private byte[] body = new byte[0];

  public MessageBody() { }

  public MessageBody(byte[] daBody) {
    body = new byte[daBody.length];
    System.arraycopy(daBody, 0, body, 0, daBody.length);
  }

  // positionne le BODY (RFC2616 §7.2 entity-body definition)
  public void setBody(byte[] daBody) {
    body = daBody;
  }

  public String getMessage() {
    return(new String(body));
  }

  public byte[] getMessageInBytes() {
    return(body);
  }

  public int length() {
    return(body.length);
  }

}

/*
 * class permettant de maintenir l'état d'un BiStream, le fermer, le remplacer...
 */
class BiStreamHandle {
  private BiStream bis;

  /*
   * constructeur
   */
  public BiStreamHandle() {}
  public BiStreamHandle(BiStream bs) {
    this.bis = bs;
  }

  /*
   * accessors
   */

  public synchronized void setBiStream(BiStream bs) {
    this.bis = bs;
  }

  public synchronized BiStream getBiStream() {
    return bis;
  }

  /*
   * methodes
   */
  public void flush() throws IOException {
    bis.flush();
  }

  /*
   * TO DO : en cours d'implémentation de close()
   */
  public void close() throws IOException {
    if(bis != null)
      bis.close();
  }

  public void stopit() {
    if(bis != null)
      bis.stopit();
  }

  public boolean sendRequest(MultiOutputStream mps, byte[] mib) {
    StreamManager bsm = new StreamManager();
    bsm.setAction(mps, "SendRequest", mib);
    bsm.start();

    try {
      bsm.join();

    }
    catch(InterruptedException ie) {
      System.err.println(ie);
    }

    // envoi de la variable d'échange indiquant si tout s'est bien passé
    return(bsm.IOEResult == null);
  }

  public ResMessageHeader buildHeader(MultiOutputStream mps, GenericCookie ocookie, String shostname, String spath) {
    StreamManager bsm = new StreamManager();
    bsm.setAction(mps, "readHeader");
    bsm.start();

    try {
      bsm.join();

    }
    catch(InterruptedException ie) {
      System.err.println(ie);
    }

    // envoi de la variable d'échange indiquant si tout s'est bien passé
    return(bsm.rmh);
  }
  public ResMessageHeader buildHeader(MultiOutputStream mps, GenericCookie ocookie, String shostname, String spath, HTMLStamps netstamps) {
    StreamManager bsm = new StreamManager();
    bsm.setAction(mps, "readHeader", netstamps);
    bsm.start();

    try {
      bsm.join();

    }
    catch(InterruptedException ie) {
      System.err.println(ie);
    }

    // envoi de la variable d'échange indiquant si tout s'est bien passé
    return(bsm.rmh);
  }
  public ResMessageHeader buildHeader(MultiOutputStream mps) {
    StreamManager bsm = new StreamManager();
    bsm.setAction(mps, "readHeader");
    bsm.start();

    try {
      bsm.join();

    }
    catch(InterruptedException ie) {
      System.err.println(ie);
    }

    // envoi de la variable d'échange indiquant si tout s'est bien passé
    return(bsm.rmh);
  }
  public ResMessageHeader buildHeader(MultiOutputStream mps, HTMLStamps netstamps) {
    StreamManager bsm = new StreamManager();
    bsm.setAction(mps, "readHeader", netstamps);
    bsm.start();

    try {
      bsm.join();

    }
    catch(InterruptedException ie) {
      System.err.println(ie);
    }

    // envoi de la variable d'échange indiquant si tout s'est bien passé
    return(bsm.rmh);
  }

  public boolean buildBody(MultiOutputStream mos, boolean boo, ResMessageHeader header, Hashtable hConvert, boolean isRAW) {
    boolean keepalive = true;
    String scod = header.getStatusCode();

    // cas 1- pour les codes HTTP 1XX 204 304 le body est forcément vide
    if(!scod.startsWith("1") && !scod.equals("204") && !scod.equals("304") && boo) {
      try { // cas 2- header Transfer-Encoding est présent
        if(!header.appearsInHeaderValue("Transfer-Encoding", "chunked")) {  // possibly throws UndefinedHeaderException
          // as explained in ERRATA of RFC 2616 : all case different from 'chunked' -> read until the socket is closed
          StreamManager tito = new StreamManager();
          tito.setAction(mos, "buildBody", !keepalive, hConvert);
          tito.start();

          try {
            tito.join();
          }
          catch(InterruptedException ie) { }
        }
        else { // cas "chunked" : algorithme fourni dans RFC2616 §19.4.6
          int chunksize = 0;
          StreamManager tito = new StreamManager();
          tito.setAction(mos, "readChunkLength", isRAW);
          tito.start();

          try {
            tito.join();
          }
          catch(InterruptedException ie) {}

          chunksize = tito.INTResult;

          while(chunksize > 0) {
            //System.err.println("chunk:"+ chunksize);
            MultiOutputStream tmpmps = tito.getMultiPrintStream();
            tito = new StreamManager();
            tito.setAction(mos, "buildChunkData", chunksize, hConvert);
            tito.start();

            try {
              tito.join();
            }
            catch(InterruptedException ie) {}

            tmpmps = tito.getMultiPrintStream();
            tito = new StreamManager();
            tito.setAction(mos, "readChunkLength", isRAW);
            tito.start();

            try {
              tito.join();
            }
            catch(InterruptedException ie) {}

            chunksize = tito.INTResult;
          }

          MultiOutputStream tmpmps = tito.getMultiPrintStream();
          tito = new StreamManager();
          tito.setAction(mos, "readFooter", isRAW);
          tito.start();

          try {
            tito.join();
          }
          catch(InterruptedException ie) {}

          // s'il y a des headers envoyés après le trailer, il faut les prendre en compte (par ex: scénario digest)
          ByteArrayOutputStream baos = tito.BAOSba;

          if(baos != null) {
            try {
              header.addHeaders(baos.toString());
            }
            catch(MalformedHeaderException mhe) {}
          }

        } // fin algo
      }
      catch(UndefinedHeaderException e) {
        try { // cas 3- header Content-Length présent
          String[] valz = header.getHeader("Content-Length");
          int iCL = (new Integer(valz[0])).intValue();

          // 0.9/1.0/1.1 ?
          if(header.getHTTPVersion().equals("HTTP/1.1")) {
            try {
              String[] ka = header.getHeader("Connection");

              if(ka[0].toLowerCase().equals("close".toLowerCase())) {
                StreamManager tito = new StreamManager();
                tito.setAction(mos, "buildBody", !keepalive, hConvert);
                tito.start();

                try {
                  tito.join();
                }
                catch(InterruptedException ie) { }

              }
              else {
                StreamManager tito = new StreamManager();
                tito.setAction(mos, "buildBody", iCL, hConvert);
                tito.start();

                try {
                  tito.join();
                }
                catch(InterruptedException ie) {}

              }
            }
            catch(UndefinedHeaderException eeee) {  // default HTTP/1.1 behavior = Keep-Alive
              StreamManager tito = new StreamManager();
              tito.setAction(mos, "buildBody", iCL, hConvert);
              tito.start();

              try {
                tito.join();
              }
              catch(InterruptedException ie) {}
            }
          }
          else {  // default behavior for non HTTP/1.1

            try {
              String[] ka = header.getHeader("Connection");

              if(ka[0].toLowerCase().equals("keep-alive".toLowerCase())) {
                StreamManager tito = new StreamManager();
                tito.setAction(mos, "buildBody", iCL, hConvert);
                tito.start();

                try {
                  tito.join();
                }
                catch(InterruptedException ie) { }

              }
              else {
                StreamManager tito = new StreamManager();
                tito.setAction(mos, "buildBody", !keepalive, hConvert);
                tito.start();

                try {
                  tito.join();
                }
                catch(InterruptedException ie) {}

              }

            }
            catch(UndefinedHeaderException eeee) {  // default HTTP 1.0 behavior = Close connection
              StreamManager tito = new StreamManager();
              tito.setAction(mos, "buildBody", iCL, hConvert);
              tito.start();

              try {
                tito.join();
              }
              catch(InterruptedException ie) {}
            }

          }
        }
        catch(UndefinedHeaderException ee) {
          // cas 4- header Content-Type multipart/byteranges présent
          try {
            String[] valz = header.getHeader("Content-Type");

            if(valz[0].startsWith("multipart/byteranges")) {
              String sTmp = valz[0].substring(valz[0].indexOf("boundary=") + 10);
              StreamManager tito = new StreamManager();
              // TO DO : vérifier si hConvert bien utile ici
              tito.setAction(mos, "buildBody", hConvert);
              tito.start();

              try {
                tito.join();
              }
              catch(InterruptedException ie) {}

              // TO DO : les différentes parties constituant les Range peuvent être récupérées
            }
            else {  // on est dans le cas 5 (CURRENT = voir pourquoi on attend la fin de connexion ??)
              StreamManager tito = new StreamManager();
              tito.setAction(mos, "buildBody", !keepalive, hConvert);
              tito.start();

              try {
                tito.join();
              }
              catch(InterruptedException ie) {}
            }
          }
          catch(UndefinedHeaderException eee) {
            // cas 5 amélioré- la connexion est fermée par le server mais gestion des connexions bloquantes en KA sans CLength
            try {
              String[] ka = header.getHeader("Connection");

              if(ka[0].toLowerCase().equals("Keep-Alive".toLowerCase())) {
                StreamManager tito = new StreamManager();
                tito.setAction(mos, "buildNonBlockedBody", hConvert);
                tito.start();

                try {
                  tito.join();
                }
                catch(InterruptedException ie) { }
              }
              else {
                StreamManager tito = new StreamManager();
                tito.setAction(mos, "buildBody", !keepalive, hConvert);
                tito.start();

                try {
                  tito.join();
                }
                catch(InterruptedException ie) { }
              }
            }
            catch(UndefinedHeaderException uhe) {
              String stHTV = header.getHTTPVersion();

              if(stHTV.equals("HTTP/0.9") || stHTV.equals("HTTP/1.0")) {
                StreamManager tito = new StreamManager();
                tito.setAction(mos, "buildBody", !keepalive, hConvert);
                tito.start();

                try {
                  tito.join();
                }
                catch(InterruptedException ie) { }
              }
              else {
                StreamManager tito = new StreamManager();
                tito.setAction(mos, "buildNonBlockedBody", hConvert);
                tito.start();

                try {
                  tito.join();
                }
                catch(InterruptedException ie) { }
              }
            }
          }
        }
      }
    }

    // TO DO : else -> il n'y a pas de body mais il faut vérifier si la conn est fermée ou non (headers de la request ?)
    // envoi de la variable d'échange indiquant si tout s'est bien passé
    return(true);
  }

  class StreamManager extends Thread {
    private int runType = 0;
    private int CLength;
    //private BiStream bis;
    private MultiOutputStream mos;
    private byte[] byt;
    //public ResponseMessageHeader rmh = new ResponseMessageHeader();
    public ResMessageHeader rmh;
    private ResponseMessage rep;
    //  private ResponseMessage rep = new ResponseMessage();
    private boolean isBodyExpected = false;
    //-+-+private BiStreamHandle bsh;

    /* données d'échange entre ce Thread et l'objet qui l'appelle */
    public IOException IOEResult = null;
    public int INTResult = 0;
    public ByteArrayOutputStream BAOSba;//DEBUG = new ByteArrayOutputStream();

    /* gestion des cookies au moment de la réponse */
    String hostname = "";
    String path = "";
    GenericCookie ocookie;
    HTMLStamps netstamps;

    // TO DO : supprimer cette référence puisqu'elle est dans la classe supérieure ?
    private Hashtable hConvert = null;

    // RAW mode
    private boolean isRAW = false;

    /*
     * constructeurs
     */
    public StreamManager() {}

    public MultiOutputStream getMultiPrintStream() {
      return this.mos;
    }

    /*
     * accesseurs
     */
    public void setCLength(int CLength) {
      this.CLength = CLength;
      runType = 2;
    }

    public void setAction(MultiOutputStream mos, String action, byte[] byt) {
      this.mos = mos;
      this.byt = byt;

      if(action.equals("SendRequest")) {
        runType = 3;
        //System.err.println("setting action=sendRequest");
      }

      if(action.equals("keepAlive")) {
        runType = 3;
        //System.err.println("setting action=keepAlive");
      }

      if(action.equals("SendPercolatedRequest")) {
        runType = 6;
      }
    }

    public void setAction(MultiOutputStream mos, String action) {
      this.mos = mos;

      if(action.equals("readHeader")) {
        runType = 4;
      }
      else // this should never happen !!
        System.err.println("program unsafe, coding error : " + action + " instead of readHeader");
    }

    public void setAction(MultiOutputStream mos, String action, HTMLStamps netstamps) {
      this.mos = mos;
      this.netstamps = netstamps;

      if(action.equals("readHeader")) {
        runType = 12;
      }
      else // this should never happen !!
        System.err.println("program unsafe, coding error : " + action + " instead of readHeader");
    }

    public void setAction(MultiOutputStream mos, String action, boolean isRAW) {
      this.mos = mos;
      this.isRAW = isRAW;

      if(action.equals("buildNonBlockedBody")) {
        runType = 1;
      }

      if(action.equals("readChunkLength"))
        runType = 7;

      if(action.equals("readFooter"))
        runType = 9;
    }

    // TO DO : supprimer cette méthode
    public void setAction(MultiOutputStream mos, String action, Hashtable hConvert) {
      this.mos = mos;


      if(action.equals("buildNonBlockedBody")) {
        runType = 1;
      }

      if(action.equals("readChunkLength"))
        runType = 7;

      if(action.equals("readFooter"))
        runType = 9;
    }

    public void setAction(MultiOutputStream mos, String action, ResponseMessage rep, boolean isbodyexpected) {
      this.mos = mos;

      if(action.equals("writeBody")) {
        runType = 5;
        this.rep = rep;
        //this.hConvert = hConvert;
        isBodyExpected = isbodyexpected;
        //System.err.println("setting action=writeBody");
      }
    }

    public void setAction(BiStreamHandle bsh, MultiOutputStream mos, String action, ResponseMessage rep, boolean isbodyexpected) {
//      this.bis = bsh.getBiStream();
      this.mos = mos;

      if(action.equals("writeBody")) {
        runType = 5;
        this.rep = rep;
        isBodyExpected = isbodyexpected;
        //System.err.println("setting action=writeBody");
      }
    }

    public void setAction(MultiOutputStream mos, String action, boolean keepalive, Hashtable hConvert) {
      this.mos = mos;

      if(action.equals("buildBody")) {
        if(hConvert != null) {
          this.hConvert = hConvert;
          runType = 10;
        }
        else
          runType = 0;

        //System.err.println("setting action=writeBody");
      }
    }

    public void setAction(MultiOutputStream mos, String action, int CLength, Hashtable hConvert) {
      this.mos = mos;
      this.CLength = CLength;

      if(action.equals("buildBody")) {
        if(hConvert != null) {
          runType = 11;
          this.hConvert = hConvert;
        }
        else
          runType = 2;
      }

      if(action.equals("buildChunkData")) {
        if(hConvert != null) {
          this.hConvert = hConvert;
          runType = 13;
        }
        else
          runType = 8;
      }

    }

    /*
     * runner
     TO DO : vérifier les cas (in)utiles
     */
    public void run() {
      switch(runType) {
        case 0:
          bis.multiply(mos);
          break;

        case 1:
          bis.multiplynotblocked(mos);
          break;

        case 2:
          bis.multiply(mos, CLength);
          break;

        case 3: // SendRequest
          try {
            bis.write(byt, mos);
          }
          catch(IOException ioe) {
            IOEResult = ioe;
          }

          break;

          /*
           * ReadHeader
           * remarque importante : le serveur ne renvoie pas toujours une réponse constituée de response-header + response-body
           * par exemple une réponse constituée uniquement de response-body lorsque l'on envoi en clair sur un port HTTPS de Weblogic
           * on veut pouvoir traiter ce cas de manière "propre" et afficher tout ce que le serveur a envoyé
           */
        case 4:
          try {
            ByteArrayOutputStream baos = bis.read(RFCUtil.DCRLF, mos);

            // si rien n'est lu c'est que la socket est fermée côté serveur !
            if(baos.size() != 0) {
              try {
                //rmh = ResponseMessageHeaderFactory.create(baos, this.cookies, this.hostname);
                //rmh = ResponseMessageHeaderFactory.create(baos, this.ocookie, this.hostname, this.path);
                rmh = new ResMessageHeader(baos);
                //rep = new ResponseMessage(rmh);
              }
              catch(MalformedHeaderException e) {
                System.err.println(e);
              }
              catch(HeaderExtraDataException e) {
                System.err.println(e);
              }
            }
            else {
              rmh = null;
              rep = null;
            }
          }
          catch(UncompletedReadingException ure) {
            System.err.println(ure);
          }

          break;

        case 5:
          //rep.writeBody(bis, mos, isBodyExpected);
          break;

        case 6: // SendPercolatedRequest
          if(byt.length > 1) {
            byte[] dest = new byte[byt.length - 1];
            System.arraycopy(byt, 1, dest, 0, byt.length - 1);

            try {
              bis.write(byt[0], mos);
              bis.write(dest, mos);
            }
            catch(IOException ioe) {
              // mise à jour de la variable d'échange permettant de remonter l'info échec/réussite vers l'appellant
              IOEResult = ioe;
            }
          }
          else
            System.err.println("pas assez de données pour cette opération (TO DO: requête intégrale)");

          break;

        case 7:

          // indication fournie par RFC2616 §3.6.1, lecture du 'chunk-size'
          // TO DO : renvoyer pas seulement chunk-size mais aussi chunk-extension si ce champ existe
          try {
            byte[] bb = isRAW ? bis.read(RFCUtil.CRLF, mos).toByteArray() : bis.read(RFCUtil.CRLF).toByteArray();

            if(bb.length != 0) {
              // bug Apache => le ";" ou CRLF n'est pas toujours collé au 'chunk-size' donc on ignore les caractères supplémentaires (ou bien 'trim')
              int ibb = 0;
              boolean blnStop = false;

              while((ibb < bb.length) && !blnStop) {
                // le caractère est hexadécimal donc appartient à [0-9a-fA-F]
                if( ((bb[ibb] >= 48) && (bb[ibb] <= 57)) || ((bb[ibb] >= 65) && (bb[ibb] <= 70)) || ((bb[ibb] >= 97) && (bb[ibb] <= 102)) )
                  ibb++;
                else {
                  blnStop = true;
                  // DEBUG : System.err.println(bb[ibb]);
                }
              }

              // conversion hexa => décimal + sauvegarde dans la donnée d'échange
              String sRez = new String(bb, 0, ibb);
              //DEBUG : for(int i = 0; i< sRez.length(); i++)
              //DEBUG : System.err.println( (sRez.getBytes())[i] );
              //DEBUG : System.err.println(bb[ibb]);
              INTResult = Integer.parseInt(sRez, 16);

            }
          }
          catch(UncompletedReadingException ure) {
            System.err.println(ure);
          }

          break;

        case 8: // buildChunkData : lire le chunk-data et ignorer le CRLF qui le suit
          bis.multiply(mos, CLength);
          bis.skip(2);
          break;

        case 9: //readFooter
          try {
            // TO DO : vérifier dans quelles conditions le footer doit apparaitre ou être masqué, est-ce bien le mode RAW ????
            ByteArrayOutputStream baoss = isRAW ? bis.read(RFCUtil.CRLF, mos) : bis.read(RFCUtil.CRLF);

            // si rien n'est lu c'est qu'il n'y a pas de footer
            if(baoss.size() != 0)
              BAOSba = baoss;
            else
              BAOSba = null;
          }
          catch(UncompletedReadingException ure) {
            System.err.println(ure);
          }

          break;

        case 10:
          bis.multiply(mos, hConvert);
          break;

        case 11:
          bis.multiply(mos, CLength, hConvert);
          break;

          /*
           * ReadHeader
           * remarque importante : le serveur ne renvoie pas toujours une réponse constituée de response-header + response-body
           * par exemple une réponse constituée uniquement de response-body lorsque l'on envoi en clair sur un port HTTPS de Weblogic
           * on veut pouvoir traiter ce cas de manière "propre" et afficher tout ce que le serveur a envoyé
           */
        case 12:
          try {
            ByteArrayOutputStream baos = bis.read(RFCUtil.DCRLF, mos, netstamps);

            // si rien n'est lu c'est que la socket est fermée côté serveur !
            if(baos.size() != 0) {
              try {
                //rmh = ResponseMessageHeaderFactory.create(baos, this.ocookie, this.hostname, this.path);
                rmh = new ResMessageHeader(baos);
              }
              catch(MalformedHeaderException e) {
                System.err.println(e);
              }
              catch(HeaderExtraDataException e) {
                System.err.println(e);
              }
            }
            else {
              rmh = null;
              rep = null;
            }
          }
          catch(UncompletedReadingException ure) {
            System.err.println(ure);
          }

          break;

        case 13: // buildChunkData + conversion: lire le chunk-data et ignorer le CRLF qui le suit
          bis.multiply(mos, CLength, hConvert);
          bis.skip(2);
          break;
      }

      mos = null;
    }

    /*
     * stoppeur (consiste à propager l'ordre d'arrêt à l'objet concerné)
     */
    public void stopit() {
      bis.stopit();
    }

  }

}

/*
 * classe implémentant le stream de connection, permettant notamment la synchronisation des flux
 */
class BiStream {
  private InputStream in;
  private OutputStream out;
  private int inBufferSize;
  public boolean stopit = false;

  /*
   * constructeur
   */
  public BiStream(InputStream in, OutputStream out, int SO_RCVBUF) {
    this.in = in;
    this.out = out;
    this.inBufferSize = SO_RCVBUF;
  }

  /*
   * stopper (quelle que soit l'action engagée, il faut l'arrêter)
   */
  public void stopit() {
    stopit = true;

    close();
  }

  /*
   * skip n characters
   */

  public synchronized void skip(long ski) {
    try {
      in.skip(ski);
    }
    catch(IOException ioe) {}
  }

  /*
   * écrire un stream + flux
   */

  public synchronized void write(byte[] byt, MultiOutputStream mos) throws IOException {
    try {
      int i = 0, il = byt.length;

      while(!stopit && (i < il)) {
        out.write(byt[i]);

        if(mos != null)
          mos.write(byt[i]);

        i++;
      }

      out.flush();

      if(mos != null)
        mos.flush();
    }
    catch(UnknownHostException e) {
      System.err.println(e);
    }

    // on laisse IOException remonter pour prise en compte
  }


  /*
   * écrire un byte + flux
   */

  public synchronized void write(byte byt, MultiOutputStream mos) throws IOException {
    try {
      out.write(byt);

      if(mos != null)
        mos.write(byt);

      out.flush();

      if(mos != null)
        mos.flush();
    }
    catch(UnknownHostException e) {
      System.err.println(e);
    }

    // on laisse IOException remonter pour prise en compte
  }

  /*
   * lire le stream avec condition d'arrêt : STRING
   */

  public synchronized ByteArrayOutputStream read(String suffixe, MultiOutputStream mos) throws UncompletedReadingException {
    byte[] suf = suffixe.getBytes();
    int i = 0, intTmp;
    boolean blnBreak = false;
    ByteArrayOutputStream baos = new ByteArrayOutputStream();

    try {
      while (!stopit && !blnBreak && (intTmp = in.read()) != -1) {
        if(suf[i] == intTmp) {
          i++;

          if(i == suf.length)
            blnBreak = true;
        }
        else
          i = 0;

        baos.write(intTmp);

        if(mos != null)
          mos.write(intTmp);
      }

      // éviter les opérations inutiles
      if(baos.size() != 0) {
        if(mos != null)
          mos.flush();

        if(!blnBreak)
          throw new UncompletedReadingException(suffixe + " was not found");
      }
    }
    catch(IOException ioe) {
      System.err.println(ioe);
    }

    return baos;
  }

  /*
   * lire le 1er octet du stream et faire suivre la lecture
   */

  public synchronized ByteArrayOutputStream read(String suffixe, MultiOutputStream mos, HTMLStamps netstamps) throws UncompletedReadingException {
    byte[] suf = suffixe.getBytes();
    int i = 0, intTmp;
    boolean blnBreak = false;
    ByteArrayOutputStream baos = new ByteArrayOutputStream();

    Date d1 = new Date();

    try {
      if( (intTmp = in.read()) != -1 ) {

        // 1er caractère de suffixe détecté, on doit le supprimer de passer la main
        String suffixe2 = (suf[i] == intTmp) ? suffixe.substring(1) : suffixe;

        baos.write(intTmp);

        if(mos != null)
          mos.write(intTmp);

        if(netstamps != null) {
          Date d2 = new Date();
          netstamps.log(d2.getTime() - d1.getTime());
        }

        ByteArrayOutputStream baos2 = read(suffixe2, mos);
        baos2.writeTo(baos);
      }

      // éviter les opérations inutiles
      if(baos.size() != 0) {
        if(mos != null)
          mos.flush();
      }
    }
    catch(IOException ioe) {
      System.err.println(ioe);
    }

    return baos;
  }

  /*
   * lire le stream avec condition d'arrêt : STRING, sans écrire en parallèle
   */

  public synchronized ByteArrayOutputStream read(String suffixe) throws UncompletedReadingException {
    byte[] suf = suffixe.getBytes();
    int i = 0, intTmp;
    boolean blnBreak = false;
    ByteArrayOutputStream baos = new ByteArrayOutputStream();

    try {
      while (!stopit && !blnBreak && (intTmp = in.read()) != -1) {
        if(suf[i] == intTmp) {
          i++;

          if(i == suf.length)
            blnBreak = true;
        }
        else
          i = 0;

        baos.write(intTmp);
      }

      if(!blnBreak)
        throw new UncompletedReadingException(suffixe + " was not found");

    }
    catch(IOException ioe) {
      System.err.println(ioe);
    }

    return baos;
  }


  /*
   * copie multiple du stream d'entrée vers les streams de sortie (mode blocking)
   * la fonction s'arrête dès que la socket est fermée d'un côté ou de l'autre (cas normal : fermeture par le serveur ou bien interruption client)
   */

  public synchronized void multiply(MultiOutputStream mos) {
    try {
      int intTmp;
      byte[] buf = new byte[inBufferSize];

      while( !stopit && (intTmp = in.read(buf)) != -1) {
        if(mos != null) {
          mos.write(buf, 0, intTmp);
          mos.flush();
        }
      }
    }
    catch(IOException ioe) {
      System.err.println(ioe);
    }
  }

  public synchronized void multiply(MultiOutputStream mos, Hashtable hConvert) {
    try {
      int intTmp;
      byte[] buf = new byte[inBufferSize];

      while( !stopit && (intTmp = in.read(buf)) != -1) {

        // il y a des données à lire ?
        if(mos != null) {
          ByteArrayOutputStream bout = new ByteArrayOutputStream(intTmp);

          // parcours du buffer
          for(int i = 0; i < intTmp; i++) {

            boolean blnFound = false;

            // parcours de la table de conversion
            for (Enumeration eK = hConvert.keys() ; eK.hasMoreElements() ;) {
              Byte b = (Byte)(eK.nextElement());

              // on a trouvé 1 occurence, action : convertir et s'arrête
              if(!blnFound && (b.byteValue() == buf[i]) ) {
                blnFound = true;
                String val = (String)(hConvert.get(b));
                bout.write(val.getBytes());
              }
            }

            // pas de conversion réalisée, action : copier le byte
            if(!blnFound) {
              bout.write(buf[i]);
            }

          }

          // envoie la purée
          mos.write(bout.toByteArray());
          mos.flush();
        }
      }
    }
    catch(IOException ioe) {
      System.err.println(ioe);
    }
  }

  /*
   * copie multiple du stream d'entrée vers les streams de sortie (mode blocking)
   * le nombre de caractères à lire est donné par CLength
   * la fonction s'arrête dès que la socket est fermée d'un côté ou de l'autre (cas normal : fermeture par le serveur ou bien interruption client)
   * la difficulté principale est que l'on ne connait pas par avance le nombre de bytes disponibles (au maximum inBufferSize mais pas forcément).
   */

  public synchronized void multiply(MultiOutputStream mos, int CLength) {

    try {
      int intTmp, iLength = 0;

      // calcul du 1er segment à lire
      byte[] buf = (inBufferSize < CLength) ? new byte[inBufferSize] : new byte[CLength] ;

      if(mos != null) {
        while( (!stopit) && (iLength < CLength) && ((intTmp = in.read(buf)) != -1) ) {

          mos.write(buf, 0, intTmp);
          mos.flush();

          iLength += intTmp;

          // calcul du prochain segment à lire
          int modulo = (CLength - iLength) / inBufferSize;

          if(modulo >= 1)
            buf = new byte[inBufferSize];
          else
            buf = new byte[CLength - iLength];

        } // end while
      }
      else {
        while( (!stopit) && (iLength < CLength) && ((intTmp = in.read(buf)) != -1) ) {

          iLength += intTmp;

          // calcul du prochain segment à lire
          int modulo = (CLength - iLength) / inBufferSize;

          if(modulo >= 1)
            buf = new byte[inBufferSize];
          else
            buf = new byte[CLength - iLength];

        } // end while
      }
    }
    catch(IOException ioe) {
      System.err.println(ioe);
    }

    //System.err.println("fin: multiply," + iLength + " au lieu de " + CLength);
  }

  public synchronized void multiply(MultiOutputStream mos, int CLength, Hashtable hConvert) {
    try {
      int intTmp, iLength = 0;
      byte[] buf = (inBufferSize < CLength) ? new byte[inBufferSize] : new byte[CLength] ;

      if(mos != null) {
        while( (!stopit) && (iLength < CLength) && ((intTmp = in.read(buf)) != -1) ) {

          /* dedicated part for handling mos output */
          ByteArrayOutputStream bout = new ByteArrayOutputStream(intTmp);

          // parcours du buffer
          for(int i = 0; i < intTmp; i++) {

            boolean blnFound = false;

            // parcours de la table de conversion
            for (Enumeration eK = hConvert.keys() ; eK.hasMoreElements() ;) {
              Byte b = (Byte)(eK.nextElement());

              // on a trouvé 1 occurence, action : convertir et s'arrêter
              if(!blnFound && (b.byteValue() == buf[i]) ) {
                blnFound = true;
                String val = (String)(hConvert.get(b));
                bout.write(val.getBytes());
              }
            }

            // pas de conversion réalisée, action : copier le byte
            if(!blnFound) {
              bout.write(buf[i]);
            }

          }

          // it's time to output
          mos.write(bout.toByteArray());
          mos.flush();
          /* end of dedicated part for handling mos output */

          iLength += intTmp;

          // calcul du prochain segment à lire
          int modulo = (CLength - iLength) / inBufferSize;

          if(modulo >= 1)
            buf = new byte[inBufferSize];
          else
            buf = new byte[CLength - iLength];

        } // end while
      }
      else {
        while( (!stopit) && (iLength < CLength) && ((intTmp = in.read(buf)) != -1) ) {
          iLength += intTmp;

          // calcul du prochain segment à lire
          int modulo = (CLength - iLength) / inBufferSize;

          if(modulo >= 1)
            buf = new byte[inBufferSize];
          else
            buf = new byte[CLength - iLength];
        }
      }
    }
    catch(IOException ioe) {
      System.err.println(ioe);
    }

  }

  /*
   * copie multiple du stream d'entrée vers les streams de sortie (mode blocking)
   * et remplace le caractère oldRE par la chaîne newRE
   * la fonction s'arrête dès que la socket est fermée d'un côté ou de l'autre (cas normal : fermeture par le serveur ou bien interruption client)
   */

  public synchronized void multiply(MultiOutputStream mos, byte oldRE, String newRE) {
    try {
      int intTmp;
      byte[] buf = new byte[inBufferSize];

      while( !stopit && (intTmp = in.read(buf)) != -1) {

        // il y a des données à lire ?
        if(mos != null) {
          ByteArrayOutputStream bout = new ByteArrayOutputStream(intTmp);

          // parcours du buffer
          for(int i = 0; i < intTmp; i++) {
            if(buf[i] == oldRE) {
              // occurence trouvée, on remplace
              bout.write(newRE.getBytes());
            }
            else {
              bout.write(buf[i]);
            }
          }

          // envoie la purée
          mos.flush();
        }
      }
    }
    catch(IOException ioe) {
      System.err.println(ioe);
    }
  }

  /*
   * copie multiple du stream d'entrée vers les streams de sortie (mode blocking)
   * et remplace le caractère oldRE par la chaîne newRE
   * le nombre de caractères à lire est donné par CLength
   * la fonction s'arrête dès que la socket est fermée d'un côté ou de l'autre (cas normal : fermeture par le serveur ou bien interruption client)
   */

  public synchronized void multiply(MultiOutputStream mos, int CLength, byte oldRE, String newRE) {
    try {
      int intTmp, iLength = 0;
      byte[] buf = (inBufferSize < CLength) ? new byte[inBufferSize] : new byte[CLength] ;

      while( (!stopit) && (iLength < CLength) && ((intTmp = in.read(buf)) != -1) ) {

        // il y a des données à lire ?
        if(mos != null) {
          ByteArrayOutputStream bout = new ByteArrayOutputStream(intTmp);

          // parcours du buffer
          for(int i = 0; i < intTmp; i++) {
            if(buf[i] == oldRE) {
              // occurence trouvée, on remplace
              bout.write(newRE.getBytes());
            }
            else {
              bout.write(buf[i]);
            }
          }

          // envoie la purée
          mos.flush();
        }

        // calcul du restant à lire
        iLength += intTmp;

        // calcul du prochain segment à lire
        int modulo = (CLength - iLength) / inBufferSize;

        if(modulo >= 1)
          buf = new byte[inBufferSize];
        else
          buf = new byte[CLength - iLength];

      }
    }
    catch(IOException ioe) {
      System.err.println(ioe);
    }
  }

  /*
   * copie multiple du stream d'entrée vers les streams de sortie (mode non blocking)
   */

  public synchronized void multiplynotblocked(MultiOutputStream mos) {
    try {
      int intTmp;
      byte[] buf = new byte[inBufferSize];

      while( !stopit && in.available() != 0) {
        intTmp = in.read(buf);

        if(mos != null) {
          mos.write(buf, 0, intTmp);
          mos.flush();
        }
      }
    }
    catch(IOException ioe) {
      System.err.println(ioe);
    }
  }


  public void flush() throws IOException {
    out.flush();
  }

  public void close() {
    try {
      if(in != null)
        in.close();
    }
    catch(IOException ioe) {} // ignored
    finally {
      in = null;
    }

    try {
      if(out != null)
        out.close();
    }
    catch(IOException ioe) {} // ignored
    finally {
      out = null;
    }
  }

}

/*
 * classe implémentant la connexion HTTP
 */
class PlainTransaction extends HTTPTransaction {

  /*
   * constructeur : on a besoin de connaitre le mos pour les sorties (TO DO : en paramètre)
   */
  public PlainTransaction() {}
  public PlainTransaction(MultiOutputStream mos) {
    super(mos);
  }
  public PlainTransaction(BiStreamHandle bsh, MultiOutputStream mos) {
    super(bsh, mos);
  }
  // constructor with multiple outputs (this allows filtering parts of request/response)
  public PlainTransaction(BiStreamHandle bsh, MultiOutputStream[] mps, boolean htmlstamps) {
    super(bsh, mps, htmlstamps);
  }
  // constructor with multiple outputs (this allows filtering parts of request/response)
  public PlainTransaction(BiStreamHandle bsh, MultiOutputStream[] mps, HTMLStamps stamps) {
    super(bsh, mps, stamps);
  }
  public PlainTransaction(BiStreamHandle bsh, MultiOutputStream[] mps, boolean htmlstamps, GenericCookie cookies) {
    super(bsh, mps, htmlstamps, cookies);
  }
  public PlainTransaction(BiStreamHandle bsh, MultiOutputStream[] mps, HTMLStamps htmlstamps, GenericCookie cookies) {
    super(bsh, mps, htmlstamps, cookies);
  }
  public PlainTransaction(BiStreamHandle bsh, MultiOutputStream[] mps, boolean htmlstamps, GenericCookie cookies, Hashtable convertByteToString) {
    super(bsh, mps, htmlstamps, cookies, convertByteToString);
  }
  public PlainTransaction(BiStreamHandle bsh, MultiOutputStream[] mps, boolean htmlstamps, boolean netstamps, GenericCookie cookies, Hashtable convertByteToString) {
    super(bsh, mps, cookies, convertByteToString);

    if(htmlstamps)
      this.stamps = new HTMLStamps1();

    if(netstamps)
      this.nstamps = new NETStamps1();
  }
  public PlainTransaction(BiStreamHandle bsh, MultiOutputStream[] mps, boolean htmlstamps, boolean netstamps, boolean resolveDNS, GenericCookie cookies, Hashtable convertByteToString, boolean israw) {
    super(bsh, mps, cookies, convertByteToString, resolveDNS, israw);

    if(htmlstamps)
      this.stamps = new HTMLStamps1();

    if(netstamps)
      this.nstamps = (resolveDNS) ? new NETStamps1_DNS() : new NETStamps1();
  }
  public PlainTransaction(BiStreamHandle bsh, MultiOutputStream[] mps, boolean htmlstamps, boolean netstamps, boolean resolveDNS, Hashtable convertByteToString, boolean israw) {
    super(bsh, mps, convertByteToString, resolveDNS, israw);

    if(htmlstamps)
      this.stamps = new HTMLStamps1();

    if(netstamps)
      this.nstamps = (resolveDNS) ? new NETStamps1_DNS() : new NETStamps1();
  }
  public PlainTransaction(BiStreamHandle bsh, MultiOutputStream[] mps, HTMLStamps htmlstamps, GenericCookie cookies, Hashtable convertByteToString) {
    super(bsh, mps, htmlstamps, cookies, convertByteToString);
  }
  public PlainTransaction(BiStreamHandle bsh, MultiOutputStream[] mps, HTMLStamps htmlstamps, HTMLStamps netstamps, GenericCookie cookies, Hashtable convertByteToString) {
    super(bsh, mps, htmlstamps, netstamps, cookies, convertByteToString);
  }

  /*
   * initialize la connexion vers le serveur
   */

  public synchronized boolean initConnection(CookieWrapper wrapper) {
    boolean rezult = true;

    try {

      Date d1;
      String sip;

      // résolution DNS lorsque spécifié
      if(resolveDNS) {
        Date d0 = new Date();
        sip = resolve(requestMessage.getHostname());
        d1 = new Date();

        if(nstamps != null)
          nstamps.log( d1.getTime() - d0.getTime(), sip );
          //nstamps.log( d1.getTime() - d0.getTime() + "" + sip );
      }
      else {
        sip = requestMessage.getHostname();
        d1 = new Date();
      }

      Socket daSocket = new Socket(sip, (new Integer(requestMessage.getPort())).intValue() );
      OutputStream outputS = new BufferedOutputStream(daSocket.getOutputStream(), 2048);
      InputStream inputS = daSocket.getInputStream();
      BiStream bs = new BiStream(inputS, outputS, daSocket.getReceiveBufferSize());
      bsh.setBiStream(bs);

      Date d2 = new Date();

      if(getHTMLStamps())
        System.err.println("timestamp init: " + (d2.getTime() - d1.getTime()) + " ms");

      if(nstamps != null)
        nstamps.log( d2.getTime() - d1.getTime() );
    }
    catch(javax.naming.NamingException ne) {
      System.err.println(ne);
      rezult = false;
    }
    catch(UnknownHostException uhe) {
      System.err.println(uhe);
      rezult = false;
    }
    catch(IOException ie) {
      System.err.println(ie);
      rezult = false;
    }

    return rezult;
  }

}

/*
 * classe implémentant la connexion HTTP via Proxy
 */
class PlainTransactionViaProxy extends HTTPTransaction {
  private String proxyname = "";
  private int proxyport = 0;

  /*
   * constructeurs
   */
  public PlainTransactionViaProxy() { }
  public PlainTransactionViaProxy(BiStreamHandle bsh, MultiOutputStream mos) {
    super(bsh, mos);
  }
  public PlainTransactionViaProxy(BiStreamHandle bsh, MultiOutputStream[] mps, boolean htmlstamps, boolean netstamps, boolean resolveDNS, GenericCookie cookies, Hashtable convertByteToString, boolean isRaw) {
    super(bsh, mps, cookies, convertByteToString, resolveDNS, isRaw);

    if(htmlstamps)
      this.stamps = new HTMLStamps1();

    if(netstamps)
      this.nstamps = (resolveDNS) ? new NETStamps1_DNS() : new NETStamps1();
  }
  public PlainTransactionViaProxy(BiStreamHandle bsh, MultiOutputStream[] mps, boolean htmlstamps, boolean netstamps, boolean resolveDNS, Hashtable convertByteToString, boolean isRaw) {
    super(bsh, mps, convertByteToString, resolveDNS, isRaw);

    if(htmlstamps)
      this.stamps = new HTMLStamps1();

    if(netstamps)
      this.nstamps = (resolveDNS) ? new NETStamps1_DNS() : new NETStamps1();
  }

  /*
   * accessors
   */
  public void setProxyName(String proxyname) {
    this.proxyname = proxyname;
  }

  public void setProxyPort(int proxyport) {
    this.proxyport = proxyport;
  }
  public String getProxyName() {
    return proxyname;
  }
  public int getProxyPort() {
    return proxyport;
  }


  /*
   * initialize la connexion vers le proxy
   */

  public synchronized boolean initConnection(CookieWrapper wrapper) {
    boolean rezult = true;

    try {

      Date d1;
      String sip;

      // résolution DNS lorsque spécifié
      if(resolveDNS) {
        Date d0 = new Date();
        sip = resolve(proxyname);
        d1 = new Date();

        if(nstamps != null)
          nstamps.log( d1.getTime() - d0.getTime() );
      }
      else {
        sip = proxyname;
        d1 = new Date();
      }

      Socket daSocket = new Socket(sip, proxyport);
      OutputStream outputS = new BufferedOutputStream(daSocket.getOutputStream(), 2048);
      InputStream inputS = daSocket.getInputStream();
      BiStream bs = new BiStream(inputS, outputS, daSocket.getReceiveBufferSize());
      bsh.setBiStream(bs);

      Date d2 = new Date();

      if(getHTMLStamps())
        System.err.println("timestamp init: " + (d2.getTime() - d1.getTime()) + " ms");

      if(nstamps != null)
        nstamps.log( d2.getTime() - d1.getTime() );
    }
    catch(javax.naming.NamingException ne) {
      System.err.println(ne);
      rezult = false;
    }
    catch(UnknownHostException uhe) {
      System.err.println(uhe);
      rezult = false;
    }
    catch(IOException ie) {
      System.err.println(ie);
      rezult = false;
    }

    return rezult;
  }

  /*
   * envoie la requête
   */

  public synchronized boolean sendRequest() {

    Date d1 = new Date();

    boolean rez = bsh.sendRequest(getMyMultiPrintStream("request"), requestMessage.getMessageInBytes(true));

    Date d2 = new Date();

    if(getHTMLStamps())
      System.err.println("timestamp sendrequest: " + (d2.getTime() - d1.getTime()) + " ms");

    if(stamps != null)
      stamps.log( d2.getTime() - d1.getTime() );

    return rez;
  }

}

class RFC3986 {


}

class RFC2396 {

  static final String digit = "(\\d)";
  static final String upalpha = "([A-Z])";
  static final String lowalpha = "([a-z])";
  static final String alpha = "(" + upalpha + "|" + lowalpha + ")";
  static final String alphanum = "(" + alpha + "|" + digit + ")";
  static final String hex = "(" + digit + "|[A-F]|[a-f])";
  static final String escaped = "(%" + hex + hex + ")";
  static final String mark = "(-|_|\\.|!|~|\\*|'|\\(|\\))";
  static final String unreserved = "(" + alphanum + "|" + mark + ")";
  static final String reserved = "(;|/|\\?|:|@|&|=|\\+|\\$|,)";
  static final String uric = "(" + reserved + "|" + unreserved + "|" + escaped + ")";
  static final String fragment = "((" + uric + ")*)";
  static final String query = "((" + uric + ")*)";
  static final String pchar = "(" + unreserved + "|" + escaped + "|:|@|&|=|\\+|\\$|,)";
  static final String param = "((" + pchar + ")*)";
  static final String segment = "(((" + pchar + ")*)((;" + param + ")*))";
  static final String path_segments = "(" + segment + "((/" + segment  + ")*))";

  static final String port = "((" + digit + ")*)";
  static final String IPv4address = "((" + digit + ")+\\." + "(" + digit + ")+\\." + "(" + digit + ")+\\." + "(" + digit + ")+)";
  static final String toplabel = "(" + alpha + "|(" + alpha + "(" + alphanum + "|-)*" + alphanum + "))";
  static final String domainlabel = "(" + alphanum + "|(" + alphanum + "(" + alphanum + "|-)*" + alphanum + "))";
  static final String hostname = "((" + domainlabel + "\\.)*" + toplabel + "\\.?)";
  static final String host = "(" + hostname + "|" + IPv4address + ")";
  static final String hostport = "(" + host + "(:" + port + ")?)";

  static final String userinfo = "((" + unreserved + "|" + escaped + "|;|:|&|=|\\+|\\$|,)*)";
  static final String server = "(((" + userinfo + "@)?" + hostport + ")?)";

  static final String reg_name = "((" + unreserved + "|" + escaped + "|\\$|,|;|:|@|&|=|\\+)+)";
  static final String authority = "(" + server + "|" + reg_name + ")";
  static final String scheme = "(" + alpha + "(" + alpha + "|" + digit + "|\\+|-|\\.)*"  + ")";
  static final String rel_segment = "((" + unreserved + "|" + escaped + "|;|@|&|=|\\+|\\$|,)?)";

  static final String abs_path = "(/" + path_segments + ")";
  static final String rel_path = "(" + rel_segment + "(" + abs_path + ")?)";
  static final String net_path = "(//" + authority + "(" + abs_path + ")?)";

  static final String uric_no_slash = "(" + unreserved + "|" + escaped + "|;|\\?|:|@|&|=|\\+|\\$|,)";
  static final String opaque_part = "(" + uric_no_slash + "(" + uric + ")*)";

  static final String path = "((" + abs_path + "|" + opaque_part + ")?)";

  static final String hier_part = "((" + net_path + "|" + abs_path + ")(\\?" + query + ")?)";
  static final String relativeURI = "((" + net_path + "|" + abs_path + "|" + rel_path + ")(\\?" + query + ")?)";
  static final String absoluteURI = "(" + scheme + ":(" + hier_part + "|" + opaque_part + "))";
  static final String URIreference = "((" + absoluteURI + "|" + relativeURI + ")?(#" + fragment + ")?)";

  /*
   * vérifie si une string est conforme à isIPv4address
   */
  public static boolean isIPv4address(String str) {
    Pattern pat = Pattern.compile(IPv4address);
    Matcher mat = pat.matcher(str);
    return(mat.matches());
  }

  /*
   * vérifie si une string est conforme à RequestURI
   */
  public static boolean isAbsoluteURI(String str) {
    Pattern pat = Pattern.compile(absoluteURI);
    Matcher mat = pat.matcher(str);
    return(mat.matches());
  }

  /*
   * vérifie si une string est conforme à abs_path
   */
  public static boolean isAbsPath(String str) {
    Pattern pat = Pattern.compile(abs_path);
    Matcher mat = pat.matcher(str);
    return(mat.matches());
  }

  /*
   * vérifie si une string est conforme à abs_path
   */
  public static boolean isAuthority(String str) {
    return true;
  }

  /*
   *
   */
  public static boolean isRelativeURI(String str) {
    Pattern pat = Pattern.compile(relativeURI);
    Matcher mat = pat.matcher(str);
    return(mat.matches());
  }

  /*
   *  vérifie si une string correspond à la définition de 'query', c'est à dire *uric
   */
  public static boolean isQuery(String str) {
    boolean blnRez = true;

    for(int i = 0; i < str.length(); i++) {
      Pattern pat = Pattern.compile(uric);
      Matcher mat = pat.matcher(str.substring(i, i + 1));

      if(!mat.matches())
        blnRez = false;
    }

    return blnRez;
  }

}

class RFCUtil {

  /*
   * définition des statiques
   */
  public final static String DCRLF = "\r\n\r\n";
  public final static String CRLF = "\r\n";
  public final static String SP = " ";
  public final static String NULL = "";

  static final String digit = "(\\d)";

  /*
   * extrait le 'path' d'une url
   * exemple : '/AA/BB/CC.html' renvoie '/AA/BB'
   */
  public static String getPath(String uri) {

    int ind = uri.lastIndexOf("/");

    // il y a théoriquement plusieurs "/" => on extrait la portion de la string qui nous intéresse
    if(ind > 0) {
      return(uri.substring(0, ind));
    }
    else
      return("/");
  }

  /*
   * vérifie si une string est conforme à RequestURI  (RFC 2616 §5.1.2 + ERRATA 2616)
   */
  public static boolean isCorrectRequestURI(String uri) {
    boolean blnRez = false;

    //blnRez = (uri.equals("*") || RFC2396.isAbsoluteURI(uri) || RFC2396.isAbsPath(uri) || RFC2396.isAuthority(uri));
    blnRez = (uri.equals("*") || RFC2396.isAbsoluteURI(uri) || isExtendedAbsPath(uri) || RFC2396.isAuthority(uri));

    return blnRez;
  }

  /*
   * le ERRATA 2616 précise que abs_path peut être suivi d'une query
   */
  public static boolean isExtendedAbsPath(String uri) {
    boolean blnRez;

    if(uri.indexOf("?") > 0) {
      String sabs = uri.substring(0, uri.indexOf("?"));

      if(RFC2396.isAbsPath(sabs)) {
        if(RFC2396.isQuery(uri.substring(uri.indexOf("?") + 1)))
          blnRez = true;
        else blnRez = false;
      }
      else blnRez = false;
    }
    else {
      blnRez = RFC2396.isAbsPath(uri);
    }

    return blnRez;
  }

  /*
   * vérifie si une string est conforme à Status-Code (RFC 2616 §6.1.1)
   */
  public static boolean isCorrectStatusCode(String status) {

    return status.matches("[1-5]{1}[0-9]{1}[0-9]{1}");
  }

  /*
   * vérifie si une string est conforme à Reason-Phrase (RFC 2616 §6.1.1)
   */
  public static boolean isCorrectReasonPhrase(String status) {

    // par définition reason-phrase est de type TEXT
    return(isTEXTString(status));
  }

  /*
   * vérifie si une string est conforme à HTTP-Version (RFC 2616 §3.1 + ERRATA)
   */
  public static boolean isCorrectHTTPVersion(String version) {
    boolean blnRez = true;

    blnRez = version.matches("HTTP/[1-9]{1}[0-9]*.[0-9]{1}[0-9]*");

    return blnRez;
  }

  /*
   *  vérifie si une string est conforme à METHOD (RFC 2616 §5.1.1)
   */
  public static boolean isCorrectMethod(String method) {
    boolean blnRez = false;

    if(method.equals("OPTIONS"))
      blnRez = true;

    if(method.equals("GET"))
      blnRez = true;

    if(method.equals("HEAD"))
      blnRez = true;

    if(method.equals("POST"))
      blnRez = true;

    if(method.equals("PUT"))
      blnRez = true;

    if(method.equals("DELETE"))
      blnRez = true;

    if(method.equals("TRACE"))
      blnRez = true;

    if(method.equals("CONNECT"))
      blnRez = true;

    if(!blnRez) {
      blnRez = isTokenString(method);
    }

    return blnRez;
  }

  /*
   * splitAbsoluteURI v2
   * décompose une string de type AbsoluteURI et retourne ses différents champs (RFC 2616 §3.2.2)
   * aucune vérification faite sur la validité de la string, on suppose que isAbsoluteURI() a été appellé
   */
  public static Hashtable splitAbsoluteURI(String str) {
    Hashtable<String, String> h = new Hashtable<String, String>();
    String s = str;
    int i, j;

    // DEBUG
    System.err.println(str);

    // initialisation des valeurs pour éviter les exceptions, puisque h est de taille variable
    h.put("scheme", "");
    h.put("port", "");
    h.put("path_query", "");
    h.put("host", "");

    i = s.indexOf("://");
    h.put("scheme", s.substring(0, i));

    s = s.substring(i + 3);
    i = s.indexOf(":");
    j = s.indexOf("/");

    if(i > 0) {
      h.put("host", s.substring(0, i));

      if(j > 0) {
        h.put("port", s.substring(i + 1, j));
        h.put("path_query", s.substring(j));
      }
      else {
        h.put("port", s.substring(i + 1));
        h.put("path_query", "/");
      }
    }
    else {
      if(j > 0) {
        h.put("host", s.substring(0, j));
        h.put("path_query", s.substring(j));
      }
      else {
        h.put("host", s);
        h.put("path_query", "/");
      }
    }

    return h;
  }

  /*
   * éclate une string de type AbsoluteURI en ses composantes (RFC 2616 §3.2.2)
   * composantes : scheme host port path_query
   * TO DO : 20060327 re-écrire cette fonction avec un automate à états finis
   */
  /*
  public static Hashtable splitAbsoluteURI(String str) {
   Hashtable h = new Hashtable();
   String s;
   int i, j;

   // DEBUG
   System.err.println(str);

   // initialisation des valeurs pour éviter les exceptions, puisque h est de taille variable
   h.put("scheme", "");
   h.put("port", "");
   h.put("path_query", "");
   h.put("host", "");

   h.put( "scheme", str.substring(0, str.indexOf("://")) );

   s = str.substring(str.indexOf("://") + 3);
   i = s.indexOf(":");
   j = s.indexOf("/");

   //
   if(i>0) {
     if(j>0) { // abs_path est précisé
       if(i<j) { // le port est précisé => scheme://host:port+abs_path
         h.put("host", s.substring(0, i));
         h.put("port", s.substring(i+1, j-i));
         if(s.length() > j)
           h.put("path_query", s.substring(j));
       }
       else {  // port non précisé => scheme://host+abs_path
         h.put("host", s.substring(0, j));
         if(s.length() > j)
           h.put("path_query", s.substring(j));
       }
     }
     else {  // abs_path non précisé => scheme://host:port
       h.put("host", s.substring(0, i));
     }
   }
   else {  // port non précsié
     if(j>0) { // abs_path est précisé
       h.put("host", s.substring(0, j));
       if(s.length() > j)
         h.put("path_query", s.substring(j));
     }
     else {  // ni port ni abs_path
       h.put("host", s);
     }
   }

   return h;
  }
  */

  /*
   * éclate une string de type abs_path en ses composantes (RFC 2616 §3.2.1)
   * composantes : path_query
   * TO DO : blinder les vérifications sur chacune des composantes, éventuellement remonter une Exception
   */
  public static Hashtable splitRelativeURI(String str) {
    Hashtable<String, String> h = new Hashtable<String, String>();
    h.put("path_query", "");


    return h;
  }

  /*
   * vérifie si une string est conforme à TEXT (RFC 2616 §2.2)
   */
  public static boolean isTEXTString(String str) {
    boolean blnRez = true;
    boolean blnCR = false, blnLF = false, blnSP = false;

    byte[] byt = str.getBytes();
    int i = 0;

    while( (i < byt.length) && blnRez) {
      switch(byt[i]) {
        case 13:
          if(!blnCR)
            blnCR = true;
          else
            blnRez = false;

          break;

        case 10:
          if(blnCR && !blnLF)
            blnLF = true;
          else
            blnRez = false;

          break;

        case 32:
          if(blnCR && blnLF && !blnSP)
            blnSP = true;

          break;

        case 9:
          if(blnCR && blnLF && !blnSP)
            blnSP = true;
          else
            blnRez = false;

          break;

        default:
          if( (0 <= byt[i] && byt[i] < 32) || (byt[i] == 127) )
            blnRez = false;
          else {
            if(blnCR) {
              if(blnLF) {
                if(!blnSP)
                  blnRez = false;
              }
              else
                blnRez = false;
            }
          }

          break;
      }

      i++;
    }

    return blnRez;
  }

  /*
   * vérifie si un  caractère est conforme à QDTEXT
   */
  public static boolean isQDTEXTChar(byte onechar) {
    boolean blnRez = true;

    if(isCTLChar(onechar))
      blnRez = false;

    if( (onechar == 9) || (onechar == 32) )
      blnRez = true;

    return blnRez;
  }

  /*
   *  vérifie si un caractère appartient à la famille token (au sens défini par la RFC)
   */
  public static boolean isTokenChar(byte onechar) {
    boolean blnRez = false;

    if( (onechar >= 0) && (onechar <= 127) )
      blnRez = true;

    if(isSeparatorChar(onechar) || isCTLChar(onechar))
      blnRez = false;

    return blnRez;
  }

  /*
   * vérifie si une string correspond bien à un token
   */
  public static boolean isTokenString(String str) {
    boolean blnRez = true;

    byte[] byt = str.getBytes();

    for(int i = 0; i < byt.length; i++) {
      if(!isTokenChar(byt[i])) {
        blnRez = false;
        break;
      }
    }

    return blnRez;
  }

  /*
   * vérifie si un caractère est un caractère de contrôle (CTL) (au sens défini par la RFC)
   */
  public static boolean isCTLChar(byte onechar) {
    boolean blnRez = false;

    if( (onechar >= 0) && (onechar <= 31) )
      blnRez = true;

    if(onechar == 127)
      blnRez = true;

    return blnRez;
  }

  /*
   * vérifie si un caractère est un séparateur (dans le sens défini par la RFC)
   */
  public static boolean isSeparatorChar(byte onechar) {
    boolean blnRez = false;

    switch(onechar) {
      case 40:
        blnRez = true;
        break;

      case 41:
        blnRez = true;
        break;

      case 60:
        blnRez = true;
        break;

      case 62:
        blnRez = true;
        break;

      case 64:
        blnRez = true;
        break;

      case 44:
        blnRez = true;
        break;

      case 59:
        blnRez = true;
        break;

      case 58:
        blnRez = true;
        break;

      case 92:
        blnRez = true;
        break;

      case 34:
        blnRez = true;
        break;

      case 47:
        blnRez = true;
        break;

      case 91:
        blnRez = true;
        break;

      case 93:
        blnRez = true;
        break;

      case 63:
        blnRez = true;
        break;

      case 61:
        blnRez = true;
        break;

      case 123:
        blnRez = true;
        break;

      case 125:
        blnRez = true;
        break;

      case 32:
        blnRez = true;
        break;

      case 9:
        blnRez = true;
        break;
    }

    return blnRez;
  }

  /*
   * generates a GMT date with our custom format
   * this could not be called directly from an 'empty' constructor
   */
  public static String generateDate() {

    GregorianCalendar gcalendar = new GregorianCalendar(new SimpleTimeZone(0, ""));
    gcalendar.setTime(new java.util.Date());

    String sdate = "";
    sdate += (gcalendar.get(Calendar.DAY_OF_MONTH));
    sdate += "/";
    sdate += (gcalendar.get(Calendar.MONTH) + 1);
    sdate += "/";
    sdate += (gcalendar.get(Calendar.YEAR));
    sdate += " ";
    sdate += (gcalendar.get(Calendar.HOUR));
    sdate += ":";
    sdate += (gcalendar.get(Calendar.MINUTE));
    sdate += ":";
    sdate += (gcalendar.get(Calendar.SECOND));

    return sdate;
  }

}

/*
 * OBSOLETE *
 * classe MultiPrintStream permettant la multiplication des PrintStream (écrire sur plusieurs sorties en simultané)
 */
class MultiPrintStream extends PrintStream {

  Vector<OutputStream> streams = new Vector<OutputStream>();

  public MultiPrintStream(OutputStream out) {
    super(out);
    streams.addElement(out);
  }

  public synchronized void addOutputStream(OutputStream out) {
    streams.addElement(out);
  }

  // TO DO : cela doit lancer une exception ou blinder !!

  public synchronized void delOutputStream(OutputStream out) {
    streams.remove(out);
  }

  public synchronized void println(String s) {

    for(Enumeration e = streams.elements(); e.hasMoreElements();) {
      OutputStream out = (OutputStream)e.nextElement();

      // il faut écrire la String + caractère de fin de ligne
      // TO DO : remplacer '\r\n' par caractère de fin de ligne du système
      byte[] sb = new byte[s.length() + 2];
      java.lang.System.arraycopy(s.getBytes(), 0, sb, 0, s.length());
      sb[sb.length - 2] = 13;
      sb[sb.length - 1] = 10;

      try {
        out.write(sb);
        // TO DO : tester ici ? out.flush();
      }
      catch(IOException ioe) {
        System.err.println(ioe);
        throw new RuntimeException(ioe);
      }
    }

  }

  public synchronized void println(Object o) {
    println(o.toString());
  }

  // TO DO : encapsuler tous les autres 'println' de la même manière que la méthode précédente

  public synchronized void write(int b) {

    for (Enumeration e = streams.elements(); e.hasMoreElements();) {
      OutputStream out = (OutputStream) e.nextElement();

      try {
        out.write(b);
      }
      catch(IOException ioe) {
        System.err.println(ioe);
        throw new RuntimeException(ioe);
      }
    }

  }

  public synchronized void write(byte[] data, int offset, int length) {

    for (Enumeration e = streams.elements(); e.hasMoreElements();) {
      OutputStream out = (OutputStream) e.nextElement();

      try {
        out.write(data, offset, length);
      }
      catch(IOException ioe) {
        System.err.println(ioe);
        throw new RuntimeException(ioe);
      }
    }

  }

  public synchronized void write(byte[] data) {

    for (Enumeration e = streams.elements(); e.hasMoreElements();) {
      OutputStream out = (OutputStream) e.nextElement();

      try {
        out.write(data);
      }
      catch(IOException ioe) {
        System.err.println(ioe);
        throw new RuntimeException(ioe);
      }
    }

  }

  public synchronized void flush() {

    for (Enumeration e = streams.elements(); e.hasMoreElements();) {
      OutputStream out = (OutputStream) e.nextElement();

      try {
        out.flush();
      }
      catch(IOException ioe) {
        System.err.println(ioe);
        throw new RuntimeException(ioe);
      }
    }

  }

  public synchronized void close() {

    for (Enumeration e = streams.elements(); e.hasMoreElements();) {
      OutputStream out = (OutputStream) e.nextElement();

      try {
        out.close();
      }
      catch(IOException ioe) {
        System.err.println(ioe);
        throw new RuntimeException(ioe);
      }
    }

  }

}

/*
 * this class allows writings to several OutputStream at the same time
 * usefull for writing the same data, in a File and in a socket for example
 */
class MultiOutputStream extends OutputStream {

  Vector<OutputStream> streams = new Vector<OutputStream>();

  /*
   * constructor : take the OutputStream[] and store in the Vector<OutputStream>
   */
  public MultiOutputStream(OutputStream[] outs) {
    for(OutputStream out : outs)
      streams.addElement(out);
  }

  public synchronized void addOutputStream(OutputStream out) {
    streams.addElement(out);
  }

  public synchronized void delOutputStream(OutputStream out) {
    streams.remove(out);
  }

  public synchronized void write(int b) throws IOException {

    for (Enumeration e = streams.elements(); e.hasMoreElements();) {
      OutputStream out = (OutputStream) e.nextElement();
      out.write(b);
    }

  }

  public synchronized void write(byte[] data, int offset, int length)
  throws IOException {

    for (Enumeration e = streams.elements(); e.hasMoreElements();) {
      OutputStream out = (OutputStream) e.nextElement();
      out.write(data, offset, length);
    }

  }

  public synchronized void write(byte[] data)
  throws IOException {

    for (Enumeration e = streams.elements(); e.hasMoreElements();) {
      OutputStream out = (OutputStream) e.nextElement();
      out.write(data);
    }

  }

  public synchronized void flush() throws IOException {

    for (Enumeration e = streams.elements(); e.hasMoreElements();) {
      OutputStream out = (OutputStream) e.nextElement();
      out.flush();
    }

  }

  public synchronized void close() throws IOException {

    for (Enumeration e = streams.elements(); e.hasMoreElements();) {
      OutputStream out = (OutputStream) e.nextElement();
      out.close();
    }

  }

}

/*
 * basic Scenario class for all the thread type subclasses
 TO DO : passer cette classe en interface puisqu'elle n'est jamais appelée !!!!!
 */
class SimpleScenario extends Thread {
  public HTTPTransaction handle;
  public boolean logtime = true;

  /* once run, indicates if the scenario was run succesfully */
  protected boolean IOState = false;

  /* once run, indicates if the connection should be kept (Keep-Alive) */
  public boolean keepalive = false;

  public HTMLStamps stamps;

  GenericCookie cookies;
  CookieWrapper wrapper;

  /* constructor */
  public SimpleScenario(HTTPTransaction handle) {
    this.handle = handle;
  }
  public SimpleScenario(HTTPTransaction handle, boolean logtime) {
    this.handle = handle;
    this.logtime = logtime;
  }
  public SimpleScenario(HTTPTransaction handle, boolean logtime, GenericCookie cookies) {
    this.handle = handle;
    this.logtime = logtime;
    this.cookies = cookies;
  }
  public SimpleScenario(HTTPTransaction handle,
                        boolean logtime,
                        CookieWrapper cookiewrapper) {
    this.handle = handle;
    this.logtime = logtime;
    this.wrapper = cookiewrapper;
  }
  public SimpleScenario(HTTPTransaction handle, HTMLStamps stamps) {
    this.handle = handle;
    this.stamps = stamps;
  }

  /* accessors */
  protected void setIOState(boolean b) {
    IOState = b;
  }

  public boolean getIOState() {
    return IOState;
  }

  /* runner must be overriden by sub-classes*/
  public void run() { }

  /* stopper */
  public void stopit() {
    System.err.println("simplescenario ABORT");
    handle.stopit();
  }

  /* saves the cookies after the scenario was run */
  public void saveCookies(Vector<RawCookieNetscape> vecCN, Vector<RawCookieV1> vecCV) {
    if(wrapper != null) {
      if(vecCN.size() > 0) {
        wrapper.add(handle.getRequestMessage().getHostname(),
                    RFCUtil.getPath(handle.getRequestMessage().getRequestURI()),
                    (RawCookieNetscape[])vecCN.toArray(new RawCookieNetscape[0]),
                    false);
      }

      if(vecCV.size() > 0) {
        wrapper.add(handle.getRequestMessage().getHostname(),
                    (RawCookieV1[])vecCV.toArray(new RawCookieV1[0]));
      }

      wrapper.saveAll();
    }
  }

}

/*
 * classe implémentant un scénario de requête HTTP
 * permet de séparer la logique de gestion de thread d'avec l'aspect protocole
 *
 */
class HTTPScenario extends SimpleScenario {

  private boolean reuse;
  private boolean blnExportCert;
  // variable d'échange avec celui qui appelle le thread

  public HTTPScenario(HTTPTransaction handle) {
    super(handle);
    this.reuse = false;
    this.logtime = true;
  }
  public HTTPScenario(HTTPTransaction handle, boolean reuse) {
    super(handle);
    this.reuse = reuse;
    this.logtime = true;
  }
  public HTTPScenario(HTTPTransaction handle, boolean reuse, boolean logtime) {
    super(handle, logtime);
    this.reuse = reuse;
  }
  // last constructor 20080127
  public HTTPScenario(HTTPTransaction handle, boolean reuse, boolean logtime, boolean blnExportCert) {
    super(handle, logtime);
    this.reuse = reuse;
    this.blnExportCert = blnExportCert;
  }
  public HTTPScenario(HTTPTransaction handle, boolean reuse, boolean logtime, boolean blnExportCert, GenericCookie cookies) {
    super(handle, logtime, cookies);
    this.reuse = reuse;
    this.blnExportCert = blnExportCert;
  }
  public HTTPScenario(HTTPTransaction handle,
                      boolean reuse,
                      boolean logtime,
                      boolean blnExportCert,
                      CookieWrapper cookiewrapper) {
    super(handle, logtime, cookiewrapper);
    this.reuse = reuse;
    this.blnExportCert = blnExportCert;
  }

  public void run() {
    Date startDate1 = new Date();
    //boolean[] brez = handle.runScenario(reuse, cookies);
    //keepalive = brez[0];
    ScenarioResult sr = handle.runScenario(reuse, wrapper);
    keepalive = sr.getKeepAlive();

    saveCookies( sr.getCookieNetscape(), sr.getCookieV1() );

    //IOState = brez[1];

    Date endDate1 = new Date();

    if(logtime)
      System.err.println("total time " + (endDate1.getTime() - startDate1.getTime()) + " ms");

    // export certificate to file if requested in command-line
    if(blnExportCert) {
      Hashtable h = handle.getHandshakeInfo();

      try {
        // Get the encoded form which is suitable for exporting
        X509Certificate[] certs = (X509Certificate[])h.get("peerCertificates");

        // write to the file
        int i = 0;
        String stmp;

        while(i < certs.length) {
          stmp = (i == 0) ? "webcert.pem" : "AC_" + i + ".pem" ;
          CertificateUtil.exportToFile(certs[i++], stmp);
        }
      }
      catch(NullPointerException npe) {
        // happens for DH_ANON or KERBEROS ciphersuites, do nothing
      }
    }

  } // end run

  public void stopit() {
    handle.stopit();
  }

  public BiStreamHandle getIOBSH() {
    return handle.bsh;
  }

}

abstract class HTTPTransaction {

  /*
   * variables
   */
  //protected String hostname;
  //protected int port;
  protected RequestMessage requestMessage;
  private ResponseMessage responseMessage;
  //protected BiStream biStream;
  //protected BStreamManager bsm;
  public MultiOutputStream mos;
  protected BiStreamHandle bsh;
  // temporary property
  public MultiOutputStream[] mps;
  public boolean htmlstamps = false;
  private boolean netstamps = false;

  public HTMLStamps stamps, nstamps;

  public boolean resolveDNS = false;

  protected RootHandshakeCompletedListener handshakeListener;

  /* flag indiquant si la sortie est en mode RAW (exemple : les chunk-size) */
  protected boolean isRAW = false;

  public Hashtable filteredMultiPrintStream = new Hashtable();

  protected GenericCookie ocookie = null;

  protected boolean stopit = false;

  /* flag pour savoir si on doit executer le initConnection local ou celui-de la classe mère */
  private boolean isTrueAuth = true;

  /* table de conversion byte -> String */
  protected Hashtable convertTable = null;

  /*
   * constructeur
   */
  public HTTPTransaction() {}

  public HTTPTransaction(MultiOutputStream mos) {
    this.mos = mos;
  }

  public HTTPTransaction(BiStreamHandle bsh, MultiOutputStream mos) {
    this.bsh = bsh;
    // TO REMOVE : ligne suivante
    this.mos = mos;
    // TO DO : new system
    this.filteredMultiPrintStream = MPSArrayToHash(new MultiOutputStream[] {mos, mos, mos} );
  }

  // constructor with multiple outputs (this allows filtering parts of request/response)
  public HTTPTransaction(BiStreamHandle bsh, MultiOutputStream[] mps, boolean htmlstamps) {
    this.bsh = bsh;
    this.filteredMultiPrintStream = MPSArrayToHash(mps);
    this.mos = mps[0];
    this.htmlstamps = htmlstamps;
  }
  // constructor with multiple outputs (this allows filtering parts of request/response)
  public HTTPTransaction(BiStreamHandle bsh, MultiOutputStream[] mps, HTMLStamps stamps) {
    this.bsh = bsh;
    this.filteredMultiPrintStream = MPSArrayToHash(mps);
    this.mos = mps[0];
    this.stamps = stamps;
  }

  // constructor with multiple outputs (this allows filtering parts of request/response)
  public HTTPTransaction(BiStreamHandle bsh, MultiOutputStream[] mps, boolean htmlstamps, GenericCookie cookz) {
    this.bsh = bsh;
    this.filteredMultiPrintStream = MPSArrayToHash(mps);
    this.mos = mps[0];
    this.htmlstamps = htmlstamps;
    this.ocookie = cookz;
  }
  // constructor with multiple outputs (this allows filtering parts of request/response)
  public HTTPTransaction(BiStreamHandle bsh, MultiOutputStream[] mps, HTMLStamps stamps, GenericCookie cookz) {
    this.bsh = bsh;
    this.filteredMultiPrintStream = MPSArrayToHash(mps);
    this.mos = mps[0];
    this.stamps = stamps;
    this.ocookie = cookz;
  }

  // constructor with multiple outputs, cookie support, convert table (bytes -> String)
  public HTTPTransaction(BiStreamHandle bsh, MultiOutputStream[] mps, boolean htmlstamps, GenericCookie cookz, Hashtable convertTable) {
    this.bsh = bsh;
    this.filteredMultiPrintStream = MPSArrayToHash(mps);
    this.mos = mps[0];
    this.htmlstamps = htmlstamps;
    this.ocookie = cookz;
    this.convertTable = convertTable;
  }
  // constructor with multiple outputs, cookie support, convert table (bytes -> String)
  public HTTPTransaction(BiStreamHandle bsh, MultiOutputStream[] mps, HTMLStamps stamps, GenericCookie cookz, Hashtable convertTable) {
    this.bsh = bsh;
    this.filteredMultiPrintStream = MPSArrayToHash(mps);
    this.mos = mps[0];
    this.stamps = stamps;
    this.ocookie = cookz;
    this.convertTable = convertTable;
  }
  // constructor with multiple outputs, cookie support, convert table (bytes -> String)
  public HTTPTransaction(BiStreamHandle bsh, MultiOutputStream[] mps, HTMLStamps stamps, HTMLStamps nstamps, GenericCookie cookz, Hashtable convertTable) {
    this.bsh = bsh;
    this.filteredMultiPrintStream = MPSArrayToHash(mps);
    this.mos = mps[0];
    this.stamps = stamps;
    this.nstamps = nstamps;
    this.ocookie = cookz;
    this.convertTable = convertTable;
  }
  // constructor with multiple outputs, cookie support, convert table (bytes -> String)
  public HTTPTransaction(BiStreamHandle bsh, MultiOutputStream[] mps, GenericCookie cookz, Hashtable convertTable) {
    this.bsh = bsh;
    this.filteredMultiPrintStream = MPSArrayToHash(mps);
    this.mos = mps[0];
    this.ocookie = cookz;
    this.convertTable = convertTable;
  }
  // constructor with multiple outputs, cookie support, convert table (bytes -> String)
  public HTTPTransaction(BiStreamHandle bsh, MultiOutputStream[] mps, GenericCookie cookz, Hashtable convertTable, boolean resolveDNS) {
    this.bsh = bsh;
    this.filteredMultiPrintStream = MPSArrayToHash(mps);
    this.mos = mps[0];
    this.ocookie = cookz;
    this.convertTable = convertTable;
    this.resolveDNS = resolveDNS;
  }
  // constructor with multiple outputs, cookie support, convert table (bytes -> String)
  public HTTPTransaction(BiStreamHandle bsh, MultiOutputStream[] mps, GenericCookie cookz, Hashtable convertTable, boolean resolveDNS, boolean isRAW) {
    this.bsh = bsh;
    this.filteredMultiPrintStream = MPSArrayToHash(mps);
    this.mos = mps[0];
    this.ocookie = cookz;
    this.convertTable = convertTable;
    this.resolveDNS = resolveDNS;
    this.isRAW = isRAW;
  }
  // constructor with multiple outputs, cookie support, convert table (bytes -> String)
  public HTTPTransaction(BiStreamHandle bsh, MultiOutputStream[] mps, Hashtable convertTable, boolean resolveDNS, boolean isRAW) {
    this.bsh = bsh;
    this.filteredMultiPrintStream = MPSArrayToHash(mps);
    this.mos = mps[0];
    this.convertTable = convertTable;
    this.resolveDNS = resolveDNS;
    this.isRAW = isRAW;
  }

  public final Hashtable getHandshakeInfo() {
    if(handshakeListener != null)
      return handshakeListener.getAllInfo();
    else
      return null;
  }

  /*
   * on suppose que le tableau mps est ordonné, on renvoie une hashtable
   */
  private final Hashtable MPSArrayToHash(MultiOutputStream[] mps) {
    Hashtable<String, MultiOutputStream> h = new Hashtable<String, MultiOutputStream>();

    if(mps[0] != null)
      h.put("request", mps[0]);

    if(mps[1] != null)
      h.put("response-header", mps[1]);

    if(mps[2] != null)
      h.put("response-body", mps[2]);

    return h;
  }

  /*
   * identifier la sortie MPS filtrée
   */
  public final MultiOutputStream getMyMultiPrintStream(String hashkey) {
    MultiOutputStream tmpmps = null;

    tmpmps = (MultiOutputStream)(filteredMultiPrintStream.get(hashkey));

    return tmpmps;
  }

  public final BiStreamHandle getBSH() {
    return bsh;
  }

  public final MultiOutputStream[] getMPS() {

    return new MultiOutputStream[] { (MultiOutputStream)(filteredMultiPrintStream.get("request")),
                                     (MultiOutputStream)(filteredMultiPrintStream.get("response-header")),
                                     (MultiOutputStream)(filteredMultiPrintStream.get("response-body"))
                                   } ;
  }

  public final boolean getHTMLStamps() {
    return htmlstamps;
  }

  public final boolean getNETStamps() {
    return netstamps;
  }

  public final void setRequestMessage(RequestMessage req) {
    this.requestMessage = req;
  }

  public final ResponseMessage getResponseMessage() {
    return responseMessage;
  }

  public final RequestMessage getRequestMessage() {
    return requestMessage;
  }

  public final GenericCookie getCookies() {
    return ocookie;
  }

  /*
   * résolution DNS
   */
  public final String resolve(String adr) throws javax.naming.NamingException {
    String rez = "";

    // pas besoin de résolution si adr est une adresse IP
    if(RFC2396.isIPv4address(adr))
      rez = adr;
    else {

      Hashtable<String, String> env = new Hashtable<String, String>();
      env.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
      //env.put("java.naming.provider.url", "dns://ns.socgen.com");
      DirContext ctx = new InitialDirContext(env);

      Attributes attrs = ctx.getAttributes(requestMessage.getHostname(), new String[] {"A"});

      for (NamingEnumeration ae = attrs.getAll(); ae.hasMoreElements();) {
        Attribute attr = (Attribute)ae.next();
        String attrId = attr.getID();

        for (Enumeration vals = attr.getAll(); vals.hasMoreElements();) {

          rez = (String)vals.nextElement();

        }

      }

      ctx.close();
    }

    return rez;
  }

  /*
   * vérifie si la réponse HTTP doit contenir une partie body selon la requête envoyée
   */
  private final boolean isBodyExpected() {
    if(requestMessage.getMethod().equals("HEAD"))
      return false;
    else
      return true;
  }

  /*
   * initialise une nouvelle connection si besoin (ie: 1ère connection ou bien si la précédente est fermée explicitement)
   */
  public final boolean reuseConnection(CookieWrapper wrapper) {
    boolean rez = true;

    if(bsh.getBiStream() == null) {
      rez = initConnection(wrapper);
    }

    return rez;
  }

  public abstract boolean initConnection(CookieWrapper wrapper);

  /*
   * fermeture explicite de la connexion
   */
  public final boolean closeConnection() {
    boolean rez = true;

    try {
      bsh.close();
      bsh.setBiStream(null);
    }
    catch(IOException ioe) {
      rez = false;
    }

    return rez;
  }

  /*
   * envoie la requête
   */
  public boolean sendRequest() {
    return sendRequest(true);
  }

  public synchronized boolean sendRequest(boolean logit) {

    Date d1 = new Date();

    boolean rez = bsh.sendRequest(getMyMultiPrintStream("request"), requestMessage.getMessageInBytes());

    Date d2 = new Date();

    if(getHTMLStamps())
      System.err.println("timestamp sendrequest: " + (d2.getTime() - d1.getTime()) + " ms");

    if(logit && (stamps != null))
      stamps.log( d2.getTime() - d1.getTime() );

    return rez;
  }

  public final ResMessageHeader buildHeader() {
    return buildHeader(true);
  }

  public final synchronized ResMessageHeader buildHeader(boolean logit) {

    Date d1 = new Date();

    ResMessageHeader rmh = (logit && (nstamps != null)) ?
                           bsh.buildHeader(getMyMultiPrintStream("response-header"), nstamps) :
                           bsh.buildHeader(getMyMultiPrintStream("response-header"));

    Date d2 = new Date();

    if(getHTMLStamps())
      System.err.println("timestamp readheader: " + (d2.getTime() - d1.getTime()) + " ms");

    if(logit && (stamps != null))
      stamps.log( d2.getTime() - d1.getTime() );

    return rmh;
  }

  public final synchronized void buildBody() {

    Date d1 = new Date();

    // EN COURS : 20070622, envoyer le boolean israw à bsh.buildBody, et faire suivre l'implémentation
    bsh.buildBody(getMyMultiPrintStream("response-body"), isBodyExpected(), responseMessage.header, convertTable, isRAW);

    Date d2 = new Date();

    if(getHTMLStamps())
      System.err.println("timestamp readbody: " + (d2.getTime() - d1.getTime()) + " ms");

    if(stamps != null)
      stamps.log( d2.getTime() - d1.getTime() );
  }



  public final ScenarioResult runScenario(boolean reuse, CookieWrapper cookies) {

    /*
     * la valeur retournée indique si la connection peut être maintenue
     */
    ScenarioResult sr;
    boolean rez = false;

    /*
     * reuse indique si on doit essayer de réutiliser la dernière connexion
     * utile dans le cas où tout indique de conserver une connexion (requête et réponse) mais
     * on veut explicitement en créer une nouvelle (ex : changement de hostname, de port,..)
     */
    ResMessageHeader rmh = null;
    int istate = 0, ierr = 15, istop1 = 13, istop2 = 14;

    while(!stopit && (istate != istop1) && (istate != istop2) && (istate != ierr)) {
      switch(istate) {

          // initialisation
        case 0:
          // TO DO : appel à setCookies depuis le scenario et non pas ici !!!!!!
          //System.err.println("nb_cookies: " + setCookies(cookies));
          setCookies(cookies);
          boolean initSuccesfull;

          if(!reuse)
            initSuccesfull = initConnection(cookies);
          else
            initSuccesfull = reuseConnection(cookies);

          if(initSuccesfull)
            istate = 1;
          else
            istate = ierr;

          break;

          // initialisation réussie, on essaie l'envoi de requête
        case 1:
          if(!sendRequest())  //-> Keep-Alive expiré "normalement" détecté
            istate = 4;
          else
            istate = 2;

          break;

          // lecture des headers
        case 2:

          // positionner le compteur au bon endroit
          if(nstamps != null) {
            nstamps.avoidInit();
          }

          rmh = buildHeader();

          if(rmh != null) { //-> Keep-Alive expiré "anormalement" détecté, avec du retard
            responseMessage = new ResponseMessage(rmh);
            istate = 3;
          }
          else
            istate = 4;

          break;

          // lecture du body
        case 3:
          buildBody();
          istate = 12;
          break;

          // le Keep-Alive est expiré et a été détecté, il faut relancer toute la chaîne
        case 4:

          // positionner le logger à 0
          if(stamps != null)
            stamps.initialise();

          if(nstamps != null)
            nstamps.initialise();

          if(initConnection(cookies))
            istate = 5;
          else
            istate = ierr;

          break;

          // suite de la chaîne Keep-Alive
        case 5:
          if(sendRequest())
            istate = 6;
          else
            istate = ierr;

          break;

          // suite de la chaîne Keep-Alive
        case 6:
          rmh = buildHeader();

          if(rmh != null) {
            responseMessage = new ResponseMessage(rmh);
            istate = 7;
          }
          else
            istate = ierr;

          break;

          // suite de la chaîne Keep-Alive
        case 7:
          buildBody();
          istate = 12;
          break;

        case 12:

          // fermeture de la connexion à l'initiative du client
          if(requestMessage.connMustBeClosed()) {
            try {
              bsh.close();
            }
            catch(IOException ioe) {}
            finally {
              bsh.setBiStream(null);
              istate = istop1;
            }
          }
          else {
            // fermeture de la connexion à l'initiative du serveur
            if(rmh != null) {
              if(rmh.connMustBeClosed()) {
                try {
                  bsh.close();
                }
                catch(IOException ioe) {}
                finally {
                  bsh.setBiStream(null);
                  istate = istop1;
                }
              }
              else
                istate = istop2;
            }
            else
              istate = istop1;
          }

          break;
      } // end switch
    }//end while

    // contrôle de la valeur de retour : renvoyer FALSE si 'stop' ou 'erreur'
    switch(istate) {

      case 13:  // istop1, fin "normale" avec fermeture explicite de la connexion d'un côte ou de l'autre
        rez = false;

        // EN COURS : créer l'objet cookies (avec une factory ? dans tous les cas ce n'est pas à ce niveau qu'il faut mettre à jour le fichier...)
        String[] cooks = new String[0];

        try {
          cooks = rmh.getHeader("Set-Cookie");
        }
        catch(UndefinedHeaderException uhe) {}

        return new ScenarioResult(rez, cooks);
        //break;

      case 14:  // istop2, fin "normale" avec conservation de la connexion
        rez = true;
        cooks = new String[0];

        try {
          cooks = rmh.getHeader("Set-Cookie");
        }
        catch(UndefinedHeaderException uhe) {}

        return new ScenarioResult(rez, cooks);
        //break;

      default: // ierr || stopit
        rez = false;
        bsh.setBiStream(null);
        //return new boolean[] {false, false};
        return null;
        //rez = false;
        //break;
    }


    // TO DO : positionner la valeur aux bons endroits, la récupérer dans httpscenario (surtout pour sslcheck..)
    //return new boolean[] {rez, true};
  }

  public final void stopit() {
    stopit = true;
    bsh.stopit();
  }

  /* méthodes redéfinies dans les classes filles de type 'proxy' */
  public void setProxyName(String proxyname) {}
  public void setProxyPort(int proxyport) {}
  public String getProxyName() {
    return "";
  }
  public int getProxyPort() {
    return 0;
  }

  public void setFlag(boolean b) {
    this.isTrueAuth = b;
  }

  public boolean getFlag() {
    return this.isTrueAuth;
  }

  /*
   * set the cookies on the request
   * this does not remove old header cookies (they could be added by a 'real' header
   * returns the number of cookies added (not really usefull, but...)
   */
  protected final int setCookies(GenericCookie cookies) {
    int rez = 0;

    if(cookies != null) {
      // add cookie(s)
      String[] val = (String[])(cookies.get(requestMessage.getHostname(), requestMessage.getRequestURI()));

      if(val != null) {
        try {
          requestMessage.addHeader("Cookie", val);
          rez = val.length;
        }
        catch(MalformedHeaderNameException e) {
          // this can never happen
        }
        catch(MalformedHeaderValueException e) {
          // this is not supposed to happen
          System.err.println(e);
        }
      }
    }

    return rez;
  } // end method

  protected final int setCookies(CookieWrapper cookies) {
    int rez = 0;

    // clean old headers if necessary
    removeCookies();

    if(cookies != null) {
      // add cookie(s)
      String[] val = (String[])(cookies.get(requestMessage.getHostname(), requestMessage.getRequestURI()));

      if(val != null) {
        try {
          //System.out.println("setting the cookies" + val.length);
          requestMessage.addHeader("Cookie", val, false);
          rez = val.length;
        }
        catch(MalformedHeaderNameException e) {
          // this can never happen
        }
        catch(MalformedHeaderValueException e) {
          // this is not supposed to happen
          System.err.println(e);
        }
      }
    }

    return rez;
  } // end method

  /*
   * remove cookies headers
   * usefull when we reuse this HTTPTransaction object, otherwise we could get twice the same headers
   */
  private final void removeCookies() {
    requestMessage.removeHeader("Cookie");
  }

}

/*
 *
 */
abstract class EmptySSLTransaction extends HTTPTransaction {

  /* properties liées à la gestion SSL */
  public String SSLInstance = "TLS";
  public String SSLProvider = "SunJSSE";
  public String[] SSLCipherSuites = new String[0];
  public String[] SSLProtocols = new String[0];
  public TrustManager[] SSLTrustManager = null;
  public boolean htmlstamps = false;
  public boolean useUnsecureRandom = false;
  public SecureRandom secureRandom;

  /* log exceptions */
  private boolean logException = true;

  /*
   * Stores the SSLContext objects that might have been created,
   * in order to reuse them at least for session reusing.
   * See https://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/JSSERefGuide.html
   */
  private static Hashtable cachedSSLContexts = new Hashtable<String, SSLContext>();

  /*
   * constructeurs
   */
  public EmptySSLTransaction() {
    super();
  }
  public EmptySSLTransaction(BiStreamHandle bsh, MultiOutputStream mos, String[] ciphers, String[] protocols) {
    super(bsh, mos);
    setSSLCipherSuites(ciphers);
    setSSLProtocols(protocols);
  }
  public EmptySSLTransaction(BiStreamHandle bsh, MultiOutputStream mos, String SSLInstance, String SSLProvider, String[] protocols, String[] ciphers, TrustManager[] trusted) {
    super(bsh, mos);
    setSSLCipherSuites(ciphers);
    setSSLProtocols(protocols);
    setSSLProvider(SSLProvider);
    setSSLInstance(SSLInstance);
    setTrustManager(trusted);
  }
  public EmptySSLTransaction(BiStreamHandle bsh, MultiOutputStream[] mps, boolean htmlstamps, String SSLInstance, String SSLProvider, String[] protocols, String[] ciphers, TrustManager[] trusted) {
    super(bsh, mps, htmlstamps);
    setSSLCipherSuites(ciphers);
    setSSLProtocols(protocols);
    setSSLProvider(SSLProvider);
    setSSLInstance(SSLInstance);
    setTrustManager(trusted);
  }
  public EmptySSLTransaction(BiStreamHandle bsh, MultiOutputStream[] mps, boolean htmlstamps, GenericCookie cookies, String SSLInstance, String SSLProvider, String[] protocols, String[] ciphers, TrustManager[] trusted) {
    super(bsh, mps, htmlstamps, cookies);
    setSSLCipherSuites(ciphers);
    setSSLProtocols(protocols);
    setSSLProvider(SSLProvider);
    setSSLInstance(SSLInstance);
    setTrustManager(trusted);
  }
  public EmptySSLTransaction(BiStreamHandle bsh, MultiOutputStream[] mps, boolean htmlstamps, GenericCookie cookies, String SSLInstance, String SSLProvider, String[] protocols, String[] ciphers, TrustManager[] trusted, Hashtable hConvert) {
    super(bsh, mps, htmlstamps, cookies, hConvert);
    setSSLCipherSuites(ciphers);
    setSSLProtocols(protocols);
    setSSLProvider(SSLProvider);
    setSSLInstance(SSLInstance);
    setTrustManager(trusted);
  }
  public EmptySSLTransaction(BiStreamHandle bsh, MultiOutputStream[] mps, HTMLStamps htmlstamps, String SSLInstance, String SSLProvider, String[] protocols, String[] ciphers, TrustManager[] trusted) {
    super(bsh, mps, htmlstamps);
    setSSLCipherSuites(ciphers);
    setSSLProtocols(protocols);
    setSSLProvider(SSLProvider);
    setSSLInstance(SSLInstance);
    setTrustManager(trusted);
  }
  public EmptySSLTransaction(BiStreamHandle bsh, MultiOutputStream[] mps, HTMLStamps htmlstamps, GenericCookie cookies, String SSLInstance, String SSLProvider, String[] protocols, String[] ciphers, TrustManager[] trusted) {
    super(bsh, mps, htmlstamps, cookies);
    setSSLCipherSuites(ciphers);
    setSSLProtocols(protocols);
    setSSLProvider(SSLProvider);
    setSSLInstance(SSLInstance);
    setTrustManager(trusted);
  }
  public EmptySSLTransaction(BiStreamHandle bsh, MultiOutputStream[] mps, HTMLStamps htmlstamps, GenericCookie cookies, String SSLInstance, String SSLProvider, String[] protocols, String[] ciphers, TrustManager[] trusted, Hashtable hConvert) {
    super(bsh, mps, htmlstamps, cookies, hConvert);
    setSSLCipherSuites(ciphers);
    setSSLProtocols(protocols);
    setSSLProvider(SSLProvider);
    setSSLInstance(SSLInstance);
    setTrustManager(trusted);
  }
  public EmptySSLTransaction(BiStreamHandle bsh, MultiOutputStream[] mps, HTMLStamps htmlstamps, HTMLStamps nstamps, GenericCookie cookies, String SSLInstance, String SSLProvider, String[] protocols, String[] ciphers, TrustManager[] trusted, Hashtable hConvert) {
    super(bsh, mps, htmlstamps, nstamps, cookies, hConvert);
    setSSLCipherSuites(ciphers);
    setSSLProtocols(protocols);
    setSSLProvider(SSLProvider);
    setSSLInstance(SSLInstance);
    setTrustManager(trusted);
  }
  // DERNIER
  public EmptySSLTransaction(BiStreamHandle bsh, MultiOutputStream[] mps, GenericCookie cookies, String SSLInstance, String SSLProvider, String[] protocols, String[] ciphers, TrustManager[] trusted, Hashtable hConvert, boolean resolveDNS, boolean israw) {
    super(bsh, mps, cookies, hConvert, resolveDNS, israw);
    setSSLCipherSuites(ciphers);
    setSSLProtocols(protocols);
    setSSLProvider(SSLProvider);
    setSSLInstance(SSLInstance);
    setTrustManager(trusted);
  }
  // DERNIER
  public EmptySSLTransaction(BiStreamHandle bsh,
                             MultiOutputStream[] mps,
                             String SSLInstance,
                             String SSLProvider,
                             String[] protocols,
                             String[] ciphers,
                             TrustManager[] trusted,
                             Hashtable hConvert,
                             boolean resolveDNS,
                             boolean israw) {
    super(bsh, mps, hConvert, resolveDNS, israw);
    setSSLCipherSuites(ciphers);
    setSSLProtocols(protocols);
    setSSLProvider(SSLProvider);
    setSSLInstance(SSLInstance);
    setTrustManager(trusted);
  }
  // DERNIER des derniers
  public EmptySSLTransaction(BiStreamHandle bsh,
                             MultiOutputStream[] mps,
                             String SSLInstance,
                             String SSLProvider,
                             String[] protocols,
                             String[] ciphers,
                             TrustManager[] trusted,
                             Hashtable hConvert,
                             boolean resolveDNS,
                             boolean israw,
                             boolean useunsecurerandom) {
    super(bsh, mps, hConvert, resolveDNS, israw);
    setSSLCipherSuites(ciphers);
    setSSLProtocols(protocols);
    setSSLProvider(SSLProvider);
    setSSLInstance(SSLInstance);
    setTrustManager(trusted);
    setUnsecureRandom(useunsecurerandom);
  }
  public EmptySSLTransaction(BiStreamHandle bsh, MultiOutputStream[] mps, GenericCookie cookies, String SSLInstance, String SSLProvider, String[] protocols, String[] ciphers, TrustManager[] trusted, Hashtable hConvert) {
    super(bsh, mps, cookies, hConvert);
    setSSLCipherSuites(ciphers);
    setSSLProtocols(protocols);
    setSSLProvider(SSLProvider);
    setSSLInstance(SSLInstance);
    setTrustManager(trusted);
  }
  public EmptySSLTransaction(BiStreamHandle bsh, MultiOutputStream[] mps, HTMLStamps htmlstamps, HTMLStamps nstamps, GenericCookie cookies, String SSLInstance, String SSLProvider, String[] protocols, String[] ciphers, TrustManager[] trusted, Hashtable hConvert, boolean logException) {
    super(bsh, mps, htmlstamps, nstamps, cookies, hConvert);
    setSSLCipherSuites(ciphers);
    setSSLProtocols(protocols);
    setSSLProvider(SSLProvider);
    setSSLInstance(SSLInstance);
    setTrustManager(trusted);
    setLogException(logException);
  }

  public final void setLogException(boolean b) {
    this.logException = b;
  }
  public final boolean getLogException() {
    return logException;
  }

  public void setSSLCipherSuites(String[] ciphers) {
    this.SSLCipherSuites = ciphers;
  }

  public void setSSLProtocols(String[] protocols) {
    this.SSLProtocols = protocols;
  }

  public void setSSLProvider(String SSLProvider) {
    if(!SSLProvider.equals(""))
      this.SSLProvider = SSLProvider;
  }

  public void setSSLInstance(String SSLInstance) {
    if(!SSLInstance.equals(""))
      this.SSLInstance = SSLInstance;
  }

  public void setTrustManager(TrustManager[] trusted) {
    if(trusted.length > 0)
      this.SSLTrustManager = trusted;
    else
      this.SSLTrustManager = null;
  }

  private void setUnsecureRandom(boolean bln) {
    this.secureRandom = (bln) ? new UnsecureRandom() : null;
  }

  public String[] getSSLCipherSuites() {
    return SSLCipherSuites;
  }

  public String[] getSSLProtocols() {
    return SSLProtocols;
  }

  public String getSSLProvider() {
    return SSLProvider;
  }

  public String getSSLInstance() {
    return SSLInstance;
  }

  public SecureRandom getUnsecureRandom() {
    return secureRandom;
  }

  /*
   * Handles the cached SSLContext objects
   */
  protected final static SSLContext getCachedSSLContext(String version, String provider) throws NoSuchAlgorithmException, NoSuchProviderException {
    SSLContext sc = SSLContext.getDefault();

    // just return the original object added previously if it exists
    if(cachedSSLContexts.containsKey(version+provider)) {
      sc = (SSLContext)cachedSSLContexts.get(version+provider);
    }
    else {
      // or initialize a new H entry when the key isn't found
      try {
        sc = SSLContext.getInstance(version , provider);
        cachedSSLContexts.put(version+provider, sc);
      }
      catch(NoSuchAlgorithmException nsae) {}
      catch(NoSuchProviderException nspe) {}
    }

    // DEBUG
    int idsCount = 0;
    Enumeration ids = sc.getClientSessionContext().getIds();
    while(ids.hasMoreElements()) {

      byte[] bz = (byte[])ids.nextElement();
      // DEBUG System.err.println("id:" + new String(bz));
      idsCount++;
    }
    //DEBUG System.err.println("ids count:" + idsCount);

    return sc;
  }

  /*
   * Shortcut to getCachedSSLContext when Provider is not specified
   */
  protected final static SSLContext getCachedSSLContext(String version) throws NoSuchAlgorithmException, NoSuchProviderException {

    SSLContext sc = SSLContext.getDefault();

    String providerName = sc.getProvider().getName();

    return getCachedSSLContext(version, providerName); 
  }

}

/*
 * classe implémentant la connection SSL
 */
class SSLTransaction extends EmptySSLTransaction {

  /* constructeurs */
  public SSLTransaction(BiStreamHandle bsh, MultiOutputStream mos, String[] ciphers, String[] protocols) {
    super(bsh, mos, ciphers, protocols);
  }

  /*
   * constructeur complètement détaillé
   */
  public SSLTransaction(BiStreamHandle bsh,
                        MultiOutputStream[] mps,
                        boolean htmlstamps,
                        boolean netstamps,
                        boolean resolveDNS,
                        String SSLInstance,
                        String SSLProvider,
                        String[] protocols,
                        String[] ciphers,
                        TrustManager[] trusted,
                        Hashtable hConvert,
                        boolean israw,
                        boolean useunsecurerandom) {
    super(bsh, mps, SSLInstance, SSLProvider, protocols, ciphers, trusted, hConvert, resolveDNS, israw, useunsecurerandom);

    if(htmlstamps)
      this.stamps = new HTMLStamps1();

    if(netstamps)
      this.nstamps = (resolveDNS) ? new NETStamps2_DNS() : new NETStamps2();
  }

  public boolean initConnection(CookieWrapper wrapper) {
    boolean result = true;

    try {

      //1- résolution DNS
      Date d1;
      String sip;

      // résolution DNS lorsque spécifié
      if(resolveDNS) {
        Date d0 = new Date();
        sip = resolve(requestMessage.getHostname());
        d1 = new Date();

        if(nstamps != null)
          nstamps.log( d1.getTime() - d0.getTime() );
      }
      else {
        sip = requestMessage.getHostname();
        d1 = new Date();
      }

      //2- context/provider
      // TO BE REMOVED SSLContext sc = (!SSLProvider.equals("")) ? SSLContext.getInstance(SSLInstance, SSLProvider) : SSLContext.getInstance(SSLInstance);
      //SSLContext sc = (!SSLProvider.equals("")) ? getCachedSSLContext(SSLInstance, SSLProvider) : getCachedSSLContext(SSLInstance);
      SSLContext sc = (!SSLProvider.equals("")) ? SSLContextProxy.getInstance(SSLInstance, SSLProvider) : SSLContextProxy.getInstance(SSLInstance);

      // TO BE REMOVED - ADAPTED
      // IMPORTANT NOTE : run with -Djdk.tls.useExtendedMasterSecret=false to enable Session Resumption

      d1 = new Date();

      boolean initStatus = SSLContextProxy.isInit(sc, null, SSLTrustManager, null);

      //System.err.println("isInited:" + inited);
      if(!initStatus) {
        // init SSLContext
        sc.init(null, SSLTrustManager, null);
        //sc.init(null, SSLTrustManager, getUnsecureRandom());

        // for sure, when init is false we also need to create the engine
        sc.createSSLEngine( sip, (new Integer(requestMessage.getPort())).intValue() );
      }
      else {
        boolean hasEngine = SSLContextProxy.hasEngine(sc, sip, (new Integer(requestMessage.getPort())).intValue() );
        //System.err.println("hasEngine:" + hasEngine);
        if(!hasEngine) {
          sc.createSSLEngine( sip, (new Integer(requestMessage.getPort())).intValue() );
        }
      }

      //3- enfin la factory et la socket
      SSLSocketFactory factory = (SSLSocketFactory)sc.getSocketFactory();
      SSLSocket daSocket = (SSLSocket) factory.createSocket(sip, (new Integer(requestMessage.getPort())).intValue() );

      Date d2 = new Date();

      if(nstamps != null)
        nstamps.log( d2.getTime() - d1.getTime() );

      //4- le bistream et la connection
      // TO DO : comparer les perf entre la version Buffered et la version non Buffered
      OutputStream outputS = new BufferedOutputStream(daSocket.getOutputStream(), 2048);
      InputStream inputS = daSocket.getInputStream();
      BiStream bs = new BiStream(inputS, outputS, daSocket.getReceiveBufferSize());
      bsh.setBiStream(bs);

      //5- le listener sur le handshake (éventuellement à déplacer plus bas)
      handshakeListener = new RootHandshakeCompletedListener();
      daSocket.addHandshakeCompletedListener(handshakeListener);

      //6- paramétrage de la cipher + handshake
      if(getSSLProtocols().length != 0)
        daSocket.setEnabledProtocols(getSSLProtocols());

      if(getSSLCipherSuites().length != 0) {
        /*
         * check the desired cipher suites are supported,
         * as it could stop completely before the handshake.
         * Supported CS might depend on the protocol and/or java version
         */
        String[] supportedCS = daSocket.getSupportedCipherSuites();
        String[] desiredCS = getSSLCipherSuites();

        // contains the matching list
        List<String> CStoBeAllowed = new ArrayList<String>();

        boolean isSupported;
        for(String oneDesiredCS : desiredCS) {
          isSupported = false;
          for(String oneSupportedCS : supportedCS) {
            if(oneDesiredCS.equals(oneSupportedCS))
              isSupported = true;
          }

          if(isSupported)
            CStoBeAllowed.add(oneDesiredCS);
          else
            System.out.println("Discarding cipher suite : " + oneDesiredCS + " because not supported/available");
        }

        //daSocket.setEnabledCipherSuites(getSSLCipherSuites());
        daSocket.setEnabledCipherSuites(CStoBeAllowed.toArray(new String[0]));
      }

      daSocket.startHandshake();

      Date d3 = new Date();

      if(nstamps != null)
        nstamps.log( d3.getTime() - d2.getTime() );
    }
    catch(javax.naming.NamingException ne) {
      if(getLogException())
        System.err.println(ne);

      result = false;
    }
    catch(java.security.NoSuchProviderException nspe) {
      if(getLogException())
        System.err.println(nspe);

      result = false;
    }
    catch(java.security.NoSuchAlgorithmException nsae) {
      if(getLogException())
        System.err.println(nsae);

      result = false;
    }
    catch(java.security.KeyManagementException kme) {
      if(getLogException())
        System.err.println(kme);

      result = false;
    }
    catch(IllegalArgumentException iae) {
      if(getLogException())
        System.err.println(iae);

      //throw new RuntimeException();
      result = false;
    }
    catch(UnknownHostException uhe) {
      if(getLogException())
        System.err.println(uhe);

      result = false;
    }
    catch(javax.net.ssl.SSLException ssle) {
      if(getLogException())
        System.err.println(ssle);

      //throw new RuntimeException();
      result = false;
    }
    catch(IOException ie) {
      if(getLogException())
        System.err.println("ie: " + ie);

      result = false;
    }

    return result;
  }
}

/*
 * classe implémentant la connection SSL via Proxy
 */
class SSLTransactionViaProxy extends EmptySSLTransaction {

  public String proxyname = "";
  public int proxyport = 0;

  private RequestMessage proreq = null;

  /* constructeurs */
  public SSLTransactionViaProxy() { }

  public SSLTransactionViaProxy(BiStreamHandle bsh, MultiOutputStream mos, String[] ciphers, String[] protocols) {
    super(bsh, mos, ciphers, protocols);
  }

  public SSLTransactionViaProxy(BiStreamHandle bsh, MultiOutputStream[] mps, boolean htmlstamps, boolean netstamps, boolean resolveDNS, String SSLInstance, String SSLProvider, String[] protocols, String[] ciphers, TrustManager[] trusted, Hashtable hConvert, boolean israw, boolean useunsecurerandom) {
    super(bsh, mps, SSLInstance, SSLProvider, protocols, ciphers, trusted, hConvert, resolveDNS, israw, useunsecurerandom);

    if(htmlstamps)
      this.stamps = new HTMLStamps1();

    if(netstamps)
      this.nstamps = (resolveDNS) ? new NETStamps3_DNS() : new NETStamps3();

// EN COURS : proxy 200.89.23.3:80
  }

  /*
   * accessors
   */
  public void setProxyName(String proxyname) {
    this.proxyname = proxyname;
  }

  public void setProxyPort(int proxyport) {
    this.proxyport = proxyport;
  }

  public String getProxyName() {
    return proxyname;
  }

  public int getProxyPort() {
    return proxyport;
  }

  public void setProxyRequest(RequestMessage rm) {
    this.proreq = rm;
  }

  public boolean initConnection(CookieWrapper wrapper) {
    boolean rezult = false;

    try {
      //0- sauvegarde du requestMessage pour rappel
      RequestMessage rmSave = requestMessage;
      SSLSocketFactory factory = null;
      Socket tunnel = null;
      ResMessageHeader prmh = null;

      Date d1 = new Date(), d2 = new Date();
      String sip = "";
      int istate = 0, ierr = 8, iend = 7;

      while(!stopit && (istate != iend) && (istate != ierr)) {

        switch(istate) {
          case 0: // préparation de l'environnement SSL (la Factory)

            // initialisation du context avec le provider spécifié ou celui par défaut
            // TO BE REMOVED SSLContext sc = (!SSLProvider.equals("")) ? SSLContext.getInstance(SSLInstance, SSLProvider) : SSLContext.getInstance(SSLInstance);
            //SSLContext sc = (!SSLProvider.equals("")) ? getCachedSSLContext(SSLInstance, SSLProvider) : getCachedSSLContext(SSLInstance);
            SSLContext sc = (!SSLProvider.equals("")) ? SSLContextProxy.getInstance(SSLInstance, SSLProvider) : SSLContextProxy.getInstance(SSLInstance);

            boolean initStatus = SSLContextProxy.isInit(sc, null, SSLTrustManager, null);
            //System.err.println("isInited:" + inited);
            if(!initStatus) {
              // init SSLContext
              sc.init(null, SSLTrustManager, null);
              //sc.init(null, SSLTrustManager, getUnsecureRandom());
            }

            boolean hasEngine = SSLContextProxy.hasEngine(sc, sip, (new Integer(requestMessage.getPort())).intValue() );
            //System.err.println("hasEngine:" + hasEngine);
            if(!initStatus) {
              sc.createSSLEngine( sip, (new Integer(requestMessage.getPort())).intValue() );
            }

            // initialisation de la factory
            factory = (SSLSocketFactory)sc.getSocketFactory();

            istate++;
            break;

          case 1:

            //1- résolution DNS

            // résolution DNS lorsque spécifié
            if(resolveDNS) {
              Date d0 = new Date();
              sip = resolve(proxyname);
              d1 = new Date();

              if(nstamps != null)
                nstamps.log( d1.getTime() - d0.getTime() );
            }
            else {
              sip = proxyname;
              d1 = new Date();
            }

            istate++;
            break;

          case 2: // connexion au proxy
            d1 = new Date();

            // création du tunnel proxy
            tunnel = new Socket(sip, proxyport);

            OutputStream tout = new BufferedOutputStream(tunnel.getOutputStream(), 2048);
            InputStream tin = tunnel.getInputStream();
            BiStream bs = new BiStream(tin, tout, tunnel.getReceiveBufferSize());
            bsh.setBiStream(bs);

            d2 = new Date();

            if(nstamps != null)
              nstamps.log( d2.getTime() - d1.getTime() );

            istate++;
            break;

          case 3: // création de la requête adaptée au proxy + envoi

            d1 = new Date();

            // construction du RequestMessage de connection au proxy sauf s'il a été passé au constructeur
            if(proreq == null) {
              //RequestMessageHeader hprox = (RequestMessageHeader)(RequestMessageHeaderFactory.create(null));
              ReqMessageHeader hprox = new ReqMessageHeader();

              try {
                hprox.setRequestURI(requestMessage.getHostname().concat(":").concat(requestMessage.getPort()));
                hprox.setMethod("CONNECT");
                hprox.setHTTPVersion(requestMessage.getHTTPVersion());
                hprox.addHeader("User-Agent", requestMessage.getHeader("User-Agent"));

                hprox.setHostname(getProxyName());

              }
              catch(MalformedHeaderException mhe) {} // Ce cas ne peut pas se présenter donc aucune action

              // requestMessage a auparavant été sauvegardé, aucune perte
              requestMessage = new RequestMessage(hprox);

              //setCookies(wrapper);
            }
            else
              requestMessage = proreq;

            setCookies(wrapper);

            //send request without logging (remember the real type of logger object)
            if(sendRequest(false))
              istate++;
            else
              istate = ierr;

            break;

          case 4: // obtenir la réponse proxy

            //6- analyse de la réponse du proxy, auquel on décide de poursuivre ou arrêter le process
            prmh = buildHeader(false);
            istate++;
            break;

          case 5:  // analyse de la réponse
            if("200".equals(prmh.getStatusCode())) {
              //fin du tunneling handshake ! on remet le requestMessage à sa valeur initiale
              requestMessage = rmSave;

              d2 = new Date();

              if(nstamps != null)
                nstamps.log( d2.getTime() - d1.getTime() );

              istate++;
            }
            else {
              // expected return codes : 401, 403, 50X, but not expected 400, 404,..
              istate = ierr;
            }

            break;

          case 6: // récupération de la socket SSL vers le serveur final
            d1 = new Date();

            // création de la SSLSocket
            SSLSocket daSocket = (SSLSocket)factory.createSocket(tunnel, requestMessage.getHostname(), (new Integer(requestMessage.getPort())).intValue(), true);
            OutputStream outZ = new BufferedOutputStream(daSocket.getOutputStream(), 2048);
            InputStream inZ = daSocket.getInputStream();
            bs = new BiStream(inZ, outZ, daSocket.getReceiveBufferSize());
            bsh.setBiStream(bs);

            //le listener sur le handshake (éventuellement à déplacer plus bas)
            handshakeListener = new RootHandshakeCompletedListener();
            daSocket.addHandshakeCompletedListener(handshakeListener);

            if(getSSLProtocols().length != 0)
              daSocket.setEnabledProtocols(getSSLProtocols());

            if(getSSLCipherSuites().length != 0) {
              /*
               * check the desired cipher suites are supported,
               * as it could stop completely before the handshake.
               * Supported CS might depend on the protocol and/or java version
               */
              String[] supportedCS = daSocket.getSupportedCipherSuites();
              String[] desiredCS = getSSLCipherSuites();

              // contains the matching list
              List<String> CStoBeAllowed = new ArrayList<String>();

              boolean isSupported;
              for(String oneDesiredCS : desiredCS) {
                isSupported = false;
                for(String oneSupportedCS : supportedCS) {
                  if(oneDesiredCS.equals(oneSupportedCS))
                    isSupported = true;
                }

                if(isSupported)
                  CStoBeAllowed.add(oneDesiredCS);
                else
                  System.out.println("Discarding cipher suite : " + oneDesiredCS + " because not supported/available");
              }

              //daSocket.setEnabledCipherSuites(getSSLCipherSuites());
              daSocket.setEnabledCipherSuites(CStoBeAllowed.toArray(new String[0]));
            }

            daSocket.startHandshake();

            d2 = new Date();

            if(nstamps != null)
              nstamps.log( d2.getTime() - d1.getTime() );

            istate = iend;
            break;
        } // end switch
      } // end while

      // contrôle de la valeur de retour : renvoyer FALSE si 'stop' ou 'erreur'
      switch(istate) {

        case 7:  // iend
          rezult = true;
          break;

        default:
          rezult = false;
          bsh.setBiStream(null);
          break;
      }
    }
    catch(javax.naming.NamingException ne) {
      if(getLogException())
        System.err.println(ne);

      rezult = false;
    }
    catch(java.security.NoSuchProviderException nspe) {
      if(getLogException())
        System.err.println(nspe);

      rezult = false;
    }
    catch(java.security.NoSuchAlgorithmException nsae) {
      if(getLogException())
        System.err.println(nsae);

      rezult = false;
    }
    catch(java.security.KeyManagementException kme) {
      if(getLogException())
        System.err.println(kme);

      rezult = false;
    }
    catch(IllegalArgumentException iae) {
      if(getLogException())
        System.err.println(iae);

      rezult = false;
    }
    catch(UnknownHostException uhe) {
      if(getLogException())
        System.err.println(uhe);

      rezult = false;
    }
    catch(javax.net.ssl.SSLException ssle) {
      if(getLogException())
        System.err.println(ssle);

      rezult = false;
    }
    catch(IOException ie) {
      if(getLogException())
        System.err.println(ie);

      rezult = false;
    }

    return rezult;
  }
}

/*
 * classe implémentant le TrustManager acceptant tous les certificats serveurs
 */
class X509TrustManagerTrustAll implements X509TrustManager {
  public boolean checkClientTrusted(java.security.cert.X509Certificate[] chain) {
    return true;
  }
  public boolean isServerTrusted(java.security.cert.X509Certificate[] chain) {
    return true;
  }
  public boolean isClientTrusted(java.security.cert.X509Certificate[] chain) {
    return true;
  }
  public java.security.cert.X509Certificate[] getAcceptedIssuers() {
    return new java.security.cert.X509Certificate[0];
  }
  public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) {}
  public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) {}
}

/*
 * classe implémentant HandshakeCompletedListener pour récupérer les infos de handshake
 *
 * action to run when handshake event is completed
 * note that for Diffie-Hellman anonymous or Kerberos cipher suites, no certificate is returned by the server
 * for more possibilities, see http://java.sun.com/javase/6/docs/api/javax/net/ssl/HandshakeCompletedEvent.html
 */
class RootHandshakeCompletedListener implements HandshakeCompletedListener {

  private HandshakeCompletedEvent hce;
  private String cipher;
  private Certificate[] peerCertificates = null;
  private Principal peerPrincipal = null;

  public void handshakeCompleted(HandshakeCompletedEvent hce) {
    this.hce = hce;

    cipher = hce.getCipherSuite();

    // only cipersuites different from DH_anon* will return a server certificate
    if(!cipher.toLowerCase().contains("dh_anon")) {
      try {
        peerCertificates = hce.getPeerCertificates();
        peerPrincipal = hce.getPeerPrincipal();
      }
      catch(SSLPeerUnverifiedException spue) {
        System.err.println("unexpected exception :");
        //System.err.println(spue);
        spue.printStackTrace();
      }
    }

    /* RFU : KERBEROS ciphersuites will not return certificates but getPeerPrincipal will work (see doc)
    else {
    }
    */
  } // end constructor

  /*
   * returns all the information from the handshake
   * or empty hashtable if the handshake was never done
   */
  public Hashtable getAllInfo() {
    Hashtable h = new Hashtable();

    if(cipher != null)
      h.put("cipher", cipher);

    if(peerCertificates != null)
      h.put("peerCertificates", peerCertificates);

    if(peerPrincipal != null)
      h.put("peerPrincipal", peerPrincipal);

    return h;
  }

} // end class

/*
 * class Timer pour lancer une attente
 */
class Sleeper extends Thread {

  public Sleeper() {}

  public void run() {}

}

/*
 * this class allows a JTextArea to behave like an OutputStream (more or less it is considered as an Adapter pattern)
 * subclasses are allowed, but not used yet
 * important notice : writing text is always something slow.. that's why we use a buffer, which improves performance so much (20 times according to my own tests),
 * this is why, one never should forget calling flush() method
 */
class JTextAreaOutputStream extends OutputStream {
  private ByteArrayOutputStream pbaos = new ByteArrayOutputStream(1024);
  private JTextArea jta;
  private int isize = 1024;

  public JTextAreaOutputStream( JTextArea jta ) {
    this.jta = jta;
  }

  public JTextAreaOutputStream( JTextArea jta, int isize ) {
    this.jta = jta;
    this.isize = isize;
    pbaos = new ByteArrayOutputStream(isize);
  }

  public void write( int b ) throws IOException {

    // si le buffer n'est pas plein, on bufferise
    if(pbaos.size() < isize - 1)
      pbaos.write(b);
    else {
      pbaos.write(b);
      flush();
    }
  }

  public void write(byte[] b) throws IOException {

    int ind = b.length / isize;

    for(int i = 0; i < ind; i++) {
      pbaos.write(b, i * isize, isize);
      flush();
    }

    int res = b.length % isize;

    if(res > 0) {
      pbaos.write(b, ind * isize, res);
      flush();
    }

  }

  public void flush() {
    jta.append( pbaos.toString() );
    pbaos.reset();
    //System.err.println("-> " + jta.getPreferredSize());
    //System.err.println("-> " + jta.getSize());
  }

  // TO DO : implement other methods if necessary

}

class RFC2617 {

  public static String toBasicCredentials(String userid, String password) {
    return( "Basic " + new String (Base64.encodeBytes( (userid + ":" + password).getBytes() )) );
  }

  public static String toDigestCredentials(String algo, String user, String realm, String passwd,
                                            String nonce, String ncvalue, String cnonce,
                                            String method, String uri, String entityb, String qop,
                                            String opaque) {

    String response = "";
    StringBuffer srez = new StringBuffer();

    // compulsory part of credentials
    srez.append("Digest username=" + "\"" + user
                + "\", realm=\"" + realm
                + "\", nonce=\"" + nonce
                + "\", uri=\"" + uri + "\", ");

    // optional part of credentials

    if(!opaque.equals(""))
      srez.append("opaque=\"" + opaque + "\", ");

    if(!qop.equals("")) {
      // remember the server sent a list of available qops, and only ONE was chosen by the client before entering this computation
      srez.append("qop=" + qop + ", ");

      // cnonce was chosen by the client
      srez.append("cnonce=\"" + cnonce + "\", ");

      // remember ncvalue must be a hex value, and its value is calculated by the client
      srez.append("nc=" + ncvalue + ", ");
    }

    /*
     * computation of request-digest as in RFC2617 §3.2.2.1, made by MessageDigestAlgorithm class
     * see MessageDigestAlgorithm.java for code and credits (I removed all references to Console class)
     */
    String reztmp = MessageDigestAlgorithm.calculateResponse(algo, user, realm, passwd, nonce, ncvalue, cnonce, method, uri, entityb, qop);

    srez.append("response=" + "\"" + (reztmp) + "\"");

    if(!algo.equals(""))
      srez.append(", algorithm=\"" + algo + "\"");

    return srez.toString();
  }

}

/*
 * Class documenting the available cipher suites for SUN & IBM providers
 * The list of these ciphers depend on the Java version
 * 
 * problem 1 : SSLSocket.getSupportedCipherSuites() returns only the 'enabled by default' cipher suites, so we should not use this
 * problem 2 : SUN names some ciphersuites with SSL_ though they should be named TLS_ ...
 *
 * Rules for 'be sure the web server is the one we think, and strongest ciphers first'
 * rule 1 : exchange keys - DH_ANON will be at the end to prevent man-in-the-middle attacks
 * rule 2 : key length - the longest key, the most secure (not true with elliptic curves)
 * rule 3 : crypto algorithm - 3DES > AES > DES > RC4 (this should be double-checked)
 * rule 4 : exchange keys - DHE_DSS > DHE_RSA > RSA
 * rule 5 : hash algorithm - SHA (ie : SHA-1) hash > MD5
 *
 * note : we could also give Rules for 'the strongest ciphers first, we don't fear getting fake data from a black-hat server'
 *
 * documentation : see https://docs.oracle.com/javase/8/docs/technotes/guides/security/SunProviders.html#SunJSSEProvider
 *
 */
class CipherSuiteUtil {

  private final static String[] SUN_7_ALL = new String[] {
    // 256
    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA",

    // 168
    "SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
    "SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    "SSL_RSA_WITH_3DES_EDE_CBC_SHA",

    // 128
    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    "SSL_RSA_WITH_RC4_128_MD5",
    "SSL_RSA_WITH_RC4_128_SHA",
    "TLS_RSA_WITH_AES_128_CBC_SHA",

    // 56
    "SSL_DHE_DSS_WITH_DES_CBC_SHA",
    "SSL_DHE_RSA_WITH_DES_CBC_SHA",
    "SSL_RSA_WITH_DES_CBC_SHA",

    // 40
    "SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
    "SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
    "SSL_RSA_EXPORT_WITH_DES40_CBC_SHA",
    "SSL_RSA_EXPORT_WITH_RC4_40_MD5",

    // 0
    "SSL_RSA_WITH_NULL_MD5",
    "SSL_RSA_WITH_NULL_SHA",

    // DH_anon
    "SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA",
    "SSL_DH_anon_EXPORT_WITH_RC4_40_MD5",
    "SSL_DH_anon_WITH_3DES_EDE_CBC_SHA",
    "SSL_DH_anon_WITH_DES_CBC_SHA",
    "SSL_DH_anon_WITH_RC4_128_MD5",
    "TLS_DH_anon_WITH_AES_128_CBC_SHA",
    "TLS_DH_anon_WITH_AES_256_CBC_SHA"

    // RFU
    // NULL 0
    //"SSL_NULL_WITH_NULL_NULL"
    // FORTEZZA 96
    /*see rfc2712.txt
    "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5",
    "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA",
    "TLS_KRB5_EXPORT_WITH_RC4_40_MD5",
    "TLS_KRB5_EXPORT_WITH_RC4_40_SHA",
    "TLS_KRB5_WITH_3DES_EDE_CBC_MD5",
    "TLS_KRB5_WITH_3DES_EDE_CBC_SHA",
    "TLS_KRB5_WITH_DES_CBC_MD5",
    "TLS_KRB5_WITH_DES_CBC_SHA",
    "TLS_KRB5_WITH_RC4_128_MD5",
    "TLS_KRB5_WITH_RC4_128_SHA",
    */
  };

  /*
   * cipher suites SUN JDK8 TLS 1.0,
   * ordered by SunJSSE  preference
   *
  private final static String[] SUN_8_TLS1 = new String[] {
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
    "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
    "SSL_RSA_WITH_RC4_128_SHA",
    "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
    "TLS_ECDH_RSA_WITH_RC4_128_SHA",
    "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
    "SSL_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    "SSL_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
    "SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    "SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
    "SSL_RSA_WITH_RC4_128_MD5"
  };*/

  /*
   * list taken from RFC 2246 (0x00,xxxx) and 4492 (0xC0,xxxx)
   * cipher suites SUN JDK8 TLS 1.0,
   * ordered according to the RFC
   */
  private final static String[] SUN_7_TLS1 = new String[] {
    "SSL_RSA_WITH_NULL_MD5",                   // { 0x00,0x01 }
    "SSL_RSA_WITH_NULL_SHA ",                  // { 0x00,0x02 }
    "SSL_RSA_EXPORT_WITH_RC4_40_MD5",          // { 0x00,0x03 }
    "SSL_RSA_WITH_RC4_128_MD5",                // { 0x00,0x04 }
    "SSL_RSA_WITH_RC4_128_SHA",                // { 0x00,0x05 }
    "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",      // { 0x00,0x06 }
    "TLS_RSA_WITH_IDEA_CBC_SHA",               // { 0x00,0x07 }
    "SSL_RSA_EXPORT_WITH_DES40_CBC_SHA",       // { 0x00,0x08 }
    "SSL_RSA_WITH_DES_CBC_SHA",                // { 0x00,0x09 }
    "SSL_RSA_WITH_3DES_EDE_CBC_SHA",           // { 0x00,0x0A }

    "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA",    // { 0x00,0x0B }
    "TLS_DH_DSS_WITH_DES_CBC_SHA",             // { 0x00,0x0C }
    "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA",        // { 0x00,0x0D }
    "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA",    // { 0x00,0x0E }
    "TLS_DH_RSA_WITH_DES_CBC_SHA",             // { 0x00,0x0F }
    "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA",        // { 0x00,0x10 }
    "SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",   // { 0x00,0x11 }
    "SSL_DHE_DSS_WITH_DES_CBC_SHA",            // { 0x00,0x12 }
    "SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA",       // { 0x00,0x13 }
    "SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",   // { 0x00,0x14 }
    "SSL_DHE_RSA_WITH_DES_CBC_SHA",            // { 0x00,0x15 }
    "SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA",       // { 0x00,0x16 }

    "SSL_DH_anon_EXPORT_WITH_RC4_40_MD5",      // { 0x00,0x17 }
    "SSL_DH_anon_WITH_RC4_128_MD5",            // { 0x00,0x18 }
    "SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA",   // { 0x00,0x19 }
    "SSL_DH_anon_WITH_DES_CBC_SHA",            // { 0x00,0x1A }
    "SSL_DH_anon_WITH_3DES_EDE_CBC_SHA",       // { 0x00,0x1B }

    "TLS_ECDH_ECDSA_WITH_NULL_SHA",            // { 0xC0, 0x01 }
    "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",         // { 0xC0, 0x02 }
    "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",    // { 0xC0, 0x03 }
    "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",     // { 0xC0, 0x04 }
    "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",     // { 0xC0, 0x05 }

    "TLS_ECDHE_ECDSA_WITH_NULL_SHA",           // { 0xC0, 0x06 }
    "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",        // { 0xC0, 0x07 }
    "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",   // { 0xC0, 0x08 }
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",    // { 0xC0, 0x09 }
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",    // { 0xC0, 0x0A }

    "TLS_ECDH_RSA_WITH_NULL_SHA",              // { 0xC0, 0x0B }
    "TLS_ECDH_RSA_WITH_RC4_128_SHA",           // { 0xC0, 0x0C }
    "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",      // { 0xC0, 0x0D }
    "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",       // { 0xC0, 0x0E }
    "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",       // { 0xC0, 0x0F }

    //"TLS_ECDHE_RSA_WITH_NULL_SHA",             // { 0xC0, 0x10 }
    "TLS_ECDHE_RSA_WITH_RC4_128_SHA",          // { 0xC0, 0x11 }
    "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",     // { 0xC0, 0x12 }
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",      // { 0xC0, 0x13 }
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",      // { 0xC0, 0x14 }

    "TLS_ECDH_anon_WITH_NULL_SHA",             // { 0xC0, 0x15 }
    "TLS_ECDH_anon_WITH_RC4_128_SHA",          // { 0xC0, 0x16 }
    "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",     // { 0xC0, 0x17 }
    "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",      // { 0xC0, 0x18 }
    "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",      // { 0xC0, 0x19 }

  };

  /*
   * list taken from RFC 6101 (0x00,xxxx)
   * cipher suites SUN JDK7 SSL 3.0,
   * ordered according to the RFC
   */
  private final static String[] SUN_7_SSL3 = new String[] {
    "SSL_RSA_WITH_NULL_MD5",                   // { 0x00,0x01 }
    "SSL_RSA_WITH_NULL_SHA ",                  // { 0x00,0x02 }
    "SSL_RSA_EXPORT_WITH_RC4_40_MD5",          // { 0x00,0x03 }
    "SSL_RSA_WITH_RC4_128_MD5",                // { 0x00,0x04 }
    "SSL_RSA_WITH_RC4_128_SHA",                // { 0x00,0x05 }
    "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",      // { 0x00,0x06 }
    "TLS_RSA_WITH_IDEA_CBC_SHA",               // { 0x00,0x07 }
    "SSL_RSA_EXPORT_WITH_DES40_CBC_SHA",       // { 0x00,0x08 }
    "SSL_RSA_WITH_DES_CBC_SHA",                // { 0x00,0x09 }
    "SSL_RSA_WITH_3DES_EDE_CBC_SHA",           // { 0x00,0x0A }

    "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA",    // { 0x00,0x0B }
    "TLS_DH_DSS_WITH_DES_CBC_SHA",             // { 0x00,0x0C }
    "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA",        // { 0x00,0x0D }
    "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA",    // { 0x00,0x0E }
    "TLS_DH_RSA_WITH_DES_CBC_SHA",             // { 0x00,0x0F }
    "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA",        // { 0x00,0x10 }
    "SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",   // { 0x00,0x11 }
    "SSL_DHE_DSS_WITH_DES_CBC_SHA",            // { 0x00,0x12 }
    "SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA",       // { 0x00,0x13 }
    "SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",   // { 0x00,0x14 }
    "SSL_DHE_RSA_WITH_DES_CBC_SHA",            // { 0x00,0x15 }
    "SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA",       // { 0x00,0x16 }

    "SSL_DH_anon_EXPORT_WITH_RC4_40_MD5",      // { 0x00,0x17 }
    "SSL_DH_anon_WITH_RC4_128_MD5",            // { 0x00,0x18 }
    "SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA",   // { 0x00,0x19 }
    "SSL_DH_anon_WITH_DES_CBC_SHA",            // { 0x00,0x1A }
    "SSL_DH_anon_WITH_3DES_EDE_CBC_SHA",       // { 0x00,0x1B }
  };

  /*
   * list taken from RFC 4346 (0x00,0x01) to (0x00,0x1B)
   * RFC 3268 (0x00,0x2F) to (0x00, 0x3A) : AES
   * RFC 4492 (0xC0,xxxx) : EC
   * cipher suites SUN JDK8 TLS 1.0,
   * ordered according to the RFC
   *
   * this list is finally a bit different than the one for RFC 2246
   */
  private final static String[] SUN_8_TLS1_1 = new String[] {
    "SSL_RSA_WITH_NULL_MD5",                   // { 0x00,0x01 }
    "SSL_RSA_WITH_NULL_SHA ",                  // { 0x00,0x02 }
    // "SSL_RSA_EXPORT_WITH_RC4_40_MD5",          // { 0x00,0x03 }
    "SSL_RSA_WITH_RC4_128_MD5",                // { 0x00,0x04 }
    "SSL_RSA_WITH_RC4_128_SHA",                // { 0x00,0x05 }
    // "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",      // { 0x00,0x06 }
    "TLS_RSA_WITH_IDEA_CBC_SHA",               // { 0x00,0x07 }
    // "SSL_RSA_EXPORT_WITH_DES40_CBC_SHA",       // { 0x00,0x08 }
    "SSL_RSA_WITH_DES_CBC_SHA",                // { 0x00,0x09 }
    "SSL_RSA_WITH_3DES_EDE_CBC_SHA",           // { 0x00,0x0A }

    // "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA",    // { 0x00,0x0B }
    "TLS_DH_DSS_WITH_DES_CBC_SHA",             // { 0x00,0x0C }
    "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA",        // { 0x00,0x0D }
    // "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA",    // { 0x00,0x0E }
    "TLS_DH_RSA_WITH_DES_CBC_SHA",             // { 0x00,0x0F }
    "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA",        // { 0x00,0x10 }
    // "SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",   // { 0x00,0x11 }
    "SSL_DHE_DSS_WITH_DES_CBC_SHA",            // { 0x00,0x12 }
    "SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA",       // { 0x00,0x13 }
    // "SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",   // { 0x00,0x14 }
    "SSL_DHE_RSA_WITH_DES_CBC_SHA",            // { 0x00,0x15 }
    "SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA",       // { 0x00,0x16 }


    "TLS_RSA_WITH_AES_128_CBC_SHA",      // { 0x00, 0x2F };
    "TLS_DH_DSS_WITH_AES_128_CBC_SHA",   // { 0x00, 0x30 };
    "TLS_DH_RSA_WITH_AES_128_CBC_SHA",   // { 0x00, 0x31 };
    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",  // { 0x00, 0x32 };
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",  // { 0x00, 0x33 };
    "TLS_DH_anon_WITH_AES_128_CBC_SHA",  // { 0x00, 0x34 };

    "TLS_RSA_WITH_AES_256_CBC_SHA",      // { 0x00, 0x35 };
    "TLS_DH_DSS_WITH_AES_256_CBC_SHA",   // { 0x00, 0x36 };
    "TLS_DH_RSA_WITH_AES_256_CBC_SHA",   // { 0x00, 0x37 };
    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",  // { 0x00, 0x38 };
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",  // { 0x00, 0x39 };
    "TLS_DH_anon_WITH_AES_256_CBC_SHA",  // { 0x00, 0x3A };

    "SSL_DH_anon_EXPORT_WITH_RC4_40_MD5",      // { 0x00,0x17 }
    "SSL_DH_anon_WITH_RC4_128_MD5",            // { 0x00,0x18 }
    "SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA",   // { 0x00,0x19 }
    "SSL_DH_anon_WITH_DES_CBC_SHA",            // { 0x00,0x1A }
    "SSL_DH_anon_WITH_3DES_EDE_CBC_SHA",       // { 0x00,0x1B }

    "TLS_ECDH_ECDSA_WITH_NULL_SHA",            // { 0xC0, 0x01 }
    "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",         // { 0xC0, 0x02 }
    "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",    // { 0xC0, 0x03 }
    "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",     // { 0xC0, 0x04 }
    "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",     // { 0xC0, 0x05 }

    "TLS_ECDHE_ECDSA_WITH_NULL_SHA",           // { 0xC0, 0x06 }
    "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",        // { 0xC0, 0x07 }
    "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",   // { 0xC0, 0x08 }
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",    // { 0xC0, 0x09 }
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",    // { 0xC0, 0x0A }

    "TLS_ECDH_RSA_WITH_NULL_SHA",              // { 0xC0, 0x0B }
    "TLS_ECDH_RSA_WITH_RC4_128_SHA",           // { 0xC0, 0x0C }
    "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",      // { 0xC0, 0x0D }
    "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",       // { 0xC0, 0x0E }
    "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",       // { 0xC0, 0x0F }

    //"TLS_ECDHE_RSA_WITH_NULL_SHA",             // { 0xC0, 0x10 }
    "TLS_ECDHE_RSA_WITH_RC4_128_SHA",          // { 0xC0, 0x11 }
    "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",     // { 0xC0, 0x12 }
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",      // { 0xC0, 0x13 }
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",      // { 0xC0, 0x14 }

    "TLS_ECDH_anon_WITH_NULL_SHA",             // { 0xC0, 0x15 }
    "TLS_ECDH_anon_WITH_RC4_128_SHA",          // { 0xC0, 0x16 }
    "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",     // { 0xC0, 0x17 }
    "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",      // { 0xC0, 0x18 }
    "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",      // { 0xC0, 0x19 }

  };

  /*
   * list taken from RFC 2246 (0x00,0x01) to (0x00,0x1B)
   * RFC 3268 (0x00,0x2F) to (0x00, 0x3A) : AES
   * RFC 4492 (0xC0,xxxx) : EC
   * cipher suites SUN JDK8 TLS 1.0,
   * ordered according to the RFC
   * No difference with SUN_7 above
   */
  private final static String[] SUN_8_TLS1 = new String[] {
    "SSL_RSA_WITH_NULL_MD5",                   // { 0x00,0x01 }
    "SSL_RSA_WITH_NULL_SHA ",                  // { 0x00,0x02 }
    "SSL_RSA_EXPORT_WITH_RC4_40_MD5",          // { 0x00,0x03 }
    "SSL_RSA_WITH_RC4_128_MD5",                // { 0x00,0x04 }
    "SSL_RSA_WITH_RC4_128_SHA",                // { 0x00,0x05 }
    "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",      // { 0x00,0x06 }
    "TLS_RSA_WITH_IDEA_CBC_SHA",               // { 0x00,0x07 }
    "SSL_RSA_EXPORT_WITH_DES40_CBC_SHA",       // { 0x00,0x08 }
    "SSL_RSA_WITH_DES_CBC_SHA",                // { 0x00,0x09 }
    "SSL_RSA_WITH_3DES_EDE_CBC_SHA",           // { 0x00,0x0A }

    "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA",    // { 0x00,0x0B }
    "TLS_DH_DSS_WITH_DES_CBC_SHA",             // { 0x00,0x0C }
    "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA",        // { 0x00,0x0D }
    "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA",    // { 0x00,0x0E }
    "TLS_DH_RSA_WITH_DES_CBC_SHA",             // { 0x00,0x0F }
    "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA",        // { 0x00,0x10 }
    "SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",   // { 0x00,0x11 }
    "SSL_DHE_DSS_WITH_DES_CBC_SHA",            // { 0x00,0x12 }
    "SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA",       // { 0x00,0x13 }
    "SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",   // { 0x00,0x14 }
    "SSL_DHE_RSA_WITH_DES_CBC_SHA",            // { 0x00,0x15 }
    "SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA",       // { 0x00,0x16 }


    "TLS_RSA_WITH_AES_128_CBC_SHA",      // { 0x00, 0x2F };
    "TLS_DH_DSS_WITH_AES_128_CBC_SHA",   // { 0x00, 0x30 };
    "TLS_DH_RSA_WITH_AES_128_CBC_SHA",   // { 0x00, 0x31 };
    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",  // { 0x00, 0x32 };
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",  // { 0x00, 0x33 };
    "TLS_DH_anon_WITH_AES_128_CBC_SHA",  // { 0x00, 0x34 };

    "TLS_RSA_WITH_AES_256_CBC_SHA",      // { 0x00, 0x35 };
    "TLS_DH_DSS_WITH_AES_256_CBC_SHA",   // { 0x00, 0x36 };
    "TLS_DH_RSA_WITH_AES_256_CBC_SHA",   // { 0x00, 0x37 };
    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",  // { 0x00, 0x38 };
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",  // { 0x00, 0x39 };
    "TLS_DH_anon_WITH_AES_256_CBC_SHA",  // { 0x00, 0x3A };

    "SSL_DH_anon_EXPORT_WITH_RC4_40_MD5",      // { 0x00,0x17 }
    "SSL_DH_anon_WITH_RC4_128_MD5",            // { 0x00,0x18 }
    "SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA",   // { 0x00,0x19 }
    "SSL_DH_anon_WITH_DES_CBC_SHA",            // { 0x00,0x1A }
    "SSL_DH_anon_WITH_3DES_EDE_CBC_SHA",       // { 0x00,0x1B }

    "TLS_ECDH_ECDSA_WITH_NULL_SHA",            // { 0xC0, 0x01 }
    "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",         // { 0xC0, 0x02 }
    "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",    // { 0xC0, 0x03 }
    "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",     // { 0xC0, 0x04 }
    "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",     // { 0xC0, 0x05 }

    "TLS_ECDHE_ECDSA_WITH_NULL_SHA",           // { 0xC0, 0x06 }
    "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",        // { 0xC0, 0x07 }
    "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",   // { 0xC0, 0x08 }
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",    // { 0xC0, 0x09 }
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",    // { 0xC0, 0x0A }

    "TLS_ECDH_RSA_WITH_NULL_SHA",              // { 0xC0, 0x0B }
    "TLS_ECDH_RSA_WITH_RC4_128_SHA",           // { 0xC0, 0x0C }
    "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",      // { 0xC0, 0x0D }
    "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",       // { 0xC0, 0x0E }
    "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",       // { 0xC0, 0x0F }

    //"TLS_ECDHE_RSA_WITH_NULL_SHA",             // { 0xC0, 0x10 }
    "TLS_ECDHE_RSA_WITH_RC4_128_SHA",          // { 0xC0, 0x11 }
    "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",     // { 0xC0, 0x12 }
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",      // { 0xC0, 0x13 }
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",      // { 0xC0, 0x14 }

    "TLS_ECDH_anon_WITH_NULL_SHA",             // { 0xC0, 0x15 }
    "TLS_ECDH_anon_WITH_RC4_128_SHA",          // { 0xC0, 0x16 }
    "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",     // { 0xC0, 0x17 }
    "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",      // { 0xC0, 0x18 }
    "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",      // { 0xC0, 0x19 }

  };

  /*
   * list taken from RFC 5246 (0x00,0x01) to (0x00,0x1B)
   * RFC 3268 (0x00,0x2F) to (0x00,0x3A) : AES
   * RFC 4492 (0xC0,xxxx) : ECC (Elliptic Curve Cryptography)
   * RFC 5288 (0x00,0x9C) to (0x00,0xA7) : GCM
   * RFC 5289 (0xC0,0x23) to (0xC0,0x2A) : ECC with SHA-2 SHA-3 CBC
   * RFC 5289 (0xC0,0x2B) to (0xC0,0x32) : ECC with SHA-2 SHA-3 GCM
   * cipher suites SUN JDK8 TLS 1.2,
   * ordered according to the RFC
   *
   * this list is finally a bit different than the one for RFC 2246
   */
  private final static String[] SUN_8_TLS1_2 = new String[] {
    "SSL_RSA_WITH_NULL_MD5",                   // { 0x00,0x01 }
    "SSL_RSA_WITH_NULL_SHA ",                  // { 0x00,0x02 }
    // "SSL_RSA_EXPORT_WITH_RC4_40_MD5",          // { 0x00,0x03 }
    "SSL_RSA_WITH_RC4_128_MD5",                // { 0x00,0x04 }
    "SSL_RSA_WITH_RC4_128_SHA",                // { 0x00,0x05 }
    // "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",      // { 0x00,0x06 }
    //"TLS_RSA_WITH_IDEA_CBC_SHA",               // { 0x00,0x07 }
    // "SSL_RSA_EXPORT_WITH_DES40_CBC_SHA",       // { 0x00,0x08 }
    //"SSL_RSA_WITH_DES_CBC_SHA",                // { 0x00,0x09 }
    "SSL_RSA_WITH_3DES_EDE_CBC_SHA",           // { 0x00,0x0A }

    // "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA",    // { 0x00,0x0B }
    //"TLS_DH_DSS_WITH_DES_CBC_SHA",             // { 0x00,0x0C }
    "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA",        // { 0x00,0x0D }
    // "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA",    // { 0x00,0x0E }
    //"TLS_DH_RSA_WITH_DES_CBC_SHA",             // { 0x00,0x0F }
    "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA",        // { 0x00,0x10 }
    // "SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",   // { 0x00,0x11 }
    //"SSL_DHE_DSS_WITH_DES_CBC_SHA",            // { 0x00,0x12 }
    "SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA",       // { 0x00,0x13 }
    // "SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",   // { 0x00,0x14 }
    //"SSL_DHE_RSA_WITH_DES_CBC_SHA",            // { 0x00,0x15 }
    "SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA",       // { 0x00,0x16 }


    "TLS_RSA_WITH_AES_128_CBC_SHA",      // { 0x00, 0x2F };
    "TLS_DH_DSS_WITH_AES_128_CBC_SHA",   // { 0x00, 0x30 };
    "TLS_DH_RSA_WITH_AES_128_CBC_SHA",   // { 0x00, 0x31 };
    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",  // { 0x00, 0x32 };
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",  // { 0x00, 0x33 };
    "TLS_DH_anon_WITH_AES_128_CBC_SHA",  // { 0x00, 0x34 };

    "TLS_RSA_WITH_AES_256_CBC_SHA",      // { 0x00, 0x35 };
    "TLS_DH_DSS_WITH_AES_256_CBC_SHA",   // { 0x00, 0x36 };
    "TLS_DH_RSA_WITH_AES_256_CBC_SHA",   // { 0x00, 0x37 };
    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",  // { 0x00, 0x38 };
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",  // { 0x00, 0x39 };
    "TLS_DH_anon_WITH_AES_256_CBC_SHA",  // { 0x00, 0x3A };
    "TLS_RSA_WITH_AES_128_CBC_SHA256",  // { 0x00, 0x3C };
    "TLS_RSA_WITH_AES_256_CBC_SHA256",  // { 0x00, 0x3D };
    "TLS_DH_DSS_WITH_AES_128_CBC_SHA256",  // { 0x00, 0x3E };
    "TLS_DH_RSA_WITH_AES_128_CBC_SHA256",  // { 0x00, 0x3F };
    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",  // { 0x00, 0x40 };
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",  // { 0x00, 0x67 };
    "TLS_DH_DSS_WITH_AES_256_CBC_SHA256",  // { 0x00, 0x68 };
    "TLS_DH_RSA_WITH_AES_256_CBC_SHA256",  // { 0x00, 0x69 };
    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",  // { 0x00, 0x6A };
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",  // { 0x00, 0x6B };
    "TLS_DH_anon_WITH_AES_128_CBC_SHA256",  // { 0x00, 0x6C };
    "TLS_DH_anon_WITH_AES_256_CBC_SHA256",  // { 0x00, 0x6D };

    //"SSL_DH_anon_EXPORT_WITH_RC4_40_MD5",      // { 0x00,0x17 }
    "SSL_DH_anon_WITH_RC4_128_MD5",            // { 0x00,0x18 }
    //"SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA",   // { 0x00,0x19 }
    //"SSL_DH_anon_WITH_DES_CBC_SHA",            // { 0x00,0x1A }
    "SSL_DH_anon_WITH_3DES_EDE_CBC_SHA",       // { 0x00,0x1B }

    "TLS_ECDH_ECDSA_WITH_NULL_SHA",            // { 0xC0, 0x01 }
    "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",         // { 0xC0, 0x02 }
    "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",    // { 0xC0, 0x03 }
    "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",     // { 0xC0, 0x04 }
    "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",     // { 0xC0, 0x05 }

    "TLS_ECDHE_ECDSA_WITH_NULL_SHA",           // { 0xC0, 0x06 }
    "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",        // { 0xC0, 0x07 }
    "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",   // { 0xC0, 0x08 }
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",    // { 0xC0, 0x09 }
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",    // { 0xC0, 0x0A }

    "TLS_ECDH_RSA_WITH_NULL_SHA",              // { 0xC0, 0x0B }
    "TLS_ECDH_RSA_WITH_RC4_128_SHA",           // { 0xC0, 0x0C }
    "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",      // { 0xC0, 0x0D }
    "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",       // { 0xC0, 0x0E }
    "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",       // { 0xC0, 0x0F }

    //"TLS_ECDHE_RSA_WITH_NULL_SHA",             // { 0xC0, 0x10 }
    "TLS_ECDHE_RSA_WITH_RC4_128_SHA",          // { 0xC0, 0x11 }
    "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",     // { 0xC0, 0x12 }
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",      // { 0xC0, 0x13 }
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",      // { 0xC0, 0x14 }

    "TLS_ECDH_anon_WITH_NULL_SHA",             // { 0xC0, 0x15 }
    "TLS_ECDH_anon_WITH_RC4_128_SHA",          // { 0xC0, 0x16 }
    "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",     // { 0xC0, 0x17 }
    "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",      // { 0xC0, 0x18 }
    "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",      // { 0xC0, 0x19 }

    "TLS_RSA_WITH_AES_128_GCM_SHA256",         // {0x00,0x9C}
    "TLS_RSA_WITH_AES_256_GCM_SHA384",         // {0x00,0x9D}
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",     // {0x00,0x9E}
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",     // {0x00,0x9F}
    "TLS_DH_RSA_WITH_AES_128_GCM_SHA256",      // {0x00,0xA0}
    "TLS_DH_RSA_WITH_AES_256_GCM_SHA384",      // {0x00,0xA1}
    "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",     // {0x00,0xA2}
    "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",     // {0x00,0xA3}
    "TLS_DH_DSS_WITH_AES_128_GCM_SHA256",      // {0x00,0xA4}
    "TLS_DH_DSS_WITH_AES_256_GCM_SHA384",      // {0x00,0xA5}
    "TLS_DH_anon_WITH_AES_128_GCM_SHA256",     // {0x00,0xA6}
    "TLS_DH_anon_WITH_AES_256_GCM_SHA384",     // {0x00,0xA7}

    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", // {0xC0,0x23};
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", // {0xC0,0x24};
    "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",  // {0xC0,0x25};
    "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",  // {0xC0,0x26};
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",   // {0xC0,0x27};
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",   // {0xC0,0x28};
    "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",    // {0xC0,0x29};
    "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",    // {0xC0,0x2A};
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", // {0xC0,0x2B};
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", // {0xC0,0x2C};
    "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",  // {0xC0,0x2D};
    "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",  // {0xC0,0x2E};
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",   // {0xC0,0x2F};
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",   // {0xC0,0x30};
    "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",    // {0xC0,0x31};
    "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384"    // {0xC0,0x32};

  };

  private final static String[] SUN_7_TLS1_2 = new String[] {
    "SSL_RSA_WITH_NULL_MD5",                   // { 0x00,0x01 }
    "SSL_RSA_WITH_NULL_SHA ",                  // { 0x00,0x02 }
    // "SSL_RSA_EXPORT_WITH_RC4_40_MD5",          // { 0x00,0x03 }
    "SSL_RSA_WITH_RC4_128_MD5",                // { 0x00,0x04 }
    "SSL_RSA_WITH_RC4_128_SHA",                // { 0x00,0x05 }
    // "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",      // { 0x00,0x06 }
    //"TLS_RSA_WITH_IDEA_CBC_SHA",               // { 0x00,0x07 }
    // "SSL_RSA_EXPORT_WITH_DES40_CBC_SHA",       // { 0x00,0x08 }
    //"SSL_RSA_WITH_DES_CBC_SHA",                // { 0x00,0x09 }
    "SSL_RSA_WITH_3DES_EDE_CBC_SHA",           // { 0x00,0x0A }

    // "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA",    // { 0x00,0x0B }
    //"TLS_DH_DSS_WITH_DES_CBC_SHA",             // { 0x00,0x0C }
    "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA",        // { 0x00,0x0D }
    // "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA",    // { 0x00,0x0E }
    //"TLS_DH_RSA_WITH_DES_CBC_SHA",             // { 0x00,0x0F }
    "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA",        // { 0x00,0x10 }
    // "SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",   // { 0x00,0x11 }
    //"SSL_DHE_DSS_WITH_DES_CBC_SHA",            // { 0x00,0x12 }
    "SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA",       // { 0x00,0x13 }
    // "SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",   // { 0x00,0x14 }
    //"SSL_DHE_RSA_WITH_DES_CBC_SHA",            // { 0x00,0x15 }
    "SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA",       // { 0x00,0x16 }


    "TLS_RSA_WITH_AES_128_CBC_SHA",      // { 0x00, 0x2F };
    "TLS_DH_DSS_WITH_AES_128_CBC_SHA",   // { 0x00, 0x30 };
    "TLS_DH_RSA_WITH_AES_128_CBC_SHA",   // { 0x00, 0x31 };
    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",  // { 0x00, 0x32 };
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",  // { 0x00, 0x33 };
    "TLS_DH_anon_WITH_AES_128_CBC_SHA",  // { 0x00, 0x34 };

    "TLS_RSA_WITH_AES_256_CBC_SHA",      // { 0x00, 0x35 };
    "TLS_DH_DSS_WITH_AES_256_CBC_SHA",   // { 0x00, 0x36 };
    "TLS_DH_RSA_WITH_AES_256_CBC_SHA",   // { 0x00, 0x37 };
    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",  // { 0x00, 0x38 };
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",  // { 0x00, 0x39 };
    "TLS_DH_anon_WITH_AES_256_CBC_SHA",  // { 0x00, 0x3A };
    "TLS_RSA_WITH_AES_128_CBC_SHA256",  // { 0x00, 0x3C };
    "TLS_RSA_WITH_AES_256_CBC_SHA256",  // { 0x00, 0x3D };
    "TLS_DH_DSS_WITH_AES_128_CBC_SHA256",  // { 0x00, 0x3E };
    "TLS_DH_RSA_WITH_AES_128_CBC_SHA256",  // { 0x00, 0x3F };
    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",  // { 0x00, 0x40 };
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",  // { 0x00, 0x67 };
    "TLS_DH_DSS_WITH_AES_256_CBC_SHA256",  // { 0x00, 0x68 };
    "TLS_DH_RSA_WITH_AES_256_CBC_SHA256",  // { 0x00, 0x69 };
    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",  // { 0x00, 0x6A };
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",  // { 0x00, 0x6B };
    "TLS_DH_anon_WITH_AES_128_CBC_SHA256",  // { 0x00, 0x6C };
    "TLS_DH_anon_WITH_AES_256_CBC_SHA256",  // { 0x00, 0x6D };

    //"SSL_DH_anon_EXPORT_WITH_RC4_40_MD5",      // { 0x00,0x17 }
    "SSL_DH_anon_WITH_RC4_128_MD5",            // { 0x00,0x18 }
    //"SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA",   // { 0x00,0x19 }
    //"SSL_DH_anon_WITH_DES_CBC_SHA",            // { 0x00,0x1A }
    "SSL_DH_anon_WITH_3DES_EDE_CBC_SHA",       // { 0x00,0x1B }

    "TLS_ECDH_ECDSA_WITH_NULL_SHA",            // { 0xC0, 0x01 }
    "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",         // { 0xC0, 0x02 }
    "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",    // { 0xC0, 0x03 }
    "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",     // { 0xC0, 0x04 }
    "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",     // { 0xC0, 0x05 }

    "TLS_ECDHE_ECDSA_WITH_NULL_SHA",           // { 0xC0, 0x06 }
    "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",        // { 0xC0, 0x07 }
    "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",   // { 0xC0, 0x08 }
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",    // { 0xC0, 0x09 }
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",    // { 0xC0, 0x0A }

    "TLS_ECDH_RSA_WITH_NULL_SHA",              // { 0xC0, 0x0B }
    "TLS_ECDH_RSA_WITH_RC4_128_SHA",           // { 0xC0, 0x0C }
    "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",      // { 0xC0, 0x0D }
    "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",       // { 0xC0, 0x0E }
    "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",       // { 0xC0, 0x0F }

    //"TLS_ECDHE_RSA_WITH_NULL_SHA",             // { 0xC0, 0x10 }
    "TLS_ECDHE_RSA_WITH_RC4_128_SHA",          // { 0xC0, 0x11 }
    "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",     // { 0xC0, 0x12 }
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",      // { 0xC0, 0x13 }
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",      // { 0xC0, 0x14 }

    "TLS_ECDH_anon_WITH_NULL_SHA",             // { 0xC0, 0x15 }
    "TLS_ECDH_anon_WITH_RC4_128_SHA",          // { 0xC0, 0x16 }
    "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",     // { 0xC0, 0x17 }
    "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",      // { 0xC0, 0x18 }
    "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",      // { 0xC0, 0x19 }

    // "TLS_RSA_WITH_AES_128_GCM_SHA256",         // {0x00,0x9C}
    // "TLS_RSA_WITH_AES_256_GCM_SHA384",         // {0x00,0x9D}
    // "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",     // {0x00,0x9E}
    // "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",     // {0x00,0x9F}
    "TLS_DH_RSA_WITH_AES_128_GCM_SHA256",      // {0x00,0xA0}
    "TLS_DH_RSA_WITH_AES_256_GCM_SHA384",      // {0x00,0xA1}
    // "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",     // {0x00,0xA2}
    // "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",     // {0x00,0xA3}
    "TLS_DH_DSS_WITH_AES_128_GCM_SHA256",      // {0x00,0xA4}
    "TLS_DH_DSS_WITH_AES_256_GCM_SHA384",      // {0x00,0xA5}
    "TLS_DH_anon_WITH_AES_128_GCM_SHA256",     // {0x00,0xA6}
    "TLS_DH_anon_WITH_AES_256_GCM_SHA384",     // {0x00,0xA7}

    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", // {0xC0,0x23};
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", // {0xC0,0x24};
    "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",  // {0xC0,0x25};
    "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",  // {0xC0,0x26};
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",   // {0xC0,0x27};
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",   // {0xC0,0x28};
    "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",    // {0xC0,0x29};
    "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384"     // {0xC0,0x2A};

  };

  /*
   * list taken from RFC 8446 (0x13,0x01) to (0x13,0x05)
   */
  private final static String[] SUN_8_TLS1_3 = new String[] {
    "TLS_AES_128_GCM_SHA256",                   // { 0x13,0x01 }
    "TLS_AES_256_GCM_SHA384",                   // { 0x13,0x02 }
    "TLS_CHACHA20_POLY1305_SHA256",             // { 0x13,0x03 }
    "TLS_AES_128_CCM_SHA256",                   // { 0x13,0x04 }
    "TLS_AES_128_CCM_8_SHA256"                  // { 0x13,0x05 }
  };

  private final static String[] SUN = new String[] {
    // 256
    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA",

    // 168
    "SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
    "SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    "SSL_RSA_WITH_3DES_EDE_CBC_SHA",

    // 128
    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    "SSL_RSA_WITH_RC4_128_MD5",
    "SSL_RSA_WITH_RC4_128_SHA",
    "TLS_RSA_WITH_AES_128_CBC_SHA",

    // 56
    "SSL_DHE_DSS_WITH_DES_CBC_SHA",
    "SSL_DHE_RSA_WITH_DES_CBC_SHA",
    "SSL_RSA_WITH_DES_CBC_SHA",

    // 40
    "SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
    "SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
    "SSL_RSA_EXPORT_WITH_DES40_CBC_SHA",
    "SSL_RSA_EXPORT_WITH_RC4_40_MD5",

    // 0
    "SSL_RSA_WITH_NULL_MD5",
    "SSL_RSA_WITH_NULL_SHA",

    // DH_anon
    "SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA",
    "SSL_DH_anon_EXPORT_WITH_RC4_40_MD5",
    "SSL_DH_anon_WITH_3DES_EDE_CBC_SHA",
    "SSL_DH_anon_WITH_DES_CBC_SHA",
    "SSL_DH_anon_WITH_RC4_128_MD5",
    "TLS_DH_anon_WITH_AES_128_CBC_SHA",
    "TLS_DH_anon_WITH_AES_256_CBC_SHA"

    // RFU
    // NULL 0
    //"SSL_NULL_WITH_NULL_NULL"
    // FORTEZZA 96
    /*see rfc2712.txt
    "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5",
    "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA",
    "TLS_KRB5_EXPORT_WITH_RC4_40_MD5",
    "TLS_KRB5_EXPORT_WITH_RC4_40_SHA",
    "TLS_KRB5_WITH_3DES_EDE_CBC_MD5",
    "TLS_KRB5_WITH_3DES_EDE_CBC_SHA",
    "TLS_KRB5_WITH_DES_CBC_MD5",
    "TLS_KRB5_WITH_DES_CBC_SHA",
    "TLS_KRB5_WITH_RC4_128_MD5",
    "TLS_KRB5_WITH_RC4_128_SHA",
    */
  };

  /*
   * AES_256 and AES_128 should be named with TLS_.. at the beginning, but SUN doesn't support these names
   */
  private final static String[] IBM = new String[] {
    // 256
    "SSL_DHE_DSS_WITH_AES_256_CBC_SHA",
    "SSL_DHE_RSA_WITH_AES_256_CBC_SHA",
    "SSL_RSA_WITH_AES_256_CBC_SHA",

    // 168
    "SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
    "SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    "SSL_RSA_WITH_3DES_EDE_CBC_SHA",
    "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA",

    // 128
    "SSL_DHE_DSS_WITH_AES_128_CBC_SHA",
    "SSL_DHE_RSA_WITH_AES_128_CBC_SHA",
    "SSL_RSA_WITH_AES_128_CBC_SHA",
    "SSL_DHE_DSS_WITH_RC4_128_SHA",
    "SSL_RSA_WITH_RC4_128_SHA",
    "SSL_RSA_WITH_RC4_128_MD5",

    // 56
    "SSL_DHE_DSS_WITH_DES_CBC_SHA",
    "SSL_DHE_RSA_WITH_DES_CBC_SHA",
    "SSL_RSA_WITH_DES_CBC_SHA",
    "SSL_RSA_FIPS_WITH_DES_CBC_SHA",

    // 40
    "SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
    "SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
    "SSL_RSA_EXPORT_WITH_DES40_CBC_SHA",
    "SSL_RSA_EXPORT_WITH_RC4_40_MD5",
    "SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5",

    // 0
    "SSL_RSA_WITH_NULL_MD5",
    "SSL_RSA_WITH_NULL_SHA",

    // DH_anon
    "SSL_DH_anon_WITH_AES_256_CBC_SHA",
    "SSL_DH_anon_WITH_3DES_EDE_CBC_SHA",
    "SSL_DH_anon_WITH_RC4_128_MD5",
    "SSL_DH_anon_WITH_AES_128_CBC_SHA",
    "SSL_DH_anon_WITH_DES_CBC_SHA",
    "SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA",
    "SSL_DH_anon_EXPORT_WITH_RC4_40_MD5"
  };

  /*
   * list taken from RFC 6101 (0x00,xxxx)
   * cipher suites SUN JDK7 SSL 3.0,
   * ordered according to the RFC
   */
  private final static String[] IBM_7_SSL2 = new String[] {
    "SSL_RSA_WITH_RC4_128_MD5",
    "SSL_RSA_WITH_RC4_128_SHA",
    "SSL_RSA_WITH_AES_128_CBC_SHA",
    "SSL_RSA_WITH_AES_256_CBC_SHA",
    "SSL_RSA_WITH_DES_CBC_SHA",
    "SSL_RSA_FIPS_WITH_DES_CBC_SHA",
    "SSL_RSA_WITH_3DES_EDE_CBC_SHA",
    "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA",
    "SSL_DHE_RSA_WITH_AES_128_CBC_SHA",
    "SSL_DHE_RSA_WITH_AES_256_CBC_SHA",
    "SSL_DHE_RSA_WITH_DES_CBC_SHA",
    "SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    "SSL_DHE_DSS_WITH_AES_128_CBC_SHA",
    "SSL_DHE_DSS_WITH_AES_256_CBC_SHA",
    "SSL_DHE_DSS_WITH_RC4_128_SHA",
    "SSL_DHE_DSS_WITH_DES_CBC_SHA",
    "SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
    "SSL_RSA_EXPORT_WITH_RC4_40_MD5",
    "SSL_RSA_EXPORT_WITH_DES40_CBC_SHA",
    "SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
    "SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
    "SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
    "SSL_RSA_WITH_NULL_MD5",
    "SSL_RSA_WITH_NULL_SHA",
    "SSL_DH_anon_WITH_AES_128_CBC_SHA",
    "SSL_DH_anon_WITH_AES_256_CBC_SHA",
    "SSL_DH_anon_WITH_RC4_128_MD5",
    "SSL_DH_anon_WITH_DES_CBC_SHA",
    "SSL_DH_anon_WITH_3DES_EDE_CBC_SHA",
    "SSL_DH_anon_EXPORT_WITH_RC4_40_MD5",
    "SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA"
  };

  /*
   * returns the ciphers list for the given provider and Java version
   * This list is ordered by the most secure first
   *
   * @param provider the provider
   * @param JavaVersion the Java version
   * @param SSLVersion the SSL/TLS version
   * @return String[]
   */
  private static String[] getCiphersByProvider(String provider, int JavaVersion, int SSLVersion) {
    String[] ciphers = new String[0];

    if(provider.equals("SUN"))
      switch(SSLVersion) {

        /* SSL 3 */
        case 3:
          switch(JavaVersion) {
            case 0:
              ciphers = SUN;
              break;

            case 7:
              ciphers = SUN_7_SSL3;
              break;

            case 8:
              // TO BE CHANGED - MAYBE
              ciphers = SUN_7_SSL3;
              break;

            default:
              //ciphers = SUN;
              ciphers = SUN_7_SSL3;
              break;
          }
          break;

        /* TLS 1.0 */
        case 4:
          switch(JavaVersion) {
            case 7:
            case 8:
            default:
              ciphers = SUN_8_TLS1_1;
              break;
          }
          break;

        /* TLS 1.1 */
        case 5:
          switch(JavaVersion) {
            case 7:
            case 8:
            default:
              ciphers = SUN_8_TLS1;
              break;
          }
          break;

        /* TLS 1.2 */
        case 6:
        default:
          switch(JavaVersion) {
            case 7:
              ciphers = SUN_7_TLS1_2;
              break;
            case 8:
            default:
              ciphers = SUN_8_TLS1_2;
              break;
          }
          break;

        /* TLS 1.3 */
        case 7:
          switch(JavaVersion) {
            default:
              ciphers = SUN_8_TLS1_3;
              break;
          }
          break;

      }

    if(provider.equals("IBM")) {
      switch(SSLVersion) {

        /* SSL 2 */
        case 2:
        case 3:
        default:
          switch(JavaVersion) {
            case 0:
            default:
              ciphers = IBM_7_SSL2;
              break;
          }
        break;
      }
    }

    return ciphers;
  }

  /*
   * returns the ciphers list for the given provider and Java version
   * This list is ordered by the most secure first
   *
   * @param provider the provider
   * @return String[]
   */
  private static String[] getCiphersByProvider(String provider, int JavaVersion, String SSLVersion) {
    String[] rez = new String[0];

    switch(SSLVersion) {

      case "SSLv2" :
        rez = getCiphersByProvider(provider, JavaVersion, 2);
        break;

      case "SSLv3" :
        rez = getCiphersByProvider(provider, JavaVersion, 3);
        break;

      case "TLSv1" :
        rez = getCiphersByProvider(provider, JavaVersion, 4);
        break;

      case "TLSv1.1" :
        rez = getCiphersByProvider(provider, JavaVersion, 5);
        break;

      case "TLSv1.2" :
        rez = getCiphersByProvider(provider, JavaVersion, 6);
        break;

      case "TLSv1.3" :
        rez = getCiphersByProvider(provider, JavaVersion, 7);
        break;

      // defaults to TLS 1.0 - aka value "4"
      default :
        rez = getCiphersByProvider(provider, JavaVersion, 4);
        break;

    }

    return rez;
  }

 // tmp , to be removed when possible
  public static String[] getCiphersByProvider(String provider) {
    return getCiphersByProvider("SUN", RuntimeUtil.getVersion(), "TLSv1");
  }

  public static String[] getCiphersByProvider(String provider, String SSLVersion) {
    return getCiphersByProvider(provider, RuntimeUtil.getVersion(), SSLVersion );
  }

  public static String convertGUIConnConnect(String guiValue) {
    String rez = "";

    switch(guiValue) {
      case "SSL 2.0":
        rez = "SSLv2";
        break;

      case "SSL 3.0":
        rez = "SSLv3";
        break;

      case "TLS 1.0":
        rez = "TLSv1";
        break;

      case "TLS 1.1":
        rez = "TLSv1.1";
        break;

      case "TLS 1.2":
        rez = "TLSv1.2";
        break;

      case "TLS 1.3":
        rez = "TLSv1.3";
        break;
    }

    return rez;
  }

} // end class

class ScenarioTimerTask extends TimerTask {

  private SimpleScenario cus;

  public ScenarioTimerTask(SimpleScenario cus) {
    //super();
    this.cus = cus;
  }

  public void run() {
    cus.run();
  }

}

class SSLProxyAuthScenario extends SimpleScenario {

  private boolean reuse = false;

  private String user = "";
  private String passwd = "";

  private boolean blnFound = false;

  private boolean blnExportCert;

  public SSLProxyAuthScenario(SSLTransactionViaProxy handle) {
    super(handle);
  }
  public SSLProxyAuthScenario(SSLTransactionViaProxy handle, boolean logtime, String user, String passwd) {
    super(handle, logtime);
    this.user = user;
    this.passwd = passwd;
  }
  public SSLProxyAuthScenario(SSLTransactionViaProxy handle, boolean logtime, String user, String passwd, boolean blnExportCert) {
    super(handle, logtime);
    this.user = user;
    this.passwd = passwd;
    this.blnExportCert = blnExportCert;
  }
  public SSLProxyAuthScenario(SSLTransactionViaProxy handle, boolean logtime, String user, String passwd, boolean blnExportCert, CookieWrapper cookiewrapper) {
    super(handle, logtime, cookiewrapper);
    this.user = user;
    this.passwd = passwd;
    this.blnExportCert = blnExportCert;
  }
  public SSLProxyAuthScenario(SSLTransactionViaProxy handle, boolean logtime, String user, String passwd, boolean blnExportCert, GenericCookie cookies) {
    super(handle, logtime, cookies);
    this.user = user;
    this.passwd = passwd;
    this.blnExportCert = blnExportCert;
  }

  public void run() {
    Date startDate1 = new Date();
    boolean is407;

    // récupération des paramètres pour la conn

    //RequestMessageHeader hprox = new RequestMessageHeader();
    //LAST RequestMessageHeader hprox = (RequestMessageHeader)(RequestMessageHeaderFactory.create(null));
    ReqMessageHeader hprox = new ReqMessageHeader();

    //RequestMessageHeader hprox = (RequestMessageHeader)(RequestMessageHeaderFactory.create(handle.getCookies()));
    //System.err.println(handle.getCookies().toString());
    try {
      hprox.setRequestURI(handle.getRequestMessage().getHostname().concat(":").concat(handle.getRequestMessage().getPort()));
      hprox.setMethod("CONNECT");
      hprox.setHTTPVersion(handle.getRequestMessage().getHTTPVersion());
      //hprox.setHostname(handle.getProxyName());
      // in order to save the cookie with the final web server 'name'
      hprox.setHostname(handle.getProxyName());
      hprox.setPort( Integer.toString(handle.getProxyPort()) );

      // en 1.1 => positionner le header Host
      if( handle.getRequestMessage().getHTTPVersion().equals("HTTP/1.1") )
        hprox.addHeader("Host", handle.getRequestMessage().getHostname());
    }
    catch(MalformedHeaderException mhe) {
      // Ce cas ne peut pas se présenter donc aucune action
    }

    RequestMessage rm = new RequestMessage(hprox);

    // construction de la connection au proxy
    // TO DO : vérifier cet appel de constructeur
    PlainTransaction spt = new PlainTransaction(handle.getBSH(), handle.getMPS(), handle.getHTMLStamps(), handle.getCookies());
    spt.setRequestMessage(rm);

    // TO DO : check cette valeur
    //IOState = spt.runScenario(reuse, null)[1];
    ScenarioResult srr = spt.runScenario(reuse, null);

    if(wrapper != null) {
      Vector<RawCookieNetscape> vecCN = srr.getCookieNetscape();

      if(vecCN.size() > 0) {
        wrapper.add(spt.getRequestMessage().getHostname(),
                    spt.getRequestMessage().getRequestURI(),
                    (RawCookieNetscape[])vecCN.toArray(new RawCookieNetscape[0]),
                    true);
      }

      Vector<RawCookieV1> vecCV = srr.getCookieV1();

      if(vecCV.size() > 0) {
        // TO DO
      }

      wrapper.saveAll();
    }

    is407 = spt.getResponseMessage().getStatusCode().equals("407");

    // fermeture explicite afin de forcer le init du proxy (cas utile uniquement en HTTP/1.1)
    handle.closeConnection();

    // check the 1st response : it should return a 407 with "WWW-Authenticate: Digest challenge" header line
    if(is407) {

      // EN COURS : refresh the cookies if necessary (if cookies were sent by the proxy itself, as in load-balancing cases)
      //handle.getRequestMessage().refreshCookies();

      Hashtable<String, String> h = new Hashtable<String, String>();

      // optional Authentication-Info header (see RFC2617 §3.2.3) (but could be in the trailer when chunked is used)
      try {
        String[] strAInfo = spt.getResponseMessage().getHeader("Authentication-Info");
        // TO DO
      }
      catch(UndefinedHeaderException uhe) {}

      try {
        String[] strDig = spt.getResponseMessage().getHeader("Proxy-Authenticate");

        // there should be only ONE header, but in case there are several we keep the first matching "basic"||"digest" without any warning/error
        int i = 0;

        while(i < strDig.length && (!blnFound)) {
          String strVal = (strDig[i]).trim();

          // BASIC scheme
          if(strVal.toLowerCase().startsWith("basic")) {

            blnFound = true;

            // encodage Base64
            String basic = RFC2617.toBasicCredentials(user, passwd);

            // positionnement des User-Agent(s) s'il le header est défini (obligé de segmenter le try/catch en 2 parties)
            try {
              spt.getRequestMessage().addHeader("User-Agent", handle.getRequestMessage().getHeader("User-Agent"));
            }
            catch(MalformedHeaderNameException mhne) {}
            catch(MalformedHeaderValueException mhve) {}
            catch(UndefinedHeaderException mhve) {}

            try {
              spt.getRequestMessage().addHeader("Proxy-Authorization", basic);
              ((SSLTransactionViaProxy)handle).setProxyRequest(spt.getRequestMessage());
              //boolean[] brez = handle.runScenario(reuse, null);
              //keepalive = brez[0];
              ScenarioResult sr = handle.runScenario(reuse, wrapper);
              keepalive = sr.getKeepAlive();

              if(wrapper != null) {
                Vector<RawCookieNetscape> vecCN = sr.getCookieNetscape();

                if(vecCN.size() > 0) {
                  wrapper.add(handle.getRequestMessage().getHostname(),
                              handle.getRequestMessage().getRequestURI(),
                              (RawCookieNetscape[])vecCN.toArray(new RawCookieNetscape[0]),
                              false);
                }

                Vector<RawCookieV1> vecCV = sr.getCookieV1();

                if(vecCV.size() > 0) {
                  wrapper.add(handle.getRequestMessage().getHostname(),
                              (RawCookieV1[])vecCV.toArray(new RawCookieV1[0]));
                }

                wrapper.saveAll();
              }

              //IOState = brez[1];
            }
            catch(MalformedHeaderNameException mhne) {}
            catch(MalformedHeaderValueException mhve) {}
          }

          // DIGEST scheme
          if(strVal.toLowerCase().startsWith("digest")) {

            int challenge_index = strVal.indexOf(" ");

            if(challenge_index > 0)
              h = DigestChallenge.extractDirectives(strVal.substring(challenge_index + 1), false);

            if(h.size() > 0) {
              blnFound = true;
              String entitybody = "";

              if( !((String)h.get("qop-options")).equals("") ) {
                h.put("ncvalue", "00000001"); // we suppose it is always the 1st request with that nonce
                h.put("cnonce", "abcd5678");
                String[] qopz = ((String)h.get("qop-options")).split(",");
                boolean blnaut = false, blnint = false;

                for(int iqo = 0; iqo < qopz.length; iqo++) {
                  if(qopz[iqo].equals("auth"))
                    blnaut = true;

                  if(qopz[iqo].equals("auth-int"))
                    blnint = true;
                }

                // "auth" has more priority than "auth-int", and "auth-int" more than any other
                if(blnaut)
                  h.put("qop-options", "");
                else {
                  if(blnint) {
                    h.put("qop-options", "auth-int");
                    // we suppose RequestMessage.body is stored without any transfer-coding applied, otherwise change this code
                    entitybody = spt.getRequestMessage().getBody();
                  }
                  else {
                    System.err.println("shouldn't happen : " + h.get("qop-options"));
                    // TO DO : RFU ?
                  }
                }
              }
              else {
                h.put("ncvalue", "");
                h.put("cnonce", "");
              }

              String digest = RFC2617.toDigestCredentials((String)h.get("algorithm"),
                              user, (String)h.get("realm"), passwd, (String)h.get("nonce"),
                              (String)h.get("ncvalue"), (String)h.get("cnonce"),
                              spt.getRequestMessage().getMethod(),
                              spt.getRequestMessage().getRequestURI(),
                              entitybody,
                              (String)h.get("qop-options"),
                              (String)h.get("opaque") );

              // the 2nd request is now ready !!
              try {
                spt.getRequestMessage().addHeader("Proxy-Authorization", digest);
                ((SSLTransactionViaProxy)handle).setProxyRequest(spt.getRequestMessage());
                //boolean[] brez = handle.runScenario(reuse, null);
                //keepalive = brez[0];
                ScenarioResult sr = handle.runScenario(reuse, wrapper);
                keepalive = sr.getKeepAlive();
                //IOState = brez[1];

                if(wrapper != null) {
                  Vector<RawCookieNetscape> vecCN = sr.getCookieNetscape();

                  if(vecCN.size() > 0) {
                    wrapper.add(handle.getRequestMessage().getHostname(),
                                handle.getRequestMessage().getRequestURI(),
                                (RawCookieNetscape[])vecCN.toArray(new RawCookieNetscape[0]),
                                false);
                  }

                  Vector<RawCookieV1> vecCV = sr.getCookieV1();

                  if(vecCV.size() > 0) {
                    wrapper.add(handle.getRequestMessage().getHostname(),
                                (RawCookieV1[])vecCV.toArray(new RawCookieV1[0]));
                  }

                  wrapper.saveAll();
                }

              }
              catch(MalformedHeaderNameException mhne) {}
              catch(MalformedHeaderValueException mhve) {}
            }

          }

          // seek next header, whenever this one was not good (paranoid)
          i++;
        }
      }
      catch(UndefinedHeaderException uhe) {}
    }


    Date endDate1 = new Date();

    if(logtime)
      System.err.println("total time " + (endDate1.getTime() - startDate1.getTime()) + " ms");

    // export certificate to file if requested in command-line
    if(blnExportCert) {
      Hashtable h = handle.getHandshakeInfo();

      try {
        // Get the encoded form which is suitable for exporting
        X509Certificate[] certs = (X509Certificate[])h.get("peerCertificates");

        // write to the file
        int i = 0;
        String stmp;

        while(i < certs.length) {
          stmp = (i == 0) ? "webcert.pem" : "AC_" + i + ".pem" ;
          CertificateUtil.exportToFile(certs[i++], stmp);
        }
      }
      catch(NullPointerException npe) {
        // happens for DH_ANON or KERBEROS ciphersuites, do nothing
      }
    } // end export

  }

}

/*
 * classe implémentant le ProxyAuthScenario
 * celui-ci se compose d'une 1ère requête sans authentification afin d'obtenir le type d'authentification et le challenge
 * et d'une seconde requête avec les credentials calculés avec le challenge reçu précedemment
 */
class ProxyAuthScenario extends SimpleScenario {

  private boolean reuse = false;

  private String user = "";
  private String passwd = "";

  private boolean blnFound = false;

  public ProxyAuthScenario(HTTPTransaction handle) {
    super(handle);
  }
  public ProxyAuthScenario(HTTPTransaction handle, boolean logtime, String user, String passwd) {
    super(handle, logtime);
    this.user = user;
    this.passwd = passwd;
  }
  public ProxyAuthScenario(HTTPTransaction handle, boolean logtime, String user, String passwd, GenericCookie cookies) {
    super(handle, logtime, cookies);
    this.user = user;
    this.passwd = passwd;
  }
  public ProxyAuthScenario(HTTPTransaction handle, boolean logtime, String user, String passwd, CookieWrapper cookiewrapper) {
    super(handle, logtime, cookiewrapper);
    this.user = user;
    this.passwd = passwd;
  }

  public void run() {
    Date startDate1 = new Date();
    boolean is407;

    HTTPTransaction hold;
    // TO DO : check cette valeur
    //boolean[] brez = handle.runScenario(reuse, null);
    //keepalive = brez[0];
    ScenarioResult sr = handle.runScenario(reuse, wrapper);

    if(wrapper != null) {
      Vector<RawCookieNetscape> vecCN = sr.getCookieNetscape();

      if(vecCN.size() > 0) {
        wrapper.add(handle.getRequestMessage().getHostname(),
                    handle.getRequestMessage().getRequestURI(),
                    (RawCookieNetscape[])vecCN.toArray(new RawCookieNetscape[0]),
                    false);
      }

      Vector<RawCookieV1> vecCV = sr.getCookieV1();

      if(vecCV.size() > 0) {
        wrapper.add(handle.getRequestMessage().getHostname(),
                    (RawCookieV1[])vecCV.toArray(new RawCookieV1[0]));
      }

      wrapper.saveAll();
    }

    keepalive = sr.getKeepAlive();
    //IOState = brez[1];
    is407 = handle.getResponseMessage().getStatusCode().equals("407");
    hold = handle;

    // check the 1st response : it should return a 401 with "WWW-Authenticate: Digest challenge" header line
    if(is407) {
      Hashtable<String, String> h = new Hashtable<String, String>();

      // optional Authentication-Info header (see RFC2617 §3.2.3) (but could be in the trailer when chunked is used)
      try {
        String[] strAInfo = hold.getResponseMessage().getHeader("Authentication-Info");
        // TO DO
      }
      catch(UndefinedHeaderException uhe) {}

      try {
        String[] strDig = hold.getResponseMessage().getHeader("Proxy-Authenticate");

        // there should be only ONE header, but in case there are several we keep the first matching "basic"||"digest" without any warning/error
        int i = 0;

        while(i < strDig.length && (!blnFound)) {
          String strVal = (strDig[i]).trim();

          // BASIC scheme
          if(strVal.toLowerCase().startsWith("basic")) {

            blnFound = true;

            // encodage Base64
            String basic = RFC2617.toBasicCredentials(user, passwd);

            // the 2nd request is now ready !!
            try {
              //EN COURS : build a new request from the clone object (necessary to refresh the cookies)
              //handle.setRequestMessage();Personne personne2 = (Personne) personne1.clone();
              //handle.getRequestMessage().refreshCookies();
              handle.getRequestMessage().addHeader("Proxy-Authorization", basic);
              //brez = handle.runScenario(reuse, null);
              //keepalive = brez[0];
              sr = handle.runScenario(reuse, wrapper);
              keepalive = sr.getKeepAlive();
              //IOState = brez[1];

              if(wrapper != null) {
                Vector<RawCookieNetscape> vecCN = sr.getCookieNetscape();

                if(vecCN.size() > 0) {
                  wrapper.add(handle.getRequestMessage().getHostname(),
                              handle.getRequestMessage().getRequestURI(),
                              (RawCookieNetscape[])vecCN.toArray(new RawCookieNetscape[0]),
                              false);
                }

                Vector<RawCookieV1> vecCV = sr.getCookieV1();

                if(vecCV.size() > 0) {
                  wrapper.add(handle.getRequestMessage().getHostname(),
                              (RawCookieV1[])vecCV.toArray(new RawCookieV1[0]));
                }

                wrapper.saveAll();
              }

            }
            catch(MalformedHeaderNameException mhne) {}
            catch(MalformedHeaderValueException mhve) {}
          }

          // DIGEST scheme
          if(strVal.toLowerCase().startsWith("digest")) {

            int challenge_index = strVal.indexOf(" ");

            if(challenge_index > 0)
              h = DigestChallenge.extractDirectives(strVal.substring(challenge_index + 1), false);

            if(h.size() > 0) {
              blnFound = true;
              String entitybody = "";

              if( !((String)h.get("qop-options")).equals("") ) {
                h.put("ncvalue", "00000001"); // we suppose it is always the 1st request with that nonce
                h.put("cnonce", "abcd5678");
                String[] qopz = ((String)h.get("qop-options")).split(",");
                boolean blnaut = false, blnint = false;

                for(int iqo = 0; iqo < qopz.length; iqo++) {
                  if(qopz[iqo].equals("auth"))
                    blnaut = true;

                  if(qopz[iqo].equals("auth-int"))
                    blnint = true;
                }

                // "auth" has more priority than "auth-int", and "auth-int" more than any other
                if(blnaut)
                  h.put("qop-options", "");
                else {
                  if(blnint) {
                    h.put("qop-options", "auth-int");
                    // we suppose RequestMessage.body is stored without any transfer-coding applied, otherwise change this code
                    entitybody = hold.getRequestMessage().getBody();
                  }
                  else {
                    System.err.println("shouldn't happen : " + h.get("qop-options"));
                    // TO DO : RFU ?
                  }
                }
              }
              else {
                h.put("ncvalue", "");
                h.put("cnonce", "");
              }

              String digest = RFC2617.toDigestCredentials((String)h.get("algorithm"),
                              user, (String)h.get("realm"), passwd, (String)h.get("nonce"),
                              (String)h.get("ncvalue"), (String)h.get("cnonce"),
                              hold.getRequestMessage().getMethod(),
                              hold.getRequestMessage().getRequestURI(),
                              entitybody,
                              (String)h.get("qop-options"),
                              (String)h.get("opaque") );

              // the 2nd request is now ready !!
              try {
                handle.getRequestMessage().addHeader("Proxy-Authorization", digest);
                //brez = handle.runScenario(reuse, null);
                //keepalive = brez[0];
                sr = handle.runScenario(reuse, wrapper);
                keepalive = sr.getKeepAlive();
                //IOState = brez[1];

                if(wrapper != null) {
                  Vector<RawCookieNetscape> vecCN = sr.getCookieNetscape();

                  if(vecCN.size() > 0) {
                    wrapper.add(handle.getRequestMessage().getHostname(),
                                handle.getRequestMessage().getRequestURI(),
                                (RawCookieNetscape[])vecCN.toArray(new RawCookieNetscape[0]),
                                false);
                  }

                  Vector<RawCookieV1> vecCV = sr.getCookieV1();

                  if(vecCV.size() > 0) {
                    wrapper.add(handle.getRequestMessage().getHostname(),
                                (RawCookieV1[])vecCV.toArray(new RawCookieV1[0]));
                  }

                  wrapper.saveAll();
                }

              }
              catch(MalformedHeaderNameException mhne) {}
              catch(MalformedHeaderValueException mhve) {}
            }

          }

          // seek next header, whenever this one was not good (paranoid)
          i++;
        }
      }
      catch(UndefinedHeaderException uhe) {}
    }


    Date endDate1 = new Date();

    if(logtime)
      System.err.println("total time " + (endDate1.getTime() - startDate1.getTime()) + " ms");
  }

}

/*
 * classes de type ActionListener pour les différentes actions de la GUI
 */
class swgAbort implements ActionListener {
  JTouch jtouch;

  swgAbort ( JTouch jtouch ) {
    this.jtouch = jtouch;
  }

  public void actionPerformed ( ActionEvent e ) {
    jtouch.swgAbort();
  }

}

class swgAdvList implements ActionListener {
  JTouch jtouch;

  swgAdvList ( JTouch jtouch ) {
    this.jtouch = jtouch;
  }

  public void actionPerformed ( ActionEvent e ) {
    jtouch.swgAdvList();
  }

}

class swgAuthMethod implements ActionListener {
  JTouch jtouch;

  swgAuthMethod ( JTouch jtouch ) {
    this.jtouch = jtouch;
  }

  public void actionPerformed ( ActionEvent e ) {
    jtouch.swgAuthMethod();
  }

}

class swgConfigSSL implements ActionListener {
  JTouch jtouch;

  swgConfigSSL ( JTouch jtouch ) {
    this.jtouch = jtouch;
  }

  public void actionPerformed ( ActionEvent e ) {
    jtouch.swgConfigSSL();
  }

}

class swgAbout implements ActionListener {
  JTouch jtouch;

  swgAbout ( JTouch jtouch ) {
    this.jtouch = jtouch;
  }

  public void actionPerformed ( ActionEvent e ) {
    jtouch.swgAbout();
  }

}

class swgConnCipher implements ActionListener {
  JTouch jtouch;

  swgConnCipher ( JTouch jtouch ) {
    this.jtouch = jtouch;
  }

  public void actionPerformed ( ActionEvent e ) {
    jtouch.swgConnCipher();
  }

}

class swgConnConnect implements ActionListener {
  JTouch jtouch;

  swgConnConnect ( JTouch jtouch ) {
    this.jtouch = jtouch;
  }

  public void actionPerformed ( ActionEvent e ) {
    jtouch.swgConnConnect();
  }

}

class swgGo implements ActionListener {
  JTouch jtouch;

  swgGo ( JTouch jtouch ) {
    this.jtouch = jtouch;
  }

  public void actionPerformed ( ActionEvent e ) {
    jtouch.swgGo();
  }

}

class swgHost implements ActionListener {
  JTouch jtouch;

  swgHost ( JTouch jtouch ) {
    this.jtouch = jtouch;
  }

  public void actionPerformed ( ActionEvent e ) {
    jtouch.swgHost();
  }

}

class swgLogSettings implements ActionListener {
  JTouch jtouch;

  swgLogSettings ( JTouch jtouch ) {
    this.jtouch = jtouch;
  }

  public void actionPerformed ( ActionEvent e ) {
    jtouch.swgLogSettings();
  }

}

class swgExportCertificate implements ActionListener {
  JTouch jtouch;
  X509Certificate[] certs;
  String filename;

  swgExportCertificate ( JTouch jtouch, X509Certificate[] certs, String filename ) {
    this.jtouch = jtouch;
    this.certs = certs;
    this.filename = filename;
  }

  public void actionPerformed ( ActionEvent e ) {
    jtouch.swgExportCertificate(certs, filename);
  }

}

class swgMethod implements ActionListener {
  JTouch jtouch;

  swgMethod ( JTouch jtouch ) {
    this.jtouch = jtouch;
  }

  public void actionPerformed ( ActionEvent e) {
    jtouch.swgMethod();
  }

}

class swgPath implements ActionListener {
  JTouch jtouch;

  swgPath ( JTouch jtouch ) {
    this.jtouch = jtouch;
  }

  public void actionPerformed ( ActionEvent e ) {
    jtouch.swgPath();
  }

}

class swgPort implements ActionListener {
  JTouch jtouch;

  swgPort ( JTouch jtouch ) {
    this.jtouch = jtouch;
  }

  public void actionPerformed ( ActionEvent e ) {
    jtouch.swgPort();
  }

}

class swgProxOnOff implements ActionListener {
  JTouch jtouch;

  swgProxOnOff ( JTouch jtouch ) {
    this.jtouch = jtouch;
  }

  public void actionPerformed ( ActionEvent e ) {
    jtouch.swgProxOnOff();
  }

}

class swgQuitter implements ActionListener {
  JTouch jtouch;

  swgQuitter ( JTouch jtouch ) {
    this.jtouch = jtouch;
  }

  public void actionPerformed ( ActionEvent e ) {
    jtouch.swgQuitter();
  }

}

class swgSelectPLAF implements ActionListener {
  JTouch jtouch;

  swgSelectPLAF ( JTouch jtouch ) {
    this.jtouch = jtouch;
  }

  public void actionPerformed ( ActionEvent e ) {
    jtouch.swgSelectPLAF();
  }

}

class swgSSLServerCheckUp implements ActionListener {
  JTouch jtouch;

  swgSSLServerCheckUp ( JTouch jtouch ) {
    this.jtouch = jtouch;
  }

  public void actionPerformed ( ActionEvent e ) {
    jtouch.swgSSLServerCheckUp();
  }

}

class swgSSLTruststore implements ActionListener {
  JTouch jtouch;

  swgSSLTruststore ( JTouch jtouch ) {
    this.jtouch = jtouch;
  }

  public void actionPerformed ( ActionEvent e ) {
    jtouch.swgSSLTruststore();
  }

}

class swgInstalledProviders implements ActionListener {
  JTouch jtouch;

  swgInstalledProviders ( JTouch jtouch ) {
    this.jtouch = jtouch;
  }

  public void actionPerformed ( ActionEvent e ) {
    jtouch.swgInstalledProviders();
  }

}

class swgLastCertificate implements ActionListener {
  JTouch jtouch;

  swgLastCertificate ( JTouch jtouch ) {
    this.jtouch = jtouch;
  }

  public void actionPerformed ( ActionEvent e ) {
    jtouch.swgLastCertificate();
  }

}

class swgVersion implements ActionListener {
  JTouch jtouch;

  swgVersion ( JTouch jtouch ) {
    this.jtouch = jtouch;
  }

  public void actionPerformed ( ActionEvent e ) {
    jtouch.swgVersion();
  }

}

class swgCookieSupport implements ActionListener {
  JTouch jtouch;

  swgCookieSupport ( JTouch jtouch ) {
    this.jtouch = jtouch;
  }

  public void actionPerformed ( ActionEvent e ) {
    jtouch.swgCookieSupport();
  }

}

class swgSSLRandom implements ActionListener {
  JTouch jtouch;

  swgSSLRandom ( JTouch jtouch ) {
    this.jtouch = jtouch;
  }

  public void actionPerformed ( ActionEvent e ) {
    jtouch.swgSSLRandom();
  }

}

class swgWindowListener implements WindowListener {
  JTouch jtouch;

  swgWindowListener( JTouch jtouch) {
    this.jtouch = jtouch;
  }

  public void windowActivated(WindowEvent e) {
    System.err.println(e);
  }
  public void windowClosed(WindowEvent e) {
    System.err.println(e);
  }
  public void windowClosing(WindowEvent e) {
    System.err.println(e);
  }
  public void windowDeactivated(WindowEvent e) {
    System.err.println(e);
  }
  public void windowDeiconified(WindowEvent e) {
    System.err.println(e);
  }
  public void windowIconified(WindowEvent e) {
    System.err.println(e);
  }
  public void windowOpened(WindowEvent e) {
    System.err.println(e);
  }

}

class swgComponentListener implements ComponentListener {
  JTouch jtouch;

  swgComponentListener( JTouch jtouch) {
    this.jtouch = jtouch;
  }

  public void componentResized(ComponentEvent ce) {
    try {
      SwingUtilities.invokeLater(new Runnable() {
        public void run() {
          // forcer le rafraichissement de la fenêtre
          SwingUtilities.updateComponentTreeUI(jtouch);
          jtouch.pack();
        }
      });
    }
    catch(Exception e) {
      System.err.println(e);
    }
  }

  public void componentMoved(ComponentEvent ce) {}
  public void componentShown(ComponentEvent ce) {}
  public void componentHidden(ComponentEvent ce) {}

}

/*
 * classes pour le PATTERN Factory appliqué au RequestMessageHeader
 */

class RequestMessageHeaderFactory {

  public static RequestMessageHeader create(GenericCookie ocook) {
    if(ocook != null)
      return new RequestMessageHeaderWithCookies(ocook);
    else
      return new RequestMessageHeaderWithoutCookies();
  }

}


class ResponseMessageHeaderFactory {

  public static ResponseMessageHeader create(Hashtable cookz) {

    if(cookz != null)
      return new ResponseMessageHeaderWithCookies(cookz);
    else
      return new ResponseMessageHeaderWithoutCookies();
  }

  public static ResponseMessageHeader create(ByteArrayOutputStream baz, GenericCookie cookz, String hostname, String URL) throws MalformedHeaderException, HeaderExtraDataException {

    //System.err.println("debug cookz:" + (cookz==null));

    if(cookz != null)
      return new ResponseMessageHeaderWithCookies(baz, cookz, hostname, URL);
    else
      return new ResponseMessageHeaderWithoutCookies(baz);
  }

}

class ResponseMessageHeaderWithCookies extends ResponseMessageHeader {

  public String hostname = "";
  public String path = "";
  private GenericCookie ocookie;

  public ResponseMessageHeaderWithCookies(Hashtable cookz) {}

  public ResponseMessageHeaderWithCookies(ByteArrayOutputStream daIn, GenericCookie ocookie, String hostname, String url) throws MalformedHeaderException, HeaderExtraDataException {
    super(daIn);
    this.ocookie = ocookie;
    this.hostname = hostname;
    this.path = url;
    /*  très important : cet appel à parse ne peut pas être automatisé dans le constructeur de la classe mère
        car les champs cookies et hostname n'auraient pas été initialisés ! */
    parse();
  }

  /*
   * ajoute un header
   * c'est ici que la différenciation pour la gestion des cookies est effectuée : si un cookie est présent on doit le sauvegarder
   */
  public void addHeader(String headerName, String headerValue) throws MalformedHeaderNameException, MalformedHeaderValueException {
    addHeader(headerName, headerValue, false);
  }

  public final void addHeader(String headerName, String headerValue, boolean merge) throws MalformedHeaderNameException, MalformedHeaderValueException {

    if( isCorrectHeaderName(headerName) ) {
      try {
        String strCleanedVal = getCleanedHeaderVal(headerValue);

        if(merge) {
          boolean isFound = false;

          // parse the existing headers
          for (Enumeration e = headers.elements(); e.hasMoreElements();) {

            String[] headerNameAndValue = (String[]) e.nextElement();

            if( headerName.toLowerCase().equals(headerNameAndValue[0].toLowerCase()) ) {

              // build the new element : add this value to the previous ones
              String[] s = new String[headerNameAndValue.length + 1];
              System.arraycopy(headerNameAndValue, 0, s, 0, headerNameAndValue.length);
              s[headerNameAndValue.length] = strCleanedVal;

              // replace the element in the vector
              isFound = true;
              this.headers.remove(headerNameAndValue);
              this.headers.add(s);
            }
          }

          if(!isFound)
            this.headers.add( new String[] {headerName, strCleanedVal} );
        }
        else {
          // just add another one in the vector
          this.headers.add(new String[] { headerName, strCleanedVal } );
        }

        // RFC2616 §4.2 indique que l'on peut assembler plusieurs headers de même header-value en un seul, le séparateur étant ","
        // c'est ce que l'on va faire ici pour les cookies
        // TEST : on peut utiliser le site www.pagesjaunes.fr qui renvoie plusieurs cookies
        // www.pagesjaunes.fr/ciweb2g-pagesjaunes/RecherchePagesJaunes.do => à tester !!
        if( headerName.toLowerCase().equals("Set-Cookie".toLowerCase()) ) {
          ocookie.add(this.hostname, strCleanedVal, this.path);
        }

      }
      catch (MalformedHeaderValueException e) {
        e.printStackTrace(System.out);
        throw(e);
      }
    }
    else {
      throw(new MalformedHeaderNameException(headerName));
    }
  }

}

class ResponseMessageHeaderWithoutCookies extends ResponseMessageHeader {
  public ResponseMessageHeaderWithoutCookies() {}

  public ResponseMessageHeaderWithoutCookies(ByteArrayOutputStream daIn) throws MalformedHeaderException, HeaderExtraDataException {
    super(daIn);
    parse();
  }

  public void addHeader(String headerName, String headerValue) throws MalformedHeaderNameException, MalformedHeaderValueException {
    addHeader(headerName, headerValue, false);
  }

  public final void addHeader(String headerName, String headerValue, boolean merge) throws MalformedHeaderNameException, MalformedHeaderValueException {

    if( isCorrectHeaderName(headerName) ) {
      try {
        String strCleanedVal = getCleanedHeaderVal(headerValue);

        if(merge) {
          boolean isFound = false;

          // parse the existing headers
          for (Enumeration e = headers.elements(); e.hasMoreElements();) {

            String[] headerNameAndValue = (String[]) e.nextElement();

            if( headerName.toLowerCase().equals(headerNameAndValue[0].toLowerCase()) ) {

              // build the new element : add this value to the previous ones
              String[] s = new String[headerNameAndValue.length + 1];
              System.arraycopy(headerNameAndValue, 0, s, 0, headerNameAndValue.length);
              s[headerNameAndValue.length] = strCleanedVal;

              // replace the element in the vector
              this.headers.remove(headerNameAndValue);
              this.headers.add(s);
            }
          }

          if(!isFound)
            this.headers.add( new String[] {headerName, strCleanedVal} );
        }
        else {
          // just add another one in the vector
          this.headers.add(new String[] { headerName, strCleanedVal } );
        }
      }
      catch (MalformedHeaderValueException e) {
        e.printStackTrace(System.out);
        throw(e);
      }
    }
    else {
      throw(new MalformedHeaderNameException(headerName));
    }
  }


}


class RequestMessageHeaderWithCookies extends RequestMessageHeader {

  Hashtable referenceToCookies = new Hashtable();
  GenericCookie cookies;

  public RequestMessageHeaderWithCookies() { }

  public RequestMessageHeaderWithCookies(Hashtable cookz) {
    this.referenceToCookies = cookz;
  }
  public RequestMessageHeaderWithCookies(GenericCookie ocook) {
    this.cookies = ocook;
  }


  /*
   * positionne le champ hostname
   */
  public void setHostname(String hostname) {
    this.hostname = hostname;
  }
  public void setHostname(String hostname, String path) {

    // supprimer le(s) ancien(s) cookie(s)
    removeHeader("cookie");

    // on positionne le nouveau hostname
    this.hostname = hostname;

    // ajouter le(s) nouveau(x) cookie(s)
    String[] val = (String[])(cookies.get(hostname, path));

    if(val != null) {
      try {
        addHeader("Cookie", val, false);
      }
      // filtrage des exceptions inutiles
      catch(MalformedHeaderNameException e) {}
      catch(MalformedHeaderValueException e) {}
    }
  }

  /*
   * re-read the cookies
   */
  public void refreshCookies() {

    // remove old cookie(s)
    removeHeader("cookie");

    // refresh & add new cookie(s)
    String[] val = (String[])(cookies.get(hostname, RequestURI));

    if(val != null) {
      try {
        addHeader("Cookie", val, false);
      }
      // filter unusefull exceptions
      catch(MalformedHeaderNameException e) {}
      catch(MalformedHeaderValueException e) {}
    }
  } // end method

}

class RequestMessageHeaderWithoutCookies extends RequestMessageHeader {

  /*
   * positionne le champ hostname
   */
  public void setHostname(String hostname) {
    this.hostname = hostname;
  }
  public void setHostname(String hostname, String path) {
    this.hostname = hostname;
  }

  public RequestMessageHeaderWithoutCookies() {
    super();
  }

  public void refreshCookies() {}

}


abstract class GenericCookie {

  abstract void add(String key, String val, String path);
  abstract String[] get(String key, String path);

}

/*
 * cette classe implémente un cookie de version 1 (RFC 2109) et doit être serializable afin d'autoriser la sauvegarde sur fichier
 */
class AtomCookie implements Serializable {

  /* déclaration de tous les champs qui seront éventuellement sauvegardés sur fichier */
  private String cookiename = "";
  private String cookievalue = "";
  private String comment = "";
  private String domain = "";
  private String default_domain = "";
  private String maxage = "";
  private String path = "";
  private String default_path = "";
  private boolean secure;
  private int version = 1;

  /* RFU : déclaration de tous les champs à ne pas sauvegarder sur fichier */
  // private transient int example_non_serializable;

  public AtomCookie(String toBeParsed, String zhostname, String path) {

    // ces 2 paramètres sont utilisés uniquement lors des écritures
    this.default_domain = zhostname;
    this.default_path = path;

    byte[] byt = toBeParsed.getBytes();
    int i = 0;
    int AEFstate = 0;
    boolean blnError = false;

    ByteArrayOutputStream baos1 = new ByteArrayOutputStream(16);
    ByteArrayOutputStream baos2 = new ByteArrayOutputStream(16);
    ByteArrayOutputStream[] baos = new ByteArrayOutputStream[] {baos1, baos2};

    // parse the byte array
    while( (i < byt.length) && !blnError) {
      byte car = byt[i];

      switch(car) {
        case 32:  // ' '
          switch(AEFstate) {
            case 0:
              break;

            case 1:
              blnError = true;
              break;

            case 2:
              blnError = true;
              break;

            case 3: // sauvegarder dans le cookie-value
              baos[1].write(car);
              break;

            case 4: // ignorer après le ";"
              break;

            case 5:
              blnError = true;
              break;

            case 6:
              blnError = true;
              break;

            case 7: // conserver dans les values, sauf au début et à la fin (trim)
              baos[1].write(car);
              break;
          }

          break;

        case 61: // "="
          switch(AEFstate) {
            case 0:
              blnError = true;
              break;

            case 1:
              // TO DO : l'initialisation ne doit pas être faite ici !
              setCookiename(baos[0].toString());
              baos[1] = new ByteArrayOutputStream(16);
              AEFstate++;
              break;

            case 2:
              // on autorise le caractère "=" dans la valeur du cookie, y compris comme 1er caractère
              baos[1].write(car);
              AEFstate++;
              break;

            case 3:
              // on autorise le caractère "=" dans la valeur du cookie
              baos[1].write(car);
              break;

            case 4:
              blnError = true;
              break;

            case 5:
              baos[1] = new ByteArrayOutputStream(16);
              AEFstate++;
              break;

            case 6:
              blnError = true;
              break;

            case 7:
              blnError = true;
              break;
          }

          break;

        case 59: // ";"
          switch(AEFstate) {
            case 0:
              blnError = true;
              break;

            case 1:
              blnError = true;
              break;

            case 2:
              // pas de cookie value => on passe au traitement des attr-value
              setCookievalue("");
              baos[0] = new ByteArrayOutputStream(16);
              AEFstate = 4;
              break;

            case 3:
              setCookievalue(baos[1].toString());
              baos[0] = new ByteArrayOutputStream(16);
              AEFstate++;
              break;

            case 4:
              blnError = true;  // modifiable
              break;

            case 5:
              setCookieAV(baos[0].toString());  // expected match is Secure flag : "Secure"
              baos[0] = new ByteArrayOutputStream(16);
              AEFstate = 4;
              break;

            case 6:
              setCookieAV(baos[0].toString(), "");  // expected match is an attribute without value : "attr="
              baos[0] = new ByteArrayOutputStream(16);
              AEFstate = 4;
              break;

            case 7:
              setCookieAV(baos[0].toString(), baos[1].toString());  // expected match is a complete pair : "attr=value"
              baos[0] = new ByteArrayOutputStream(16);
              AEFstate = 4;  // on boucle
              break;
          }

          break;

        case 34:  // '"' ignorer le guillemet en toutes circonstances y compris dans le cookie-value
          break;

        default:
          switch(AEFstate) {
            case 0:
              baos[0].write(car);
              AEFstate++;
              break;

            case 1:
              baos[0].write(car);
              break;

            case 2:
              baos[1].write(car);
              AEFstate++;
              break;

            case 3:
              baos[1].write(car);
              break;

            case 4:
              baos[0].write(car);
              AEFstate++;
              break;

            case 5:
              baos[0].write(car);
              break;

            case 6:
              baos[1].write(car);
              AEFstate++;
              break;

            case 7:
              baos[1].write(car);
              break;
          }

          break;

      }

      i++;
    }

    // vérification de l'état final
    boolean blnError2 = false;

    if(!blnError) {
      switch(AEFstate) {
        case 3: // arrêt après le 'cookie value' proprement dit
          setCookievalue(baos[1].toString());
          break;

        case 5: // arrêt après une 1ère partie de cookie-av : est-ce "Secure" ?
          setCookieAV(baos[0].toString());
          break;

        case 6:
          setCookieAV(baos[0].toString(), "");
          break;

        case 7: // arrêt après un cookie-av complet ?
          setCookieAV(baos[0].toString(), baos[1].toString());
          break;

        default:
          blnError2 = true;
          break;
      }
    }

    // TO DO : exception si blnError || blnError2

  }

  /*
   * vérifie si 2 cookies désignent une seule et même ressource
   * 2 cookies se réfèrent à la même ressource si leurs propriétés suivantes sont identiques respectivement :
   *  cookie-name, path, domain
   */
  public boolean match(AtomCookie ac) {
    boolean rez = true;

    //if(! (this.cookiename.toLowerCase().equals(ac.getCookiename().toLowerCase())) )
    if( this.cookiename.compareTo(ac.getCookiename()) != 0)
      rez = false;

    if(!this.domain.toLowerCase().equals(ac.getDomain().toLowerCase()))
      rez = false;

    if(!this.path.toLowerCase().equals(ac.getPath().toLowerCase()))
      rez = false;

    return rez;
  }

  private void setCookiename(String s) {
    this.cookiename = s;
  }

  private void setCookievalue(String s) {
    this.cookievalue = s;
  }

  private boolean setCookieAV(String s) {
    if(s.toLowerCase().equals("secure")) {
      this.secure = true;
      return true;
    }
    else
      return false;
  }

  private boolean setCookieAV(String attr, String value) {
    boolean blnRez = false;

    if(attr.toLowerCase().equals("comment")) {
      this.comment = value;
      blnRez = true;
    }

    if(attr.toLowerCase().equals("domain")) {
      this.domain = value;
      blnRez = true;
    }

    if(attr.toLowerCase().equals("max-age")) {
      this.maxage = value;
      blnRez = true;
    }

    if(attr.toLowerCase().equals("path")) {
      this.path = value;
      blnRez = true;
    }

    if(attr.toLowerCase().equals("version")) {
      this.version = Integer.parseInt(value);
      blnRez = true;
    }

    return blnRez;
  }

  public String getCookiename() {
    return this.cookiename;
  }

  public String getCookievalue() {
    return this.cookievalue;
  }

  public boolean isSecure() {
    return this.secure;
  }

  public String getComment() {
    return this.comment;
  }

  public String getDomain() {
    return this.domain;
  }

  public String getPath() {
    return this.path;
  }

  public String getMaxage() {
    return this.maxage;
  }

  public int getVersion() {
    return this.version;
  }

  public String getDefaultDomain() {
    return this.default_domain;
  }

  public String getDefaultPath() {
    return this.default_path;
  }

  public String getMessage() {
    StringBuffer srez = new StringBuffer();

    System.err.println("AtomCookie.getMessage()");

    // la version n'est pas renvoyée : cette tâche est déléguée aux sous-classes de GenericCookie
    // rez += "Version=" + version;

    srez.append(";" + cookiename + "=\"" + cookievalue + "\"");

    return srez.toString();
  }


}

class RFC822 {

  /*
   * define the usual Regular Expressions
   */
  static final String digit = "(\\d)";
  static final String upalpha = "([A-Z])";
  static final String lowalpha = "([a-z])";
  static final String alpha = "(" + upalpha + "|" + lowalpha + ")";

  /*
   * define the complex Regular Expressions for detecting the cookie type
   */
  static final String dodigit = "(" + digit + "{2}" + ")";
  static final String ootdigit = "(" + digit + "{1,2}" + ")";
  static final String shortDay = "(" + alpha + "{3}" + ")";
  static final String longDay =  "(" + alpha + "{4,}" + ")";
  static final String month = "(" + alpha + "{3}" + ")";
  static final String shortYear = "(" + digit + "{2}" + ")";
  static final String longYear = "(" + digit + "{4}" + ")";
  static final String time = "((" + dodigit + ":){2}" + dodigit + ")";
  static final String tz = "(" + upalpha + "{3}" + ")";
  static final String dateTypeNetscape = "(" + shortDay + ", " + dodigit + "-" + month + "-" + longYear + " " + time + " GMT)";
  static final String dateTypeAbnormal1 = "(" + shortDay + ", " + dodigit + " " + month + " " + longYear + " " + time + " GMT)";
  static final String dateTypeAbnormal2 = "(" + shortDay + ", " + dodigit + "-" + month + "-" + shortYear + " " + time + " GMT)";
  static final String dateTypeJava = "(" + shortDay + " " + month + " " + dodigit + " " + time + " " + tz + " " + longYear + ")";
  static final String dateTypeJavaGMT = "(" + ootdigit + "/" + ootdigit + "/" + longYear + " " + ootdigit + ":" + ootdigit + ":" + ootdigit + ")";

  public class Date {

    private int iYear = 0;
    private int iMonth = 0;
    private int iDay = 0;
    private int iHour = 0;
    private int iMinute = 0;
    private int iSecond = 0;
    private String TZ = "";

    /*
     * constructors
     */
    public Date(String dat) throws IllegalArgumentException {

      /*
       * the netscape 'PERSISTENT CLIENT STATE HTTP COOKIES' documentation says the following
       * 'The date string is formatted as: Wdy, DD-Mon-YYYY HH:MM:SS GMT
       *  This is based on RFC 822, RFC 850, RFC 1036, and RFC 1123, with the
       *  variations that the only legal time zone is GMT and the separators between
       *  the elements of the date must be dashes.'
       * but MANY servers are not compliant to this, and use another format. Example:
       * netscape.aol.com (Wdy, DD Mon YYYY HH:MM:SS GMT)
       * es.warrants.com (Wdy, DD-Mon-YY HH:MM:SS GMT)
       *
       * For this reason, it is necessary to first detect the format, and then build the date object.
       *
       * Another problem is the java date format itself. As it is difficult to deal with all possible Locales,
       *   we construct a custom and easy format using the GregorianCalendar, with a GMT locale (cookies are themselves with GMT locale)
       */

      // 1- identify what kind of date we are dealing with
      int caseVal = -1;
      Pattern pat = Pattern.compile(dateTypeNetscape);
      Matcher mat = pat.matcher(dat);

      if(mat.matches())
        caseVal = 0;

      pat = Pattern.compile(dateTypeJava);
      mat = pat.matcher(dat);

      if(mat.matches())
        caseVal = 1;

      pat = Pattern.compile(dateTypeJavaGMT);
      mat = pat.matcher(dat);

      if(mat.matches())
        caseVal = 4;

      pat = Pattern.compile(dateTypeAbnormal1);
      mat = pat.matcher(dat);

      if(mat.matches())
        caseVal = 2;

      pat = Pattern.compile(dateTypeAbnormal2);
      mat = pat.matcher(dat);

      if(mat.matches())
        caseVal = 3;

      if(caseVal == -1) {
        // this case should never happen => throw exception to identify the cause
        throw new IllegalArgumentException("Cookie date format unexpected : " + dat);
      }
      else {

        // 2- parse the date to build our object
        switch(caseVal) {
          case 0:
            String stime = dat.substring(dat.indexOf(" ") + 1);
            this.iDay = Integer.parseInt( stime.substring(0, stime.indexOf("-")) );
            stime = stime.substring(stime.indexOf("-") + 1);
            this.iMonth = formatMonth(stime.substring(0, stime.indexOf("-") ));
            stime = stime.substring(stime.indexOf("-") + 1);
            this.iYear = Integer.parseInt(stime.substring(0, stime.indexOf(" ")) );
            stime = stime.substring(stime.indexOf(" ") + 1);
            this.iHour = Integer.parseInt(stime.substring(0, stime.indexOf(":")));
            stime = stime.substring(stime.indexOf(":") + 1);
            this.iMinute = Integer.parseInt(stime.substring(0, stime.indexOf(":")));
            stime = stime.substring(stime.indexOf(":") + 1);
            this.iSecond = Integer.parseInt(stime.substring(0, stime.indexOf(" ")));
            //TO DO : TZ
            break;

          case 1:
            this.iMonth = formatMonth(dat.substring(dat.indexOf(" ") + 1, dat.indexOf(" ") + 4));
            stime = dat.substring(dat.indexOf(" ") + 5);
            this.iDay = Integer.parseInt( stime.substring(0, stime.indexOf(" ")) );
            stime = stime.substring(stime.indexOf(" ") + 1);
            this.iHour = Integer.parseInt(stime.substring(0, stime.indexOf(":")));
            stime = stime.substring(stime.indexOf(":") + 1);
            this.iMinute = Integer.parseInt(stime.substring(0, stime.indexOf(":")));
            stime = stime.substring(stime.indexOf(":") + 1);
            this.iSecond = Integer.parseInt(stime.substring(0, stime.indexOf(" ")));
            stime = stime.substring(stime.indexOf(" ") + 1);
            this.TZ = stime.substring(0, stime.indexOf(" "));
            this.iYear = Integer.parseInt(stime.substring(stime.lastIndexOf(" ") + 1));
            break;

          case 2:
            stime = dat.substring(dat.indexOf(" ") + 1);
            this.iDay = Integer.parseInt( stime.substring(0, stime.indexOf(" ")) );
            stime = stime.substring(stime.indexOf(" ") + 1);
            this.iMonth = formatMonth(stime.substring(0, stime.indexOf(" ") ));
            stime = stime.substring(stime.indexOf(" ") + 1);
            this.iYear = Integer.parseInt(stime.substring(0, stime.indexOf(" ")) );
            stime = stime.substring(stime.indexOf(" ") + 1);
            this.iHour = Integer.parseInt(stime.substring(0, stime.indexOf(":")));
            stime = stime.substring(stime.indexOf(":") + 1);
            this.iMinute = Integer.parseInt(stime.substring(0, stime.indexOf(":")));
            stime = stime.substring(stime.indexOf(":") + 1);
            this.iSecond = Integer.parseInt(stime.substring(0, stime.indexOf(" ")));
            //TO DO : TZ
            break;

          case 3:
            stime = dat.substring(dat.indexOf(" ") + 1);
            this.iDay = Integer.parseInt( stime.substring(0, stime.indexOf("-")) );
            stime = stime.substring(stime.indexOf("-") + 1);
            this.iMonth = formatMonth(stime.substring(0, stime.indexOf("-") ));
            stime = stime.substring(stime.indexOf("-") + 1);
            String stmp = "20" + stime.substring(0, stime.indexOf(" "));
            this.iYear = Integer.parseInt(stmp);
            //this.iYear = Integer.parseInt(stime.substring(0, stime.indexOf(" ")) );
            stime = stime.substring(stime.indexOf(" ") + 1);
            this.iHour = Integer.parseInt(stime.substring(0, stime.indexOf(":")));
            stime = stime.substring(stime.indexOf(":") + 1);
            this.iMinute = Integer.parseInt(stime.substring(0, stime.indexOf(":")));
            stime = stime.substring(stime.indexOf(":") + 1);
            this.iSecond = Integer.parseInt(stime.substring(0, stime.indexOf(" ")));
            //TO DO : TZ
            break;

          case 4:
            stime = dat;
            this.iDay = Integer.parseInt(stime.substring(0, stime.indexOf("/")));
            stime = stime.substring(stime.indexOf("/") + 1);
            this.iMonth = Integer.parseInt(stime.substring(0, stime.indexOf("/")));
            stime = stime.substring(stime.indexOf("/") + 1);
            this.iYear = Integer.parseInt(stime.substring(0, stime.indexOf(" ")));
            stime = stime.substring(stime.indexOf(" ") + 1);
            this.iHour = Integer.parseInt(stime.substring(0, stime.indexOf(":")));
            stime = stime.substring(stime.indexOf(":") + 1);
            this.iMinute = Integer.parseInt(stime.substring(0, stime.indexOf(":")));
            stime = stime.substring(stime.indexOf(":") + 1);
            this.iSecond = Integer.parseInt(stime.substring(0));
            break;

          default:
            // this can't be reached since we throwed the exception earlier
            break;
        } // end switch
      } // end else
    }

    /*
     * compares this date with another one
     *
     * @return integer
     *  the value 0 if the argument Date is equal to this Date
     *  a value less than 0 if this Date is before the Date argument
     *  and a value greater than 0 if this Date is after the Date argument
     */
    public int compareTo(Date date2) {
      int blnRez = 0;
      // TO DO : calcul de la nouvelle date en fonction de sa timezone

      Integer itmp1 = new Integer(this.iYear);
      Integer itmp2 = new Integer(date2.iYear);

      // compare years
      int rez1 = itmp1.compareTo(itmp2);

      if(rez1 != 0)
        blnRez = rez1;  // years different => finished
      else { // same year,..

        // compare months
        itmp1 = new Integer(this.iMonth);
        itmp2 = new Integer(date2.iMonth);
        int rez2 = itmp1.compareTo(itmp2);

        if(rez2 != 0)
          blnRez = rez2;  // months different => finished
        else {  // same months,..

          // compare days
          itmp1 = new Integer(this.iDay);
          itmp2 = new Integer(date2.iDay);
          int rez3 = itmp1.compareTo(itmp2);

          if(rez3 != 0)
            blnRez = rez3;  // days different => finished
          else {// same days,..

            // compare hours
            itmp1 = new Integer(this.iHour);
            itmp2 = new Integer(date2.iHour);
            int rez4 = itmp1.compareTo(itmp2);

            if(rez4 != 0)
              blnRez = rez4;  // hours different => finished
            else {  // same hours,..

              // compare minutes
              itmp1 = new Integer(this.iMinute);
              itmp2 = new Integer(date2.iMinute);
              int rez5 = itmp1.compareTo(itmp2);

              if(rez5 != 0)
                blnRez = rez5;  // minutes different => finished
              else {  // same minutes,..

                // compare seconds
                itmp1 = new Integer(this.iSecond);
                itmp2 = new Integer(date2.iSecond);
                int rez6 = itmp1.compareTo(itmp2);

                blnRez = rez6;  // finished, difference was calculated on the seconds
              }
            }
          }
        }

      }

      return blnRez;
    }

    /*
     * formats the month given as string into integer
     * ex : "Mar" returns 3, "Dec" returns 12
     */
    private int formatMonth(String s) {
      int iRez = 0;

      if(s.toLowerCase().equals("jan"))
        iRez = 1;

      if(s.toLowerCase().equals("feb"))
        iRez = 2;

      if(s.toLowerCase().equals("mar"))
        iRez = 3;

      if(s.toLowerCase().equals("apr"))
        iRez = 4;

      if(s.toLowerCase().equals("may"))
        iRez = 5;

      if(s.toLowerCase().equals("jun"))
        iRez = 6;

      if(s.toLowerCase().equals("jul"))
        iRez = 7;

      if(s.toLowerCase().equals("aug"))
        iRez = 8;

      if(s.toLowerCase().equals("sep"))
        iRez = 9;

      if(s.toLowerCase().equals("oct"))
        iRez = 10;

      if(s.toLowerCase().equals("nov"))
        iRez = 11;

      if(s.toLowerCase().equals("dec"))
        iRez = 12;

      return iRez;
    }

  }
}


/*
 *
 */
abstract class HTMLStamps {

  //
  public int offset = 0;

  // remet le compteur à 0, utile par exemple pour les Keep-Alive
  public final void initialise() {
    offset = 0;
  }

  public abstract void avoidDNS();

  public abstract void avoidInit();

  public abstract void log(String s);

  public abstract void log(String s, String t);

  public final void log(long l) {
    log(Long.toString(l));
  }

  public final void log(long l, String s) {
    log(Long.toString(l), s);
  }

}

class HTMLStamps1 extends HTMLStamps {

  public void avoidInit() {}

  public void avoidDNS() {}

  public void log(String s, String t) {
    log(s);
  }

  public void log(String s) {

    // mise à jour du compteur
    int j;

    synchronized(this) {
      if(offset == 3)
        offset = 0;

      j = offset++;
    }

    // évaluation du message à logger
    String prefix = "";
    String suffix = " mS";

    switch(j) {
      case 0:
        prefix = "htmlstamp-sendrequest ";
        break;

      case 1:
        prefix = "htmlstamp-readheader ";
        break;

      case 2:
        prefix = "htmlstamp-readbody ";
        break;

      default:
        // NO DEFAULT CASE
        break;
    }

    // log it !
    System.err.println(prefix + s + suffix);
  }

}

class NETStamps1 extends HTMLStamps {

  public void avoidInit() {
    offset = 1;
  }

  public void avoidDNS() {}

  public void log(String s, String t) {
    log(s);
  }

  public void log(String s) {

    // mise à jour du compteur
    int j;

    synchronized(this) {
      if(offset == 3)
        offset = 0;

      j = offset++;
    }

    // évaluation du message à logger
    String prefix = "";
    String suffix = " mS";

    switch(j) {
      case 0:
        prefix = "netstamp-init ";
        break;

      case 1:
        prefix = "netstamp-1st byte ";
        break;

      case 2:
        prefix = "netstamp-readbody ";
        break;

      default:
        // NO DEFAULT CASE
        break;
    }

    // log it !
    System.err.println(prefix + s + suffix);
  }
}

class NETStamps1_DNS extends HTMLStamps {

  private final static String suffix = " mS";

  public void avoidInit() {
    offset = 2;
  }

  public void avoidDNS() {
    offset = 1;
  }

  private String calculatePrefix() {
    // mise à jour du compteur
    int j;

    synchronized(this) {
      if(offset == 4)
        offset = 0;

      j = offset++;
    }

    // évaluation du message à logger
    String prefix = "";

    switch(j) {
      case 0:
        prefix = "netstamp-DNS ";
        break;

      case 1:
        prefix = "netstamp-init ";
        break;

      case 2:
        prefix = "netstamp-1st byte ";
        break;

      case 3:
        prefix = "netstamp-readbody ";
        break;

      default:
        // NO DEFAULT CASE
        break;
    }

    return prefix;
  }

  public void log(String s) {
    // log it !
    System.err.println(calculatePrefix() + s + suffix);
  }

  public void log(String s, String ipv4) {
    // log it !
    System.err.println( calculatePrefix() + s + suffix + " (" + ipv4 + ")" );
  }

}

class NETStamps2 extends HTMLStamps {

  public void avoidInit() {
    offset = 2;
  }

  public void avoidDNS() {}

  public void log(String s, String t) {
    log(s);
  }

  public void log(String s) {

    // mise à jour du compteur
    int j;

    synchronized(this) {
      if(offset == 4)
        offset = 0;

      j = offset++;
    }

    // évaluation du message à logger
    String prefix = "";
    String suffix = " mS";

    switch(j) {
      case 0:
        prefix = "netstamp-init ";
        break;

      case 1:
        prefix = "netstamp-ssl handshake";
        break;

      case 2:
        prefix = "netstamp-1st byte ";
        break;

      case 3:
        prefix = "netstamp-readbody ";
        break;

      default:
        // NO DEFAULT CASE
        break;
    }

    // log it !
    System.err.println(prefix + s + suffix);
  }
}

class NETStamps2_DNS extends HTMLStamps {

  private final static String suffix = " mS";

  public void avoidInit() {
    offset = 3;
  }

  public void avoidDNS() {
    offset = 2;
  }

  private String calculatePrefix() {

    // mise à jour du compteur
    int j;

    synchronized(this) {
      if(offset == 5)
        offset = 0;

      j = offset++;
    }

    // évaluation du message à logger
    String prefix = "";

    switch(j) {
      case 0:
        prefix = "netstamp-DNS ";
        break;

      case 1:
        prefix = "netstamp-init ";
        break;

      case 2:
        prefix = "netstamp-ssl handshake";
        break;

      case 3:
        prefix = "netstamp-1st byte ";
        break;

      case 4:
        prefix = "netstamp-readbody ";
        break;

      default:
        // NO DEFAULT CASE
        break;
    }

    return prefix;
  }

  public void log(String s) {
    // log it !
    System.err.println(calculatePrefix() + s + suffix);
  }

  public void log(String s, String ipv4) {
    // log it !
    System.err.println( calculatePrefix() + s + suffix + " (" + ipv4 + ")" );
  }

}

class NETStamps3 extends HTMLStamps {

  public void avoidInit() {
    offset = 3;
  }

  public void avoidDNS() {}

  public void log(String s, String t) {
    log(s);
  }

  public void log(String s) {

    // mise à jour du compteur
    int j;

    synchronized(this) {
      if(offset == 5)
        offset = 0;

      j = offset++;
    }

    // évaluation du message à logger
    String prefix = "";
    String suffix = " mS";

    switch(j) {
      case 0:
        prefix = "netstamp-init proxy";
        break;

      case 1:
        prefix = "netstamp-init final server";
        break;

      case 2:
        prefix = "netstamp-ssl handshake ";
        break;

      case 3:
        prefix = "netstamp-1st byte ";
        break;

      case 4:
        prefix = "netstamp-readbody ";
        break;

      default:
        // NO DEFAULT CASE
        break;
    }

    // log it !
    System.err.println(prefix + s + suffix);
  }

}

class NETStamps3_DNS extends HTMLStamps {

  private final static String suffix = " mS";

  public void avoidInit() {
    offset = 4;
  }

  public void avoidDNS() {
    offset = 3;
  }

  private String calculatePrefix() {

    // mise à jour du compteur
    int j;

    synchronized(this) {
      if(offset == 6)
        offset = 0;

      j = offset++;
    }

    // évaluation du message à logger
    String prefix = "";

    switch(j) {
      case 0:
        prefix = "netstamp-DNS";
        break;

      case 1:
        prefix = "netstamp-init proxy";
        break;

      case 2:
        prefix = "netstamp-init final server";
        break;

      case 3:
        prefix = "netstamp-ssl handshake ";
        break;

      case 4:
        prefix = "netstamp-1st byte ";
        break;

      case 5:
        prefix = "netstamp-readbody ";
        break;

      default:
        // NO DEFAULT CASE
        break;
    }

    return prefix;
  }

  public void log(String s) {
    // log it !
    System.err.println(calculatePrefix() + s + suffix);
  }

  public void log(String s, String ipv4) {
    // log it !
    System.err.println( calculatePrefix() + s + suffix + " (" + ipv4 + ")" );
  }

}

/*
 * implements certificate utilities.
 * instead of using static methods, a next version could extend X509Certificate if necessary
 */
class CertificateUtil {

  /*
   * exports a X509Certificate to a file, in PEM format (ASN.1 DER format, encoded in Base 64)
   *
   * @param X509Certificate the certificate to export
   * @param String the file name which will contain the certificate
   * @return boolean indicates if the operation ended correctly
   */
  public static boolean exportToFile(X509Certificate cert, String filename) {
    boolean blnResult = true;

    try {
      byte[] buf = cert.getEncoded();

      Writer wr = null;

      try {
        File file = new File(filename);
        FileOutputStream fos = new FileOutputStream(file);
        wr = new OutputStreamWriter(fos, Charset.forName("UTF-8"));
        wr.write("-----BEGIN CERTIFICATE-----" + System.getProperty("line.separator"));
        wr.write(Base64.encodeBytes(buf));
        wr.write("\n-----END CERTIFICATE-----" + System.getProperty("line.separator"));
        wr.flush();
      }
      catch(java.io.IOException ioe) {
        System.err.println(ioe);
        blnResult = false;
      }
      finally {
        try {
          if(wr != null)
            wr.close();
        }
        catch(IOException ioe) {
          System.err.println(ioe);
          blnResult = false;
        }
      } // end finally block
    }
    catch(CertificateEncodingException cee) {
      // should never happen, but print it for debug
      System.err.println(cee);
      blnResult = false;
    }

    return blnResult;
  } // end exportToFile

} // end class

/*
 * ReqMessageHeader implements the header part of a HTTP request
 */
class ReqMessageHeader extends MessageHeader {

  private String Method = "";
  protected String RequestURI = "";
  private String HTTPVersion = "";
  String hostname = "";
  private String port = "";

  /*
   * constructeur par défaut
   */
  public ReqMessageHeader() { }

  /*
   * constructeur à partir d'une String => voir la classe mère
   */
  public ReqMessageHeader(String str) {

    try {

      // 1- définition du start-line
      String sLine = str.substring(0, str.indexOf(RFCUtil.CRLF));
      setStartLine(sLine);

      // 2- définition et ajout des headers
      if(sLine.length() < str.length()) {
        addHeaders(str.substring(str.indexOf(RFCUtil.CRLF) + 2));
      }
    }
    catch(MalformedHeaderException e) {
      System.err.println(e);
    }
  }

  /*
   * adds a header, by default we add it to the existing one
   */
  public final void addHeader(String headerName, String headerValue) throws MalformedHeaderNameException, MalformedHeaderValueException {
    addHeader(headerName, headerValue, true);
  }

  /*
   * adds a header
   * sometimes we don't want to merge the values in the same request line, we use merge boolean for this
   */
  public final void addHeader(String headerName, String headerValue, boolean merge) throws MalformedHeaderNameException, MalformedHeaderValueException {

    if( isCorrectHeaderName(headerName) ) {
      try {
        String strCleanedVal = getCleanedHeaderVal(headerValue);

        if(merge) {
          boolean isFound = false;

          // parse the existing headers
          for (Enumeration e = headers.elements(); e.hasMoreElements();) {

            String[] headerNameAndValue = (String[]) e.nextElement();

            if( headerName.toLowerCase().equals(headerNameAndValue[0].toLowerCase()) ) {

              // build the new element : add this value to the previous ones
              String[] s = new String[headerNameAndValue.length + 1];
              System.arraycopy(headerNameAndValue, 0, s, 0, headerNameAndValue.length);
              s[headerNameAndValue.length] = strCleanedVal;

              // replace the element in the vector
              isFound = true;
              this.headers.remove(headerNameAndValue);
              this.headers.add(s);
            }
          }

          if(!isFound)
            this.headers.add( new String[] {headerName, strCleanedVal} );
        }
        else {
          // just add another one in the vector
          this.headers.add(new String[] { headerName, strCleanedVal } );
        }
      }
      catch (MalformedHeaderValueException e) {
        e.printStackTrace(System.out);
        throw(e);
      }
    }
    else {
      throw(new MalformedHeaderNameException(headerName));
    }
  }

  /*
   * sets a header
   * of course this method has only meaning for requests
   */
  public final void setHeader(String headerName, String headerValue, boolean toclean) throws MalformedHeaderNameException, MalformedHeaderValueException {

    // vérification du headerValue
    String strCleanedVal = (toclean) ? getCleanedHeaderVal(headerValue) : headerValue;

    boolean isFound = false;

    // parse the existing headers
    for (Enumeration e = headers.elements(); e.hasMoreElements();) {

      String[] headerNameAndValue = (String[]) e.nextElement();

      if( headerName.toLowerCase().equals(headerNameAndValue[0].toLowerCase()) ) {
        isFound = true;

        // build the new element
        String[] s = new String[] {headerName, strCleanedVal};

        // replace the element in the vector
        this.headers.remove(headerNameAndValue);
        this.headers.add(s);
      }
    }

    if(!isFound)
      addHeader(headerName, strCleanedVal);
  }

  /*
   * positionne le champ Method
   */
  public final void setMethod(String method) throws InvalidMethodException {
    boolean blnRez = false;

    if(RFCUtil.isCorrectMethod(method)) {
      Method = method;
    }
    else
      throw new InvalidMethodException();
  }

  /*
   * positionne le champ Request-URI
   */
  public final void setRequestURI(String uri) throws InvalidRequestURIException {

    if(RFCUtil.isCorrectRequestURI(uri)) {

      // TO DO : encodage de l'URL au format UTF-8
      //RequestURI = URLEncoder.encode(uri, "UTF-8");
      RequestURI = uri;
    }
    else
      throw new InvalidRequestURIException();

  }

  /*
   * positionne le champ HTTP-Version
   */
  public final void setHTTPVersion(String version) throws InvalidHTTPVersionException {

    if(RFCUtil.isCorrectHTTPVersion(version))
      HTTPVersion = version;
    else
      throw(new InvalidHTTPVersionException());
  }


  /*
   * positionne le champ port
   */
  public final void setPort(String port) {
    this.port = port;
  }

  public final void setHostname(String s) {
    this.hostname = s;
  }

  public final String getHostname() {
    return hostname;
  }

  public final String getPort() {
    return port;
  }

  public final String getMethod() {
    return Method;
  }

  public final String getRequestURI() {
    return RequestURI;
  }
  public final String getHTTPVersion() {
    return HTTPVersion;
  }

  /*
   * retourne la 1ère ligne du message : pour une request ce sera la request-line
   */
  public final String getStartLine() {
    return(getRequestLine());
  }
  public final String getStartLine(boolean absoluteURI) {
    return(getRequestLine(absoluteURI));
  }

  /*
   * positionne la 1ère ligne du message : pour une request il s'agit de request-line
   */
  public final void setStartLine(String sLine) throws MalformedHeaderException {
    String[] parts = sLine.split("\\s");

    try {
      setMethod(parts[0]);
      setHTTPVersion(parts[2]);
      setRequestURI(parts[1]);
    }
    catch(InvalidMethodException e) {
      throw (MalformedHeaderException)e;
    }
    catch(InvalidHTTPVersionException e) {
      throw (MalformedHeaderException)e;
    }
    catch(InvalidRequestURIException e) {
      throw (MalformedHeaderException)e;
    }
  }

  /*
   * retourne la request-line (définie à RFC2616 §5.1)
   */
  // cas par défaut : Request-URI sous la forme de abs_path
  private final String getRequestLine() {
    return(Method.concat(RFCUtil.SP).concat(RequestURI).concat(RFCUtil.SP).concat(HTTPVersion).concat(RFCUtil.CRLF));
  }
  // cas où l'on distingue le format de la request-line
  private final String getRequestLine(boolean absoluteURI) {
    if(!absoluteURI)
      return(Method.concat(RFCUtil.SP).concat(RequestURI).concat(RFCUtil.SP).concat(HTTPVersion).concat(RFCUtil.CRLF));
    else
      return(Method.concat(RFCUtil.SP).concat("http://").concat(hostname).concat(":").concat(port).concat(RequestURI).concat(RFCUtil.SP).concat(HTTPVersion).concat(RFCUtil.CRLF));
  }

  /*
   * indique si le client demande la fermeture de la connexion
   */
  public final boolean connMustBeClosed() {
    boolean rez = false;

    if(getHTTPVersion().equals("HTTP/1.1")) {
      try {
        if(hasHeaderValue("connection", "close"))
          rez = true;
      }
      catch(UndefinedHeaderException uhe) {}

      try {
        if(hasHeaderValue("proxy-connection", "close"))
          rez = true;
      }
      catch(UndefinedHeaderException uhe) {}
    }
    else
      rez = true;

    return rez;
  }

}

class ResMessageHeader extends MessageHeader {
  private String HTTPVersion = "";
  private String StatusCode = "";
  private String ReasonPhrase = "";

  protected byte[] daByte;

  public ResMessageHeader() {
  }

  public ResMessageHeader(ByteArrayOutputStream daIn) throws MalformedHeaderException, HeaderExtraDataException {
    daByte = daIn.toByteArray();
    parse();
  }

  public final void parse() throws MalformedHeaderException, HeaderExtraDataException {
    int AEFstate = 0;
    int i = 0, car = 0;
    boolean blnError = false;

    // we need 2 buffers maximum
    ByteArrayOutputStream[] baos = new ByteArrayOutputStream[] {new ByteArrayOutputStream(16), new ByteArrayOutputStream(16)};

    // parse the credentials
    while( (i < daByte.length) && !blnError) {

      car = daByte[i];

      // TO DO : case 4 (reason phrase cas normal, ou bien un jump si CRLF est détecté)

      switch(car) {

        case 10:  // LF
          switch(AEFstate) {
            case 6: // step_10
              baos[0] = new ByteArrayOutputStream(16);
              baos[1] = new ByteArrayOutputStream(16);
              AEFstate++;
              break;

            case 12:
              AEFstate++;
              break;

            case 15:  // final_2 reached !!
              AEFstate++;
              break;

            case 17:  // final_1 reached !!
              AEFstate++;
              break;

            default:
              blnError = true;
              break;
          }

          break;

        case 13:  // CR
          switch(AEFstate) {
            case 3:
              try {
                setStatusCode(baos[1].toString());
              }
              catch(InvalidStatusCodeException e) {
                throw (MalformedHeaderException)e;
              }

              AEFstate = 6;
              break;

            case 4:
              try {
                setStatusCode(baos[1].toString());
              }
              catch(InvalidStatusCodeException e) {
                throw (MalformedHeaderException)e;
              }

              AEFstate = 6;
              break;

            case 5: // step_9 : end of first line
              try {
                setReasonPhrase(baos[0].toString());
              }
              catch(InvalidReasonPhraseException e) {
                throw (MalformedHeaderException)e;
              }

              AEFstate++;
              break;

            case 7: // jump to final_1
              AEFstate = 17;
              break;

            case 9:
              AEFstate = 12;
              break;

            case 10:
              AEFstate = 12;
              break;

            case 11:
              AEFstate++;
              break;

            case 13:
              try {
                addHeader(baos[0].toString(), baos[1].toString());
              }
              catch(MalformedHeaderNameException e) {
                throw( (MalformedHeaderException) e);
              }
              catch(MalformedHeaderValueException e) {
                throw( (MalformedHeaderException) e);
              }

              AEFstate = 15;
              break;

            case 14:
              AEFstate = 12;
              break;

            default:
              blnError = true;
              break;
          }

          break;

        case 32:  // SP
          switch(AEFstate) {
            case 1: // step_3 : HTTP Version finished
              try {
                setHTTPVersion(baos[0].toString());
              }
              catch(InvalidHTTPVersionException e) {
                throw (MalformedHeaderException)e;
              }

              AEFstate++;
              break;

            case 3: // step_6 : HTTP Version finished
              try {
                setStatusCode(baos[1].toString());
                baos[0] = new ByteArrayOutputStream(16);
              }
              catch(InvalidStatusCodeException e) {
                throw (MalformedHeaderException)e;
              }

              AEFstate++;
              break;

            case 4: // SP allowed when starting reason phrase
              baos[0].write(car);
              AEFstate++;
              break;

            case 5: // SP allowed in the reason phrase of course
              baos[0].write(car);
              break;

            case 9: // step_14
              AEFstate++;
              break;

            case 10:
              baos[1].write(car);
              AEFstate++;
              break;

            case 11:
              baos[1].write(car);
              break;

            case 13:
              AEFstate++;
              break;

            default:
              blnError = true;
              break;
          }

          break;

        case 9:  // HT
          switch(AEFstate) {
            case 13:
              AEFstate++;
              break;

            default:
              blnError = true;
              break;
          }

          break;

        case 58:  // ":" séparateur des headers
          switch(AEFstate) {
            case 8: // step_13
              AEFstate++;
              break;

            case 11:
              baos[1].write(car);
              break;

            default:
              blnError = true;
              break;
          }

          break;

        default:  // char
          switch(AEFstate) {
            case 0: // step_1 : start the HTTP Version
              baos[0].write(car);
              AEFstate++;
              break;

            case 1: // step_2 : complete the HTTP Version
              baos[0].write(car);
              break;

            case 2: // step_4 : start the Status Code
              baos[1].write(car);
              AEFstate++;
              break;

            case 3: // step_5 : complete the Status Code
              baos[1].write(car);
              break;

            case 4: // step_7 : start the Reason Phrase
              baos[0].write(car);
              AEFstate++;
              break;

            case 5: // step_8 : complete the Reason Phrase
              baos[0].write(car);
              break;

            case 7: // step_11 : start header-name
              baos[0].write(car);
              AEFstate++;
              break;

            case 8: // step_12 : complete header-name
              baos[0].write(car);
              break;

            case 10: // step_15 : start header-value
              baos[1].write(car);
              AEFstate++;
              break;

            case 11: // step_16 : complete header-value
              baos[1].write(car);
              break;

            case 13:
              try {
                addHeader(baos[0].toString(), baos[1].toString());
              }
              catch(MalformedHeaderNameException e) {
                throw( (MalformedHeaderException) e);
              }
              catch(MalformedHeaderValueException e) {
                throw( (MalformedHeaderException) e);
              }

              baos[0] = new ByteArrayOutputStream(16);
              baos[0].write(car);
              baos[1] = new ByteArrayOutputStream(16);
              AEFstate = 8;
              break;

            case 14:
              baos[1].write(car);
              AEFstate = 11;
              break;

            default:
              blnError = true;
              break;
          }

          break;
      }

      //DEBUG System.err.println(daByte[i]);
      i++;
    } // end while

    // check if parsing was finished cleanly
    boolean blnJobOK = ( AEFstate == 16 || AEFstate == 18 );

    if(!blnJobOK)
      //System.err.println("header parsing failed, returning with code: " + AEFstate + " " + baos[0].toString() + "," + baos[1].toString());
      throw new MalformedHeaderException("header parsing failed, returning with code: " + AEFstate);

  } // end parse



  /*
   * adds a header, by default we add it to the existing one
   */
  public final void addHeader(String headerName, String headerValue) throws MalformedHeaderNameException, MalformedHeaderValueException {
    addHeader(headerName, headerValue, true);
  }

  /*
   * adds a header
   * sometimes we don't want to merge the values in the same request line, we use merge boolean for this
   */
  public final void addHeader(String headerName, String headerValue, boolean merge) throws MalformedHeaderNameException, MalformedHeaderValueException {

    if( isCorrectHeaderName(headerName) ) {
      try {
        String strCleanedVal = getCleanedHeaderVal(headerValue);

        if(merge) {
          boolean isFound = false;

          // parse the existing headers
          for (Enumeration e = headers.elements(); e.hasMoreElements();) {

            String[] headerNameAndValue = (String[]) e.nextElement();

            if( headerName.toLowerCase().equals(headerNameAndValue[0].toLowerCase()) ) {

              // build the new element : add this value to the previous ones
              String[] s = new String[headerNameAndValue.length + 1];
              System.arraycopy(headerNameAndValue, 0, s, 0, headerNameAndValue.length);
              s[headerNameAndValue.length] = strCleanedVal;

              // replace the element in the vector
              isFound = true;
              this.headers.remove(headerNameAndValue);
              this.headers.add(s);
            }
          }

          if(!isFound)
            this.headers.add( new String[] {headerName, strCleanedVal} );
        }
        else {
          // just add another one in the vector
          this.headers.add(new String[] { headerName, strCleanedVal } );
        }
      }
      catch (MalformedHeaderValueException e) {
        e.printStackTrace(System.out);
        throw(e);
      }
    }
    else {
      throw(new MalformedHeaderNameException(headerName));
    }
  }

  public final void setHTTPVersion(String version) throws InvalidHTTPVersionException {
    //System.out.print(version + " ");

    if(RFCUtil.isCorrectHTTPVersion(version))
      HTTPVersion = version;
    else
      throw(new InvalidHTTPVersionException());
  }

  public final void setStatusCode(String status) throws InvalidStatusCodeException {
//    System.out.print(status + " ");

    if(RFCUtil.isCorrectStatusCode(status))
      StatusCode = status;
    else
      throw(new InvalidStatusCodeException());
  }

  public final void setReasonPhrase(String reason) throws InvalidReasonPhraseException {
//    System.err.println(reason);

    if(RFCUtil.isCorrectReasonPhrase(reason))
      ReasonPhrase = reason;
    else
      throw(new InvalidReasonPhraseException());
  }

  public void debug() {
    //System.err.println(HTTPVersion + ", " + StatusCode + ", " + ReasonPhrase);
    System.err.println("HTTPVersion: " + HTTPVersion);
    System.err.println("StatusCode: " + StatusCode);
    System.err.println("ReasonPhrase: " + ReasonPhrase);
  }

  public final String getStartLine() {
    return(getStatusLine());
  }
  public final String getStartLine(boolean b) {
    return(getStatusLine());
  }

  private final String getStatusLine() {
    return(HTTPVersion.concat(RFCUtil.SP).concat(StatusCode).concat(RFCUtil.SP).concat(ReasonPhrase).concat(RFCUtil.CRLF));
  }
  public final String getHTTPVersion() {
    return HTTPVersion;
  }

  public final String getStatusCode() {
    return(StatusCode);
  }


  public final String getReasonPhrase() {
    return(ReasonPhrase);
  }


  public final boolean connMustBeClosed() {
    // Keep-Alive par défaut en 1.1 et Close pour 0.9 et 1.0
    boolean rez = false;

    if(getHTTPVersion().equals("HTTP/1.1")) {
      // liste des cas 1.1 où il faut fermer la socket
      try {
        if(hasHeaderValue("connection", "close"))
          rez = true;
      }
      catch(UndefinedHeaderException uhe) {}

      try {
        if(hasHeaderValue("proxy-connection", "close"))
          rez = true;
      }
      catch(UndefinedHeaderException uhe) {}
    }
    else {
      rez = true;
    }

    return rez;
  }

}

/*
 * implements an object giving information about a transaction scenario result (HTTPTransaction.runScenario())
 */
class ScenarioResult {
  private boolean keepalive;
  private GenericCookie cookies;
  private Vector<RawCookieNetscape> vNetscape = new Vector<RawCookieNetscape>();
  private Vector<RawCookieV1> vV1 = new Vector<RawCookieV1>();

  /* constructor */
  public ScenarioResult(boolean keepalive, String[] headers) {
    this.keepalive = keepalive;

    for(String header : headers) {
      try {
        addElement(RawCookieFactory.create(header));
      }
      catch(MalformedCookieException mce) {
        System.err.println(mce);
      }
    }
  }

  /* accessors */
  public boolean getKeepAlive() {
    return keepalive;
  }

  public Vector<RawCookieNetscape> getCookieNetscape() {
    return vNetscape;
  }
  public Vector<RawCookieV1> getCookieV1() {
    return vV1;
  }

  public GenericCookie getCookies() {
    return cookies;
  }

  /*
   * the factory method does not allow us to automatically detect the object types
   */
  private void addElement(RawCookie rc) {
    if ( (new RawCookieNetscape()).getClass() == rc.getClass() )
      addElement((RawCookieNetscape)rc);

    if ( (new RawCookieV1()).getClass() == rc.getClass() )
      addElement((RawCookieV1)rc);
  }

  private void addElement(RawCookieNetscape rcn) {
    vNetscape.addElement(rcn);
  }

  private void addElement(RawCookieV1 rcv) {
    vV1.addElement(rcv);
  }

}

/*
 * implements a netscape cookie from a given Set-Cookie header
 * it doesn't give any information about the hostname/path which will be provided in the subclass
 * each object will be created from the Factory Method 'RawCookieFactory'
 */
class RawCookieNetscape extends RawCookie implements Serializable {

  /* déclaration de tous les champs qui seront éventuellement sauvegardés sur fichier */
  private String cookiename = "";
  private String cookievalue = "";
  private String domain = "";
  private String expires = "";
  private String path = "";
  private boolean secure;

  /* RFU : déclaration de tous les champs à ne pas sauvegarder sur fichier */
  // private transient int example_non_serializable;

  public RawCookieNetscape() {}

  public RawCookieNetscape(String headerVal) {

    byte[] byt = headerVal.getBytes();
    int i = 0;
    int AEFstate = 0;
    boolean blnError = false;

    ByteArrayOutputStream baos1 = new ByteArrayOutputStream(16);
    ByteArrayOutputStream baos2 = new ByteArrayOutputStream(16);
    ByteArrayOutputStream[] baos = new ByteArrayOutputStream[] {baos1, baos2};

    // parse the byte array
    while( (i < byt.length) && !blnError) {
      byte car = byt[i];

      switch(car) {
        case 32:  // ' '
          switch(AEFstate) {
            case 0:
              break;

            case 1:
              blnError = true;
              break;

            case 2:
              blnError = true;
              break;

            case 3: // sauvegarder dans le cookie-value
              baos[1].write(car);
              break;

            case 4: // ignorer après le ";"
              break;

            case 5:
              blnError = true;
              break;

            case 6:
              blnError = true;
              break;

            case 7: // conserver dans les values, sauf au début et à la fin (trim)
              baos[1].write(car);
              break;
          }

          break;

        case 61: // "="
          switch(AEFstate) {
            case 0:
              blnError = true;
              break;

            case 1:
              // TO DO : l'initialisation ne doit pas être faite ici !
              setCookiename(baos[0].toString());
              baos[1] = new ByteArrayOutputStream(16);
              AEFstate++;
              break;

            case 2:
              // on autorise le caractère "=" dans la valeur du cookie, y compris comme 1er caractère
              baos[1].write(car);
              AEFstate++;
              break;

            case 3:
              // on autorise le caractère "=" dans la valeur du cookie
              baos[1].write(car);
              break;

            case 4:
              blnError = true;
              break;

            case 5:
              baos[1] = new ByteArrayOutputStream(16);
              AEFstate++;
              break;

            case 6:
              blnError = true;
              break;

            case 7:
              blnError = true;
              break;
          }

          break;

        case 59: // ";"
          switch(AEFstate) {
            case 0:
              blnError = true;
              break;

            case 1:
              blnError = true;
              break;

            case 2:
              // pas de cookie value => on passe au traitement des attr-value
              setCookievalue("");
              baos[0] = new ByteArrayOutputStream(16);
              AEFstate = 4;
              break;

            case 3:
              setCookievalue(baos[1].toString());
              baos[0] = new ByteArrayOutputStream(16);
              AEFstate++;
              break;

            case 4:
              blnError = true;  // modifiable
              break;

            case 5:
              setCookieAV(baos[0].toString());  // expected match is Secure flag : "Secure"
              baos[0] = new ByteArrayOutputStream(16);
              AEFstate = 4;
              break;

            case 6:
              setCookieAV(baos[0].toString(), "");  // expected match is an attribute without value : "attr="
              baos[0] = new ByteArrayOutputStream(16);
              AEFstate = 4;
              break;

            case 7:
              setCookieAV(baos[0].toString(), baos[1].toString());  // expected match is a complete pair : "attr=value"
              baos[0] = new ByteArrayOutputStream(16);
              AEFstate = 4;  // on boucle
              break;
          }

          break;

        case 34:  // '"' ignorer le guillemet en toutes circonstances y compris dans le cookie-value
          break;

        default:
          switch(AEFstate) {
            case 0:
              baos[0].write(car);
              AEFstate++;
              break;

            case 1:
              baos[0].write(car);
              break;

            case 2:
              baos[1].write(car);
              AEFstate++;
              break;

            case 3:
              baos[1].write(car);
              break;

            case 4:
              baos[0].write(car);
              AEFstate++;
              break;

            case 5:
              baos[0].write(car);
              break;

            case 6:
              baos[1].write(car);
              AEFstate++;
              break;

            case 7:
              baos[1].write(car);
              break;
          }

          break;

      }

      i++;
    }

    // vérification de l'état final
    boolean blnError2 = false;

    if(!blnError) {
      switch(AEFstate) {
        case 3: // arrêt après le 'cookie value' proprement dit
          setCookievalue(baos[1].toString());
          break;

        case 5: // arrêt après une 1ère partie de cookie-av : est-ce "Secure" ?
          setCookieAV(baos[0].toString());
          break;

        case 6:
          setCookieAV(baos[0].toString(), "");
          break;

        case 7: // arrêt après un cookie-av complet ?
          setCookieAV(baos[0].toString(), baos[1].toString());
          break;

        default:
          blnError2 = true;
          break;
      }
    }

    // TO DO : exception si blnError || blnError2
  }

  /*
   * vérifie si 2 cookies désignent une seule et même ressource
   * 2 cookies se réfèrent à la même ressource si leurs propriétés suivantes sont identiques respectivement :
   *  cookie-name, path, domain
   */
  public boolean match(RawCookieNetscape ac) {
    boolean rez = true;

    //if(! (this.cookiename.toLowerCase().equals(ac.getCookiename().toLowerCase())) )
    if( this.cookiename.compareTo(ac.getCookiename()) != 0)
      rez = false;

    if(!this.domain.toLowerCase().equals(ac.getDomain().toLowerCase()))
      rez = false;

    if(!this.path.toLowerCase().equals(ac.getPath().toLowerCase()))
      rez = false;

    return rez;
  }

  private void setCookiename(String s) {
    this.cookiename = s;
  }

  private void setCookievalue(String s) {
    this.cookievalue = s;
  }

  private boolean setCookieAV(String s) {
    if(s.toLowerCase().equals("secure")) {
      this.secure = true;
      return true;
    }
    else
      return false;
  }

  private boolean setCookieAV(String attr, String value) {
    boolean blnRez = false;

    if(attr.toLowerCase().equals("domain")) {
      this.domain = value;
      blnRez = true;
    }

    if(attr.toLowerCase().equals("expires")) {
      this.expires = value;
      blnRez = true;
    }

    if(attr.toLowerCase().equals("path")) {
      this.path = value;
      blnRez = true;
    }

    return blnRez;
  }

  public String getCookiename() {
    return this.cookiename;
  }

  public String getCookievalue() {
    return this.cookievalue;
  }

  public boolean isSecure() {
    return this.secure;
  }

  public String getDomain() {
    return this.domain;
  }

  public String getPath() {
    return this.path;
  }

  public String getExpires() {
    return this.expires;
  }

  public boolean setPath(String pat, boolean force) {
    boolean wasChanged = false;

    // set "/" as the default path when nothing was given in parameter
    String p = (pat.equals("")) ? "/" : pat;

    if(force) {
      this.path = p;
      wasChanged = true;
    }
    else {
      if(path.equals("")) {
        this.path = p;
        wasChanged = true;
      }
    }

    return wasChanged;
  }

  public void setDomain(String s) {
    this.domain = s;
  }

  public String getCookieAsRequestHeader() {
    StringBuffer srez = new StringBuffer();

    // la version n'est pas renvoyée : cette tâche est déléguée aux sous-classes de GenericCookie
    // rez += "Version=" + version;

    srez.append(cookiename + "=" + cookievalue);

    return srez.toString();
  }

  public String toString() {
    StringBuffer srez = new StringBuffer(12);

    srez.append(cookiename);
    srez.append("=");
    srez.append(cookievalue);
    srez.append("\n\t");
    srez.append(domain);
    srez.append("\n\t");
    srez.append(expires);
    srez.append("\n\t");
    srez.append(path);
    srez.append("\n\t");
    srez.append(secure);
    srez.append("\n");

    return srez.toString();
  }

}

/*
 * implements a cookie (RFC 6265) from a given Set-Cookie header
 * each object will be created from the Factory Method 'RawCookieFactory'
 * the parsing method is the permissive algorithm given in RFC6265 §5.2
 */
class RawCookieV1 extends RawCookie implements Serializable {

  /* describe all fields which can be sent in a cookie V1 by the server */
  private String cookiename = "";
  private String cookievalue = "";
  /*
   * RFC2109 §4.3.4 :
   * The user agent does not return the comment information to the origin server.
   * => default value = ""
   */
  private String comment = "";
  /*
   * RFC2109 §4.3.4 :
   * The value for the domain attribute must be the value from the Domain
   * attribute, if any, of the corresponding Set-Cookie response header.
   * Otherwise the attribute should be omitted from the Cookie request
   * header.
   * => default value = ""
   */
  private String domain = "";
  private String maxage = "";
  /*
   * RFC2109 §4.3.4 :
   * The value for the path attribute must be the value from the Path attribute, if any,
   * of the corresponding Set-Cookie response header.  Otherwise the
   * attribute should be omitted from the Cookie request header.
   * => default value = ""
   */
  private String path = "";
  private boolean secure;
  private boolean httponly;

  /*
   * RFC2109 §4.3.4 :
   * The value of the cookie-version attribute must be the value from the
   * Version attribute, if any, of the corresponding Set-Cookie response
   * header.  Otherwise the value for cookie-version is 0.
   * => default value = 0
   */
  private int version = 0;

  /* describe all fields necessary to cookie management, but not sent by the server itself */
  // creationDate allows us to check if 'expires' value is reached
  long creationDate;

  /* RFU : initialize here all other fields that will not be stored in file (transient) */
  // private transient int example_non_serializable;

  public RawCookieV1() {}

  public RawCookieV1(String headerVal) {

    creationDate = new Date().getTime();

    byte[] byt = headerVal.getBytes();
    int i = 0;
    int AEFstate = 0;
    boolean blnError = false;

    ByteArrayOutputStream baos1 = new ByteArrayOutputStream(16);
    ByteArrayOutputStream baos2 = new ByteArrayOutputStream(16);
    ByteArrayOutputStream[] baos = new ByteArrayOutputStream[] {baos1, baos2};

    // parse the byte array
    while( (i < byt.length) && !blnError) {
      byte car = byt[i];

      switch(car) {
        case 32:  // ' '
          switch(AEFstate) {
            case 0:
              break;

            case 1:
              baos[0].write(car);
              break;

            case 2:
              break;

            case 3: // sauvegarder dans le cookie-value
              baos[1].write(car);
              break;

            case 4: // ignorer après le ";"
              break;

            case 5:
              baos[0].write(car);
              break;

            case 6:
              blnError = true;
              break;

            case 7: // conserver dans les values, sauf au début et à la fin (trim)
              baos[1].write(car);
              break;
          }

          break;

        case 61: // "="
          switch(AEFstate) {
            case 0:
              blnError = true;
              break;

            case 1:
              // TO DO : l'initialisation ne doit pas être faite ici !
              blnError = !setCookiename(baos[0].toString());
              baos[1] = new ByteArrayOutputStream(16);
              AEFstate++;
              break;

            case 2:
              // on autorise le caractère "=" dans la valeur du cookie, y compris comme 1er caractère
              baos[1].write(car);
              AEFstate++;
              break;

            case 3:
              // on autorise le caractère "=" dans la valeur du cookie
              baos[1].write(car);
              break;

            case 4:
              blnError = true;
              break;

            case 5:
              baos[1] = new ByteArrayOutputStream(16);
              AEFstate++;
              break;

            case 6:
              blnError = true;
              break;

            case 7:
              blnError = true;
              break;
          }

          break;

        case 59: // ";"
          switch(AEFstate) {
            case 0:
              blnError = true;
              break;

            case 1:
              blnError = true;
              break;

            case 2:
              // pas de cookie value => on passe au traitement des attr-value
              setCookievalue("");
              baos[0] = new ByteArrayOutputStream(16);
              AEFstate = 4;
              break;

            case 3:
              setCookievalue(baos[1].toString());
              baos[0] = new ByteArrayOutputStream(16);
              AEFstate++;
              break;

            case 4:
              // discard ";;" pattern
              break;

            case 5:
              setCookieAV(baos[0].toString());  // expected match is Secure/HttpOnly flags
              baos[0] = new ByteArrayOutputStream(16);
              AEFstate = 4;
              break;

            case 6:
              setCookieAV(baos[0].toString(), "");  // expected match is an attribute without value : "attr="
              baos[0] = new ByteArrayOutputStream(16);
              AEFstate = 4;
              break;

            case 7:
              setCookieAV(baos[0].toString(), baos[1].toString());  // expected match is a complete pair : "attr=value"
              baos[0] = new ByteArrayOutputStream(16);
              AEFstate = 4;  // on boucle
              break;
          }

          break;

        case 34:  // '"' ignorer le guillemet en toutes circonstances y compris dans le cookie-value
          break;

        default:
          switch(AEFstate) {
            case 0:
              baos[0].write(car);
              AEFstate++;
              break;

            case 1:
              baos[0].write(car);
              break;

            case 2:
              baos[1].write(car);
              AEFstate++;
              break;

            case 3:
              baos[1].write(car);
              break;

            case 4:
              baos[0].write(car);
              AEFstate++;
              break;

            case 5:
              baos[0].write(car);
              break;

            case 6:
              baos[1].write(car);
              AEFstate++;
              break;

            case 7:
              baos[1].write(car);
              break;
          }

          break;

      }

      i++;
    }

    // check final state of automaton
    boolean blnError2 = false;

    if(!blnError) {
      switch(AEFstate) {
        case 3: // stop after 'cookie value' ?
          setCookievalue(baos[1].toString());
          break;

        case 5: // stop after 1st part of cookie-av (Secure/HttpOnly) ?
          setCookieAV(baos[0].toString());
          break;

        case 6:
          setCookieAV(baos[0].toString(), "");
          break;

        case 7: // stop after complete cookie-av ?
          setCookieAV(baos[0].toString(), baos[1].toString());
          break;

        default:
          blnError2 = true;
          break;
      }
    }

    // TO DO : exception si blnError || blnError2

  }

  /*
   * vérifie si 2 cookies désignent une seule et même ressource
   * 2 cookies se réfèrent à la même ressource si leurs propriétés suivantes sont identiques respectivement :
   *  cookie-name, path, domain
   */
  public boolean match(RawCookieV1 ac) {
    boolean rez = true;

    //if(! (this.cookiename.toLowerCase().equals(ac.getCookiename().toLowerCase())) )
    if( this.cookiename.compareTo(ac.getCookiename()) != 0)
      rez = false;

    if(!this.domain.toLowerCase().equals(ac.getDomain().toLowerCase()))
      rez = false;

    if(!this.path.toLowerCase().equals(ac.getPath().toLowerCase()))
      rez = false;

    return rez;
  }

  private boolean setCookiename(String s) {
    boolean rez = false;

    if(s.trim().indexOf(" ") == -1) {
      this.cookiename = s.trim();
      rez = true;
    }

    return rez;
  }

  private void setCookievalue(String s) {
    this.cookievalue = s.trim();
  }

  private boolean setCookieAV(String s) {
    boolean blnRez = false;

    if(s.trim().toLowerCase().equals("secure")) {
      this.secure = true;
      return true;
    }

    if(s.trim().toLowerCase().equals("httponly")) {
      this.httponly = true;
      return true;
    }

    return blnRez;
  }

  private boolean setCookieAV(String attr, String value) {
    boolean blnRez = false;

    if(attr.trim().toLowerCase().equals("comment")) {
      this.comment = value.trim();
      blnRez = true;
    }

    if(attr.trim().toLowerCase().equals("domain")) {
      this.domain = value.trim();
      blnRez = true;
    }

    if(attr.trim().toLowerCase().equals("max-age")) {
      this.maxage = value.trim();
      blnRez = true;
    }

    if(attr.trim().toLowerCase().equals("path")) {
      this.path = value.trim();
      blnRez = true;
    }

    if(attr.trim().toLowerCase().equals("version")) {
      this.version = Integer.parseInt(value.trim());
      blnRez = true;
    }

    return blnRez;
  }

  public String getCookiename() {
    return this.cookiename;
  }

  public String getCookievalue() {
    return this.cookievalue;
  }

  public boolean isSecure() {
    return this.secure;
  }

  public String getComment() {
    return this.comment;
  }

  public String getDomain() {
    return this.domain;
  }

  public String getPath() {
    return this.path;
  }

  public String getMaxage() {
    return this.maxage;
  }

  public int getVersion() {
    return this.version;
  }

  public boolean isExpired() {

    long now = new Date().getTime();

    long longage = 0;

    if(maxage != "")
      longage = Long.parseLong(maxage) * 1000;

    return(now > creationDate + longage);
  }

  // return the cookie, as said in the RFC2109 §4.3.4
  public String getCookieAsRequestHeader() {

    /*
     * RFC2109 §4.3.4 :
     * Note: For backward compatibility, the separator in the Cookie header is semi-colon (;) everywhere.
     */
    String separator = ";";

    StringBuffer srez = new StringBuffer();

    // not really compliant to the RFC, but we decide not to mention the version when it is the default value of 0 (like browsers do)
    /*RFU : separation des cookies
      if(version != 0)
      srez.append("$Version=\"" + version + "\"" + separator);*/

    srez.append(cookiename + "=\"" + cookievalue + "\"");
    /*RFU : separation des cookies
      if(path != "")
      srez.append(separator + "$Path=\"" + path + "\"");
    if(domain != "")
      srez.append(separator + "$Domain=\"" + domain + "\"");*/

    return srez.toString();
  }

}

abstract class RawCookie {
}

/*
 * Factory Method for RawCookie classes
 */
class RawCookieFactory {

  /*
   * builds and returns a RawCookie object
   * the main work is to recognize what kind of cookie we are dealing with,
   * since servers are not all compliant to RFCs
   */
  public static RawCookie create(String headerVal) throws MalformedCookieException {
    int caseVal = 0;
    RawCookie rc = null;

    /*
     * improved in v0.119b
     * as said in RFC2109 §10.1.2, the difference of cookie V1 from Netscape, is that the header-value contains :
     *  version=1 or, Max-Age or, Expires with a quoted value
     * when a Netscape cookie only contains Expires without quotes
     * For example Apache doesn't send the 'version=1', so we must check several things before choosing the cookie type
     */
    if( (headerVal.toLowerCase().indexOf("max-age=") != -1) ||
        (headerVal.toLowerCase().indexOf("expires=\"") != -1)  ||
        (headerVal.toLowerCase().indexOf("version=1") != -1) )
      caseVal = 1;
    else
      caseVal = 2;

    switch(caseVal) {
      case 1:
        rc = new RawCookieV1(headerVal);
        break;

      case 2:
        rc = new RawCookieNetscape(headerVal);
        break;

      default:
        break;
    }

    if(caseVal == 0)
      throw new MalformedCookieException(headerVal);
    else
      return rc;

  }

}

class CookieWrapper {

  private Hashtable<String, Vector> netscape = new Hashtable<String, Vector>();
  private Hashtable<String, Vector> V1 = new Hashtable<String, Vector>();

  /*
   * CLI specific properties : file names
   */
  private String fileNetscape;
  private String fileV1;

  public CookieWrapper() {}

  /*
   * constructor with files, usefull in CLI mode
   */
  public CookieWrapper(String fileNetscape, String fileV1) {

    this.fileNetscape = fileNetscape;
    Hashtable h = load(fileNetscape);

    if(h != null)
      netscape = h;

    this.fileV1 = fileV1;
    h = load(fileV1);

    if(h != null)
      V1 = h;

    //System.out.println("load ->" + netscape.size());
    //System.out.println("load ->" + V1.size());
  }


  /*
   * loads the serialiazed object from the file
   */
  private Hashtable load(String filename) {
    Hashtable h = null;
    // reading the Hashtable from the file
    ObjectInput ois = null;

    try {

      File file = new File(filename);
      FileInputStream fis = new FileInputStream(file);
      BufferedInputStream buffer = new BufferedInputStream( fis );
      ois = new ObjectInputStream(buffer);
      h = (Hashtable)ois.readObject();
      //System.out.println("load ->" + h.size());
      buffer = null;
      fis = null;
    }

    catch(java.io.FileNotFoundException fnfe) {
      System.err.println(fnfe);
    }
    catch(java.io.IOException e) {
      System.err.println(e);
    }
    catch(java.lang.ClassNotFoundException e) {
      System.err.println(e);
    }
    finally {
      try {
        if(ois != null)
          ois.close();

        ois = null;
      }
      catch(IOException ioe) {
        System.err.println(ioe);
      }
    }

    return h;
  } // end method

  public void saveAll() {
    if( fileNetscape != null && fileV1 != null ) {
      save(fileNetscape, netscape);
      save(fileV1, V1);
    }
  }

  private void save(String filename, Hashtable h) {
    // writing the Hashtable in the file
    ObjectOutputStream oos = null;

    try {
      File file = new File(filename);
      FileOutputStream fos = new FileOutputStream(file);
      OutputStream buffer = new BufferedOutputStream( fos );

      oos = new ObjectOutputStream(buffer);
      //System.err.println("writing the h with size : " + h.size());
      oos.writeObject(h);
    }
    catch(java.io.IOException e) {
      System.err.println(e);
    }
    finally {
      try {
        if(oos != null)
          oos.close();
      }
      catch(IOException ioe) {
        System.err.println(ioe);
      }
    }
  }

  public void add(String requestDomain, String requestURI, RawCookieNetscape[] rcn, boolean overwritePath) {

    // TO DO : get acceptSpoofing parameter
    boolean acceptSpoofing = true;

    for(RawCookieNetscape e : rcn) {

      // vectorDomain will be used as the key of the Vector
      String vectorDomain = "";
      String cookieDomain = e.getDomain();

      //System.err.println("adding cookie : " + requestDomain + ", " + requestURI + "; " + e.getDomain() + ", " + overwritePath);

      // when the path was not indicated in the cookie, we must set it with the default value
      e.setPath(requestURI, overwritePath);

      if(cookieDomain.equals("")) {
        // set the cookie domain when it was empty in the received Set-Cookie header
        vectorDomain = requestDomain;
        e.setDomain(vectorDomain);
      }
      else {
        if(requestDomain.toLowerCase().endsWith(cookieDomain.toLowerCase())) {
          if( cookieDomain.endsWith(".com")
              || cookieDomain.endsWith(".edu")
              || cookieDomain.endsWith(".net")
              || cookieDomain.endsWith(".org")
              || cookieDomain.endsWith(".gov")
              || cookieDomain.endsWith(".mil")
              || cookieDomain.endsWith(".int") ) {
            vectorDomain = cookieDomain;
          }
          else {
            if(cookieDomain.contains(".")) {  // we should check more that this is a real domain
              vectorDomain = cookieDomain;
            }
            else {
              // we're facing an abnormal cookie domain which is, indeed, a subdomain
            }
          }
        }
        else {
          // the cookie doesn't belong to the requested domain... it's spoofing
          if(acceptSpoofing) {
            if( cookieDomain.endsWith(".com")
                || cookieDomain.endsWith(".edu")
                || cookieDomain.endsWith(".net")
                || cookieDomain.endsWith(".org")
                || cookieDomain.endsWith(".gov")
                || cookieDomain.endsWith(".mil")
                || cookieDomain.endsWith(".int") ) {
              vectorDomain = cookieDomain;
            }
            else {
              if(cookieDomain.contains(".")) {  // we should check more that this is a real domain
                vectorDomain = cookieDomain;
              }
              else {
                // we're facing an abnormal cookie domain which is, indeed, a subdomain
              }
            }
          }
          else {
            // spoofing is not allowed
          }
        }
      }

      // créer un cookie (permettra les appels à match() et getExpires())
      RawCookieNetscape newac = e;
      RawCookieNetscape newbc = null;

      // récupérer la date d'expiration
      String newExp = newac.getExpires();

      if(!newExp.equals("")) {  // date d'expiration précisée : supprimer si antérieure à maintenant

        try {
          RFC822.Date mydat1 = new RFC822().new Date(newExp);
          //RFC822.Date mydat2 = new RFC822().new Date((new Date()).toString());
          RFC822.Date mydat2 = new RFC822().new Date(RFCUtil.generateDate());

          // stocker le cookie si date non expirée
          newbc = (mydat1.compareTo(mydat2) >= 0) ? newac : null;
        }
        catch(IllegalArgumentException iae) {
          System.err.println(iae);
        }
      }
      else {  // date d'expiration non précisée : conserver le cookie pendant la durée de vie du navigateur
        newbc = newac;
      }

      // cookie à sauvegarder si la date d'expiration n'est pas atteinte

      if(!vectorDomain.equals("")) {
        // récupération des anciennes valeurs
        if(netscape.containsKey(vectorDomain)) {
          Vector<RawCookieNetscape> oldval = (Vector)netscape.get(vectorDomain);

          // on n'autorise pas les doublons de cookie (la notion de 'doublon' est codée dans match())
          for(Enumeration ee = oldval.elements(); ee.hasMoreElements();) {
            RawCookieNetscape oldac = (RawCookieNetscape)ee.nextElement();

            if(oldac.match(newac))
              oldval.remove(oldac);
          }

          if(newbc != null)
            oldval.add(newbc);
        }
        else {
          if(newbc != null) {
            Vector<RawCookieNetscape> newval = new Vector(8);
            newval.add(newbc);
            netscape.put(vectorDomain, newval);
          }
        }
      }
      else {
        // this was not possible to add the cookie, inform the user ?
      }
    }
  }

  public void add(String key, RawCookieV1[] rcn) {

    for(RawCookieV1 e : rcn) {

      // créer un cookie (permettra les appels à match() et getExpires())
      RawCookieV1 newac = e;

      // le cookie doit-il être stocké ? (vérification sur maxage)
      RawCookieV1 newbc = (!newac.getMaxage().equals("0")) ? newac : null;

      // récupération des anciennes valeurs
      if(V1.containsKey(key)) {
        Vector<RawCookieV1> oldval = (Vector)V1.get(key);

        // on n'autorise pas les doublons de cookie (précisément la vérification porte sur le champ cookie-name)
        for(Enumeration f = oldval.elements(); f.hasMoreElements();) {
          RawCookieV1 oldac = (RawCookieV1)f.nextElement();

          if(oldac.match(newac))
            oldval.remove(oldac);
        }

        if(newbc != null)
          oldval.add(newbc);
      }
      else {
        if(newbc != null) {
          Vector<RawCookieV1> newval = new Vector<RawCookieV1>(8);
          newval.add(newbc);
          V1.put(key, newval);
        }
      }
    }
  } // end method

  /*
   * returns the cookies identified by a key and a path
   */
  public String[] get(String key, String path) {

    // the searched domain
    String requestDomain = key.toLowerCase();

    // the netscape cookies to return
    String[] rezNetscape = new String[0];

    // the cookies V1 to return
    String[] rezV1 = new String[0];

    // the netscape cookies with a matching domain
    Vector<RawCookieNetscape> vrez = new Vector<RawCookieNetscape>(8);

    /*
     * Netscape doc : "If there is a tail match, then the cookie will go through path matching to see if it should be sent."
     * but sometimes the server send cookies with a domain starting with "." character
     */
    for(Enumeration keys = netscape.keys(); keys.hasMoreElements();) {
      String vectorDomain = (String)keys.nextElement();

//System.err.println("requestDomain:" + requestDomain + " vectorDomain:" + vectorDomain);

      if(requestDomain.length() == vectorDomain.length()) {
        if(requestDomain.equals(vectorDomain.toLowerCase())) {
          // both domains are exactly the same, keep candidates
          vrez.addAll((Vector)(netscape.get(vectorDomain)));
        }
      }
      else {
        if( (requestDomain.length() > vectorDomain.length()) ) {
          if(requestDomain.endsWith(vectorDomain.toLowerCase())
              && ( (  requestDomain.charAt(requestDomain.length() - vectorDomain.length() - 1) == 46 ) || vectorDomain.startsWith(".") ) ) {
            // it is a subdomain, keep candidates
            vrez.addAll((Vector)(netscape.get(vectorDomain)));
          }
        }
        else {
          if( (vectorDomain.length() - requestDomain.length() == 1)
              && vectorDomain.startsWith(".")
              && vectorDomain.toLowerCase().endsWith(requestDomain) ) {
            // both domains are equivalent, although the cookieDomain starts with "."
            vrez.addAll((Vector)(netscape.get(vectorDomain)));
          }
        }
      }
    }

    // look for cookies having a matching path (among the ones having a matching domain)
    if(vrez.size() > 0) {

      // get the original array to sort
      RawCookieNetscape[] st = new RawCookieNetscape[vrez.size()];
      st = (RawCookieNetscape[]) vrez.toArray(st);

      // this array contains the sorted result, it will be filled later
      RawCookieNetscape[] stri = new RawCookieNetscape[vrez.size()];
      int j = 0;

      // loop on the original array
      for(int i = 0; i < st.length; i++) {

        // look for a cookie with an eligible path value
        if(path.startsWith(st[i].getPath())) {

          // loop on the sorted array, and look for the right place for the new found cookie
          int ind = 0;
          boolean blnFound = false;

          for(int k = 0; k < j; k++) {

            if(!blnFound) {
              if(st[i].getPath().length() > stri[k].getPath().length()) {
                // make the place for the cookie by shifting elements
                for(int l = k; l < j; l++) {
                  stri[j - l] = stri[j - l - 1];
                }

                // insert : end of job
                stri[k] = st[i];
                blnFound = true;
              }
            }
          }

          // nothing to shift : insert and end of job
          if(!blnFound) {
            stri[j] = st[i];
          }

          j++;
        }
      }

      // the results
      String[] str = new String[j];

      for(int i = 0; i < j; i++) {
        str[i] = stri[i].getCookieAsRequestHeader();
      }

      //return( (j>0) ? str : null );
      if(j > 0)
        rezNetscape = str;

    }

    /*
     * RFC2109 §4.3.4 :
     * The following rules apply to choosing applicable cookie-values from
     * among all the cookies the user agent has.
     *  Domain Selection
     *    The origin server's fully-qualified host name must domain-match
     *    the Domain attribute of the cookie.
     *  Path Selection
     *    The Path attribute of the cookie must match a prefix of the
     *    request-URI.
     *  Max-Age Selection
     *    Cookies that have expired should have been discarded and thus
     *    are not forwarded to an origin server.
     * If multiple cookies satisfy the criteria above, they are ordered in
     * the Cookie header such that those with more specific Path attributes
     * precede those with less specific.  Ordering with respect to other
     * attributes (e.g., Domain) is unspecified.
     */
    if(V1.containsKey(key)) {

      // get the original array to sort
      Vector<RawCookieV1> vInit = (Vector)(V1.get(key));

      // filter the expired cookies (they are not sent to the server, but we don't actually remove them from the hashtable)
      Vector<RawCookieV1> v = new Vector<RawCookieV1>();
      Enumeration keys = vInit.elements();
      RawCookieV1 rcv;

      while(keys.hasMoreElements()) {
        rcv = (RawCookieV1)keys.nextElement();

        if(!rcv.isExpired())
          v.add(rcv);
      }

      // filter done, get this object as an array
      RawCookieV1[] st = new RawCookieV1[v.size()];
      st = (RawCookieV1[]) v.toArray(st);

      // this array contains the sorted result, it will be filled later
      RawCookieV1[] stri = new RawCookieV1[v.size()];
      int j = 0;

      // loop on the original array
      for(int i = 0; i < st.length; i++) {

        // look for a cookie with an eligible path value
        if(path.startsWith(st[i].getPath())) {

          // loop on the sorted array, and look for the right place for the new found cookie
          int ind = 0;
          boolean blnFound = false;

          for(int k = 0; k < j; k++) {

            if(!blnFound) {
              if(st[i].getPath().length() > stri[k].getPath().length()) {
                // make the place for the cookie by shifting elements
                for(int l = k; l < j; l++) {
                  stri[j - l] = stri[j - l - 1];
                }

                // insert : end of job
                stri[k] = st[i];
                blnFound = true;
              }
            }
          }

          // nothing to shift : insert and end of job
          if(!blnFound) {
            stri[j] = st[i];
          }

          j++;
        }
      }

      // the results
      String[] str = new String[j];

      for(int i = 0; i < j; i++) {
        str[i] = stri[i].getCookieAsRequestHeader();
      }

      //return( (j>0) ? str : null );
      if(j > 0)
        rezV1 = str;

    }

    // build the final array including all available cookies
    /*int isize = rezNetscape.length + rezV1.length;
    if(isize > 0) {
      String[] rezSum = new String[isize];
      System.arraycopy(rezNetscape, 0, rezSum, 0, rezNetscape.length);
      System.arraycopy(rezV1, 0, rezSum, rezNetscape.length, rezV1.length);
      return rezSum;
    }
    else
      return null;*/

    // calculate array dimension
    int isize = 0;

    if( rezNetscape.length > 0 )
      isize++;

    if( rezV1.length > 0 )
      isize++; // TO DO : no ! this should be equal to rezV1 length (all v1 cookies must be on separate lines)

    String[] rezSum = new String[isize];

    // fill the array
    String strNetscape = "";
    String strV1 = "";

    if(rezNetscape.length > 0) {
      if(rezV1.length > 0) {

        for(String s : rezNetscape)
          strNetscape += s + "; ";

        rezSum[0] = strNetscape;


        for(String s : rezV1)
          strV1 += s + "; ";

        rezSum[1] = strV1;
      }
      else {

        for(String s : rezNetscape)
          strNetscape += s + "; ";

        rezSum[0] = strNetscape;
      }

    }
    else {
      if(rezV1.length > 0) {

        for(String s : rezV1)
          strV1 += s + "; ";

        rezSum[1] = strV1;
      }
    }

    // return the array
    return(isize > 0) ? rezSum : null;

  }

  /*
   * returns this object into a String
   */
  public String toString() {
    // dump the object
    StringBuffer sb = new StringBuffer();

    // get all netscape elements
    Enumeration keys = netscape.keys();
    String st;

    while(keys.hasMoreElements()) {

      st = (String)keys.nextElement();
      Vector vec = (Vector)(netscape.get(st));
      RawCookieNetscape[] nc = (RawCookieNetscape[])vec.toArray(new RawCookieNetscape[vec.size()]);

      sb.append(st).append(";\n");

      for(RawCookieNetscape onenc : nc)
        sb.append(onenc.toString()).append("\n");

    }

    // get all V1 elements
    keys = V1.keys();

    while(keys.hasMoreElements()) {

      st = (String)keys.nextElement();
      Vector vec = (Vector)(V1.get(st));
      RawCookieV1[] nc = (RawCookieV1[])vec.toArray(new RawCookieV1[vec.size()]);

      for(RawCookieV1 onenc : nc)
        sb.append(onenc.getCookieAsRequestHeader()).append("\n");

    }

    return sb.toString();
  } // end toString()

}

/*
 * This class is a natural extension of java.security.SecureRandom
 * its goal : provide the fastest (but insecure) random for SSL
 * Usually, there is only 1 initialisation of the random, so this
 *  gives better performance on the 1st call only
 * My tests say : XP 120mS -> 0mS ; Vista 50mS -> 1mS
 * which can be applied in two ways:
 */
class UnsecureRandom extends SecureRandom {

  public UnsecureRandom() {}

  public UnsecureRandom(byte[] seed) {}

  protected UnsecureRandom(SecureRandomSpi secureRandomSpi, Provider provider) {}

  /*
   * This method overrides nextBytes() from java.security.SecureRandom
   * and provides a false but fast random bytes
   * @see java.security.SecureRandom#nextBytes(byte[])
   */

  public synchronized void nextBytes(byte[] bytes) {
    for(int i = 0; i < bytes.length; ++i) {
      bytes[i] = 0;
    }
  }

} // end class

/*
 * Class used as a cache of SSLContext objects
 * It also provides mechanisms to track when init() or createSSLEngine()
 * are necessary.
 * In particular, avoiding redundant calls to init() and createSSLEngine()
 * allows us to perform Session Resumption, when the program is called with
 * -Djdk.tls.useExtendedMasterSecret=false
 */
class SSLContextProxy extends SSLContext {

  /* stores cached SSLContext objects called with protocol + provider */
  protected static Hashtable<CachedInstance, SSLContext> cachedSSLContexts;

  /* stores cached SSLContext objects called with protocol only */
  protected static Hashtable<PCachedInstance, SSLContext> pcachedSSLContexts;

  /* tracks SSLContext objects which already called init() */
  protected static ArrayList<ContextInit> contextInits;

  /* tracks SSLContext objects which already called createSSLEngine() for a host:server tuple */
  protected static ArrayList<CachedEngine> cachedEngines;

  /* Constructor */
  protected SSLContextProxy(SSLContextSpi contextSpi, Provider provider, String protocol) {
    super(contextSpi, provider, protocol);
  }

  /*
   * cached version of SSLContext.getInstance(String protocol, Provider provider)
   */
  public static SSLContext getInstance(String protocol) throws NoSuchAlgorithmException {
    SSLContext sc = null;

      //sc = SSLContext.getInstance("TLS", "SunJSSE");
      PCachedInstance candidate = new PCachedInstance(protocol);

      //check if any cached instance matches
      boolean isCached = false;
      if(pcachedSSLContexts != null)
        for (Enumeration eK = pcachedSSLContexts.keys() ; eK.hasMoreElements() ;) { 
          PCachedInstance ci = (PCachedInstance)(eK.nextElement());
          if(candidate.toString().equals(ci.toString())) {
            isCached = true;
            sc = (SSLContext)pcachedSSLContexts.get(ci);
          }
        }
      else // very first run, nothing found at all, just initialize the hashtable
        pcachedSSLContexts = new Hashtable<PCachedInstance, SSLContext>();

      // DEBUG System.err.println("isCached: " +isCached);

      // cached it if necessary
      if(!isCached) {
        sc = SSLContext.getInstance(protocol);
        pcachedSSLContexts.put(candidate, sc);
      }

    return sc;
  }

  /*
   * cached version of SSLContext.getInstance(String protocol)
   */
  public static SSLContext getInstance(String protocol, String provider) throws NoSuchAlgorithmException, NoSuchProviderException {
    SSLContext sc = null;

      //sc = SSLContext.getInstance("TLS", "SunJSSE");
      CachedInstance candidate = new CachedInstance(protocol, provider);

      //check if any cached instance matches
      boolean isCached = false;
      if(cachedSSLContexts != null)
        for (Enumeration eK = cachedSSLContexts.keys() ; eK.hasMoreElements() ;) { 
          CachedInstance ci = (CachedInstance)(eK.nextElement());
          if(candidate.toString().equals(ci.toString())) {
            isCached = true;
            sc = (SSLContext)cachedSSLContexts.get(ci);
          }
        }
      else // very first run, nothing found at all, just initialize the hashtable
        cachedSSLContexts = new Hashtable<CachedInstance, SSLContext>();

      // DEBUG System.err.println("isCached: " +isCached);

      // cached it if necessary
      if(!isCached) {
        sc = SSLContext.getInstance(protocol, provider);
        cachedSSLContexts.put(candidate, sc);
      }

    return sc;
  }

  /*
   * Checks if we already called init() for this {context:keymanager:trustmanager:random}
   */
  public static boolean isInit(SSLContext sslc, KeyManager[] km, TrustManager[] tm, SecureRandom random) throws KeyManagementException, NoSuchAlgorithmException {
    ContextInit candidate = new ContextInit( sslc, km, tm, random );

    // parse the cached objects
    boolean isCached = false;
    if(contextInits != null)
      for (int i = 0; i < contextInits.size(); i++) {
        ContextInit ci = contextInits.get(i);
        if(candidate.equals(ci))
          isCached = true;
      }

    else // very first run, nothing found at all, just initialize the hashtable
      contextInits = new ArrayList<ContextInit>();

    if(!isCached)
      contextInits.add(candidate);

    return isCached;
  }

  /*
   * Checks if we already called createSSLEngine() for this {context:server:port}
   */
  public static boolean hasEngine(SSLContext sslc, String hostname, int port) {
    boolean isCached = false;

    CachedEngine candidate = new CachedEngine(sslc, hostname, port);

    if(cachedEngines != null)
      for (int i = 0; i < cachedEngines.size(); i++) {
        CachedEngine ce = cachedEngines.get(i);
        if(candidate.equals(ce))
          isCached = true;
      }

    else // very first run, nothing found at all, just initialize the hashtable
      cachedEngines = new ArrayList<CachedEngine>();

    if(!isCached)
      cachedEngines.add(candidate);

    // DEBUG System.err.println("hasEngine: " +isCached);
    return isCached;
  }

  /*
   * Class CachedEngine : manages {SSLContext,String,int} tuples
   * already gone through SSLContext.createSSLEngine()
   */
  static class CachedEngine {
    protected SSLContext sslc;
    protected String hostname;
    protected int port;

    protected CachedEngine(SSLContext sslc, String hostname, int port) {
      this.sslc = sslc;
      this.hostname = hostname;
      this.port = port;
    }

    public boolean equals(CachedEngine ce) {
      boolean areEqual = false;

      areEqual = ( (this.sslc == ce.sslc)
                 &&(this.hostname.equals(ce.hostname))
                 &&(this.port == ce.port) );

      return areEqual;
    }

  } // end class

  /*
   * Class ContextInit : manages {SSLContext,KeyManager[],TrustManager[],SecureRandom} tuples
   * already gone through SSLContext.init()
   */
  static class ContextInit {
    protected SSLContext sslc;
    protected KeyManager[] km;
    protected TrustManager[] tm;
    protected SecureRandom random;

    protected ContextInit(SSLContext sslc, KeyManager[] km, TrustManager[] tm, SecureRandom random) {
      this.sslc = sslc;
      this.km = km;
      this.tm = tm;
      this.random = random;
    }

    public boolean equals(ContextInit ci) {
      boolean areEqual = false;

      areEqual = ( (this.sslc == ci.sslc)
                 &&(this.km == ci.km)
                 &&(this.tm == ci.tm)
                 &&(this.random == ci.random) );

      return areEqual;
    }
  } // end class

  /*
   * Class CachedInstance : manages the cached Hashtable for {protocol,provider} tuples
   */
  static class CachedInstance {
    protected String protocol;
    protected String provider;

    protected CachedInstance(String protocol, String provider) {
      this.protocol = protocol;
      this.provider = provider;
    }

    public String toString() {
      StringBuffer srez = new StringBuffer(12);

      srez.append(protocol);
      srez.append(",");
      srez.append(provider);

      return srez.toString();
    }
  } // end class

  /*
   * Class CachedInstance : manages the cached Hashtable for {protocol} only
   */
  static class PCachedInstance {
    protected String protocol;

    protected PCachedInstance(String protocol) {
      this.protocol = protocol;
    }

    public String toString() {
      StringBuffer srez = new StringBuffer(12);

      srez.append(protocol);

      return srez.toString();
    }
  } // end class

} // end class






