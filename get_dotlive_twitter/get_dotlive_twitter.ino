#include <WiFiClientSecure.h>
#include <WiFiMulti.h>
#include <WiFiUdp.h>

#include <TimeLib.h>
#include <M5Stack.h>
#include <misakiUTF16.h>

#include <base64.h>
#include "mbedtls/sha1.h"
 
#include <codecvt>
#include <string>
#include <cassert>
#include <locale>

#include "private_data.h"
 
WiFiMulti wifiMulti;
 
#define SHA1_SIZE 20
 
const char *base_host        = "api.twitter.com";
const char *base_URL         = "https://api.twitter.com/1.1/trends/place.json";
const char *base_URI         = "/1.1/trends/place.json";
const int httpsPort           = 443;
 
String woeid = "23424856"; //WOEID ( Japan )
 
const char *key_http_method        = "GET";
const char *key_consumer_key       = "oauth_consumer_key";
const char *key_nonce              = "oauth_nonce";
const char *key_signature_method   = "oauth_signature_method";
const char *key_timestamp          = "oauth_timestamp";
const char *key_token              = "oauth_token";
const char *key_version            = "oauth_version";
//const char *key_status             = "";
const char *key_signature          = "oauth_signature";
const char *value_signature_method = "HMAC-SHA1";
const char *value_version          = "1.0";
 
//-------NTPサーバー時刻取得引数初期化-----------------------------
IPAddress _NtpServerIP;
const int NTP_PACKET_SIZE = 48; // NTP time stamp is in the first 48 bytes of the message
byte packetBuffer[ NTP_PACKET_SIZE]; //buffer to hold incoming and outgoing packets
const int timeZone = 9;     // Tokyo
WiFiUDP Udp;
unsigned int localPort = 8888;  // local port to listen for UDP packets
//--------------------------------------------------------
 
#define Display_MaxData 10
String unicode_str[Display_MaxData];
uint32_t LastTime = 0;
 
//--------セットアップ関数--------------------------------
void setup()
{
  Serial.begin(115200);
  M5.begin();
  delay(100);
 
  Serial.println();
  Serial.print(F("Connecting to "));
  Serial.println(ssid);
 
  wifiMulti.addAP(ssid, password);
 
  Serial.println(F("Connecting Wifi..."));
  if(wifiMulti.run() == WL_CONNECTED) {
      Serial.println("");
      Serial.println(F("WiFi connected"));
      Serial.println(F("IP address: "));
      Serial.println(WiFi.localIP());
  }
  delay(1000);
 
  //NTPサーバーから時刻を取得---------------------------
  const char *NtpServerName = "time.windows.com";
  WiFi.hostByName(NtpServerName, _NtpServerIP);
  Serial.print(NtpServerName);
  Serial.print(": ");
  Serial.println(_NtpServerIP);
  Udp.begin(localPort);
  setSyncProvider(getNtpTime);
  Serial.print(F("now="));
  Serial.println(now());
  delay(100);
 
  Tweet_Get(); //ツイート取得
  LastTime = millis();
}
//-------------メインループ-----------------------
void loop(){
  if(millis() - LastTime > 180000){ //Tweet get every 3 minutes.
    Tweet_Get(); //ツイート取得
    LastTime = millis();
  }
}
//---------------ツイート取得----------------------
void Tweet_Get() {
  uint32_t value_timestamp  = now();
  uint32_t value_nonce      = 1111111111 + value_timestamp;
 
  Serial.println(F("--------------------------"));
  String status_all = "";
  String parameter_str = make_parameter_str(status_all, value_nonce, value_timestamp);
  String sign_base_str = make_sign_base_str(parameter_str);
  String oauth_signature = make_signature(consumer_secret, access_secret, sign_base_str);
  String OAuth_header = make_OAuth_header(oauth_signature, value_nonce, value_timestamp);
 
  Serial.print(F("OAuth_header = "));
  Serial.println(OAuth_header);
  TwitterAPI_HTTP_Request(base_host, OAuth_header, status_all);
   
  Serial.println(F("----------GET Twitter Trends Unicode ( UTF16 )-------------"));
  for(int i=0; i<Display_MaxData; i++){
    Serial.println(unicode_str[i]);
  }
 
  Serial.println(F("----------GET Twitter Trends Unicode ( UTF-8 )-------------"));

  for(int i=0; i<Display_MaxData; i++){
    Serial.println( UTF16toUTF8( unicode_str[i] ) );
    const char* printdata = UTF16toUTF8( unicode_str[i]).c_str();
    misakiPrint(0, i*10, printdata );
  }
}
//----------------HTTP GET Request----------------------
void TwitterAPI_HTTP_Request(const char* base_host, String OAuth_header, String status_all){
  WiFiClientSecure client;
 
  client.setCACert(root_ca);
 
  if (client.connect(base_host, httpsPort)) {
    Serial.print(base_host); Serial.print(F("-------------"));
    Serial.println(F("connected"));
 
    String str01 = String(key_http_method) + " " + String(base_URI) + "?id=" + String(woeid) + " HTTP/1.1\r\n";
    str01 += "Accept-Charset: UTF-8\r\n";
    str01 += "Accept-Language: ja,en\r\n";
    String str02 = "Authorization: " + OAuth_header + "\r\n";
    str02 += "Connection: close\r\n";
    str02 += "Content-Length: 0\r\n";
    str02 += "Content-Type: application/x-www-form-urlencoded\r\n";
    str02 += "Host: " + String(base_host) + "\r\n\r\n";
 
    client.print( str01 );
    client.print( str02 );
 
    Serial.println(F("-------------------- HTTP GET Request Send"));
    Serial.print( str01 );
    Serial.print( str02 );
 
    String res_str = "";
    String name_str = "";
 
    uint16_t from, to;
    uint8_t n_cnt = 0;
    String name_begin_str = "\"name\":\"";
    int16_t name_begin_flag = 0;
    Serial.println(F("--------------------HTTP Response"));
 
    while(client.connected()){
      while (client.available()) {
        res_str = client.readStringUntil('\n');
        Serial.println(res_str);
        if(res_str.indexOf("\r") <= 2){
          Serial.println(F("-------------JSON GET ALL------------"));
          while(client.connected()){
            while(client.available()){
              res_str = client.readStringUntil(',');
              name_begin_flag = res_str.indexOf(name_begin_str);
               
              if( name_begin_flag >= 0){
                from = name_begin_flag + name_begin_str.length();
                to = res_str.length() - 1;
                name_str = res_str.substring(from,to) + '\0';
                Serial.println(name_str);
                name_str.replace("#", ""); //ハッシュタグ消去
 
                if(n_cnt < Display_MaxData){
                  unicode_str[n_cnt] = name_str;
                }
                name_str = "";
                n_cnt++;
                res_str = "";
              }
            }
          }
        }
      }
    }
    client.flush();
    delay(10);
    client.stop();
    delay(10);
    Serial.println(F("--------------------Client Stop"));
  }else {
    // if you didn't get a connection to the server2:
    Serial.println(F("connection failed"));
  }
}
//-----------------------------------------
String make_parameter_str(String status_all, uint32_t value_nonce, uint32_t value_timestamp) {
  String parameter_str = "id=" + woeid;
  parameter_str += "&";
  parameter_str += key_consumer_key;
  parameter_str += "=" ;
  parameter_str += consumer_key;
  parameter_str += "&";
  parameter_str += key_nonce;
  parameter_str += "=";
  parameter_str += value_nonce;
  parameter_str += "&";
  parameter_str += key_signature_method;
  parameter_str += "=";
  parameter_str += value_signature_method;
  parameter_str += "&";
  parameter_str += key_timestamp;
  parameter_str += "=";
  parameter_str += value_timestamp;
  parameter_str += "&";
  parameter_str += key_token;
  parameter_str += "=";
  parameter_str += access_token;
  parameter_str += "&";
  parameter_str += key_version;
  parameter_str += "=";
  parameter_str += value_version;
  Serial.print(F("parameter_str = "));
  Serial.println(parameter_str);
  return parameter_str;
}
//-----------------------------------------
String make_sign_base_str(String parameter_str) {
  String sign_base_str = key_http_method;
  sign_base_str += "&";
  sign_base_str += URLEncode(base_URL);
  sign_base_str += "&";
  sign_base_str += URLEncode(parameter_str.c_str());
  Serial.print(F("sign_base_str = "));
  Serial.println(sign_base_str);
  return sign_base_str;
}
//-----------------------------------------
String make_signature(const char* secret_one, const char* secret_two, String sign_base_str) {
  String signing_key = URLEncode(secret_one);
  signing_key += "&";
  signing_key += URLEncode(secret_two);
  Serial.print(F("signing_key = "));
  Serial.println(signing_key);
 
  unsigned char digestkey[32];
  mbedtls_sha1_context context;
 
  mbedtls_sha1_starts(&context);
  mbedtls_sha1_update(&context, (uint8_t*) signing_key.c_str(), (int)signing_key.length());
  mbedtls_sha1_finish(&context, digestkey);
 
  uint8_t digest[32];
  ssl_hmac_sha1((uint8_t*) sign_base_str.c_str(), (int)sign_base_str.length(), digestkey, SHA1_SIZE, digest);
 
  String oauth_signature = URLEncode(base64::encode(digest, SHA1_SIZE).c_str());
  Serial.print(F("oauth_signature = "));
  Serial.println(oauth_signature);
  return oauth_signature;
}
//-----------------------------------------
String make_OAuth_header(String oauth_signature, uint32_t value_nonce, uint32_t value_timestamp) {
  String OAuth_header = "OAuth ";
  OAuth_header += "id=\"";
  OAuth_header += woeid;
  OAuth_header += "\", ";
  OAuth_header += key_consumer_key;
  OAuth_header += "=\"";
  OAuth_header += consumer_key;
  OAuth_header += "\",";
  OAuth_header += key_nonce;
  OAuth_header += "=\"";
  OAuth_header += value_nonce;
  OAuth_header += "\",";
  OAuth_header += key_signature;
  OAuth_header += "=\"";
  OAuth_header += oauth_signature;
  OAuth_header += "\",";
  OAuth_header += key_signature_method;
  OAuth_header += "=\"";
  OAuth_header += value_signature_method;
  OAuth_header += "\",";
  OAuth_header += key_timestamp;
  OAuth_header += "=\"";
  OAuth_header += value_timestamp;
  OAuth_header += "\",";
  OAuth_header += key_token;
  OAuth_header += "=\"";
  OAuth_header += access_token;
  OAuth_header += "\",";
  OAuth_header += key_version;
  OAuth_header += "=\"";
  OAuth_header += value_version;
  OAuth_header += "\"";
  return OAuth_header;
}
//-----------------------------------------
// Reference: http://hardwarefun.com/tutorials/url-encoding-in-arduino
// modified by chaeplin
String URLEncode(const char* msg) {
  const char *hex = "0123456789ABCDEF";
  String encodedMsg = "";
 
  while (*msg != '\0') {
    if ( ('a' <= *msg && *msg <= 'z')
         || ('A' <= *msg && *msg <= 'Z')
         || ('0' <= *msg && *msg <= '9')
         || *msg  == '-' || *msg == '_' || *msg == '.' || *msg == '~' ) {
      encodedMsg += *msg;
    } else {
      encodedMsg += '%';
      encodedMsg += hex[*msg >> 4];
      encodedMsg += hex[*msg & 0xf];
    }
    msg++;
  }
  return encodedMsg;
}
//-----------------------------------------
//Reference: https://github.com/igrr/axtls-8266/blob/master/crypto/hmac.c
//License axTLS 1.4.9 Copyright (c) 2007-2016, Cameron Rich
void ssl_hmac_sha1(uint8_t *msg, int length, const uint8_t *key, int key_len, unsigned char *digest) {
  mbedtls_sha1_context context;
  uint8_t k_ipad[64];
  uint8_t k_opad[64];
  int i;
 
  memset(k_ipad, 0, sizeof k_ipad);
  memset(k_opad, 0, sizeof k_opad);
  memcpy(k_ipad, key, key_len);
  memcpy(k_opad, key, key_len);
 
  for (i = 0; i < 64; i++)
  {
    k_ipad[i] ^= 0x36;
    k_opad[i] ^= 0x5c;
  }
 
  mbedtls_sha1_starts(&context);
  mbedtls_sha1_update(&context, k_ipad, 64);
  mbedtls_sha1_update(&context, msg, length);
  mbedtls_sha1_finish(&context, digest);
  mbedtls_sha1_starts(&context);
  mbedtls_sha1_update(&context, k_opad, 64);
  mbedtls_sha1_update(&context, digest, SHA1_SIZE);
  mbedtls_sha1_finish(&context, digest);
}
//-------------Unicode ( UTF16 ) to UTF-8 convert-----------------------------------------
String UTF16toUTF8(String str){
  str.replace("\\u","\\");
  str += '\0';
  uint16_t len = str.length();
  char16_t utf16code[len];
 
  int i=0;
  String str4 = "";
  for(int j=0; j<len; j++){
    if(str[j] == 0x5C){ //'\'を消去
      j++;
      for(int k=0; k<4; k++){
        str4 += str[j+k];
      }
      utf16code[i] = strtol(str4.c_str(), NULL, 16); //16進文字列を16進数値に変換
      str4 = "";
      j = j+3;
      i++;
    }else if(str[j] == 0x23){ //'#'を消去
      utf16code[i] = 0xFF03; //全角＃に変換
      i++;
    }else{
      utf16code[i] = (char16_t)str[j];
      i++;
    }
  }
 
  std::u16string u16str(utf16code);
  std::string u8str = utf16_to_utf8(u16str);
  String ret_str = String(u8str.c_str());
  //URLに影響のある特殊文字を全角に変換
  ret_str.replace("+", "＋");
  ret_str.replace("&", "＆");
  ret_str.replace("\\", "￥");
 
  return ret_str;
}
//----------------------------------------------------------------------------------
std::string utf16_to_utf8(std::u16string const& src){
  std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> converter;
  return converter.to_bytes(src);
}
//---------------------------------- NTP Time -----------------------------------------
time_t getNtpTime(){
  while (Udp.parsePacket() > 0) ; // discard any previously received packets
  Serial.println("Transmit NTP Request");
  sendNTPpacket(_NtpServerIP);
  uint32_t beginWait = millis();
  while (millis() - beginWait < 1500) {
    int size = Udp.parsePacket();
    if (size >= NTP_PACKET_SIZE) {
      Serial.println("Receive NTP Response");
      Udp.read(packetBuffer, NTP_PACKET_SIZE);  // read packet into the buffer
      unsigned long secsSince1900;
      // convert four bytes starting at location 40 to a long integer
      secsSince1900 =  (unsigned long)packetBuffer[40] << 24;
      secsSince1900 |= (unsigned long)packetBuffer[41] << 16;
      secsSince1900 |= (unsigned long)packetBuffer[42] << 8;
      secsSince1900 |= (unsigned long)packetBuffer[43];
      return secsSince1900 - 2208988800UL + timeZone * SECS_PER_HOUR;
    }
  }
  Serial.println("No NTP Response :-(");
  return 0; // return 0 if unable to get the time
}
//-------------------------- NTP Time -----------------------------------------
void sendNTPpacket(IPAddress &address){
  memset(packetBuffer, 0, NTP_PACKET_SIZE);
  packetBuffer[0] = 0b11100011;   // LI, Version, Mode
  packetBuffer[1] = 0;     // Stratum, or type of clock
  packetBuffer[2] = 6;     // Polling Interval
  packetBuffer[3] = 0xEC;  // Peer Clock Precision
  packetBuffer[12]  = 49;
  packetBuffer[13]  = 0x4E;
  packetBuffer[14]  = 49;
  packetBuffer[15]  = 52;         
  Udp.beginPacket(address, 123); //NTP requests are to port 123
  Udp.write(packetBuffer, NTP_PACKET_SIZE);
  Udp.endPacket();
}

//-------------------- 日本語の描画 -----------------------------------------
void misakiPrint(int x, int y, const char * pUTF8) {
  int n=0;
  byte buf[40][8];  //320x8ドットのバナー表示パターン
  while(*pUTF8)
    pUTF8 = getFontData(&buf[n++][0], pUTF8);  // フォントデータの取得

  // 文字の描画
  for (byte i=0; i < 8; i++) {
    for (byte j=0; j < n; j++) {
      for (byte k=0; k<8;k++) {
        if(bitRead(buf[j][i],7-k)) {
          M5.Lcd.drawPixel(x + 8*j + k , y + i, TFT_WHITE);
        }
      }
    }
  }
}
