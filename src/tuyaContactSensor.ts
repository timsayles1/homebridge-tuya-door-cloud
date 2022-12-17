import hmacSHA256 from 'crypto-js/hmac-sha256';
import axios, {AxiosInstance} from 'axios';
import { TuyaDoorPlatform } from './platform';

export class TuyaApi {
  private readonly secret: string;
  private readonly client_id: string;
  private lastToken: number;
  private access_token: string;
  private tokValidity: number;
  private timestamp: number;
  private nonce: number;
  private signStr: string;
  private api: AxiosInstance;
  constructor(private readonly platform: TuyaDoorPlatform) {
    this.secret = this.platform.config.options.secret_id;
    this.client_id = this.platform.config.options.access_id;
    this.lastToken = 0;
    this.access_token = '';
    this.nonce = '';
    this.timestamp = new Date().getTime();
    this.signStr = '';
    this.tokValidity = 7200; //by default a token is valid for 2h or 7200s
    this.api = axios.create({
      baseURL: this.platform.config.options.cloudCode,
      headers: {
        'sign_method': 'HMAC-SHA256',
        'client_id': this.client_id,
      },
    });
    const xurl = '/v1.0/token?grant_type=1';
    const query = 'grant_type=1';
    const mode = '';
    const httpMethod = 'GET';
    const signMap = stringToSign(this.query, this.mode, this.httpMethod, this.secret, this.xurl);
    const urlStr = signMap["url"];
    const signStr = signMap["signUrl"];
    const sign = this.calcSign(this.client_id, this.access_token, this.timestamp, this.nonce, this.signStr, this.secret);
    this.api.get(this.xurl, {
      headers: {
        'sign': sign.sign,
        't': sign.timestamp,
      },
    }).then((res) => {
      this.tokValidity = res.data.result.expire_time;
      this.lastToken = sign.timestamp;
      this.access_token = res.data.result.access_token;
    });
  }

  calcSign(clientId,access_token,timestamp,nonce,signStr,secret){
    const str = clientId + access_token + timestamp + nonce + signStr;
    const hash = HmacSHA256(str, secret);
    const hashInBase64 = hash.toString();
    const signUp = hashInBase64.toUpperCase();
    return {
      sign: signUp,
      timestamp: timestamp
    }   
  }

  function stringToSign(query, mode, method, secret,xurl){
    const burl = this.platform.config.options.cloudCode;
    var url = burl + xurl;
    var sha256 = "";
    var headersStr = "";
    const headers = this.api.headers;
    var map = {}
    var arr = []
    var bodyStr = ""
    if(query){
        toJsonObj(query, arr, map)
    }
    arr = arr.sort()
    arr.forEach(function(item){
            url += item + "=" + map[item] + "&"
    })
    if (url.length > 0 ) {
        url = url.substring(0, url.length-1)
        url = "/" + pm.request.url.path.join("/") + "?" + url
    } else {
        url = "/" + pm.request.url.path.join("/") 
    }
    
    if (headers.has("Signature-Headers") && headers.get("Signature-Headers")) {
        var signHeaderStr = headers.get("Signature-Headers")
        const signHeaderKeys = signHeaderStr.split(":")
        signHeaderKeys.forEach(function(item){
            var val = ""
            if (pm.request.headers.get(item)) {
                val = pm.request.headers.get(item)
            }
            headersStr += item + ":" + val + "\n"
        })
    }
    var map = {}
    map["signUrl"] = method + "\n" + sha256 + "\n" + headersStr + "\n" + url
    map["url"] = url
    return map
  }
  
 async getToken() {
    const timestamp = new Date().getTime();
    if (timestamp - this.lastToken > this.tokValidity || this.access_token === undefined) {
      this.platform.log.debug('Generating new token');
      const access_token = '';
      const xurl = '/v1.0/token?grant_type=1';
      const query = 'grant_type=1';
      const mode = '';
      const httpMethod = 'GET';
      const signMap = stringToSign(this.query, this.mode, this.httpMethod, this.secret, this.xurl);
      const urlStr = signMap["url"];
      const signStr = signMap["signUrl"];
      const sign = this.calcSign(this.client_id, this.access_token, this.timestamp, this.nonce, this.signStr, this.secret);
      this.platform.log.debug('Token: ' + sign.sign + ' Time: ' + sign.timestamp);
      return this.api.get(this.xurl, {
        headers: {
          'sign': sign.sign,
          't': sign.timestamp,
        },
      }).then((res) => {
        this.tokValidity = res.data.result.expire_time;
        this.lastToken = timestamp;
        this.access_token = res.data.result.access_token;
      });
    } else {
      this.platform.log.debug('Valid token already here: ', this.access_token);
    }
  }

  async getDoorSensorStatus(device_id) {
    await this.getToken();
    const xurl = '/v1.0/iot-03/devices/'+ device_id;
    const query = '';
    const mode = '';
    const httpMethod = 'GET';
    const signMap = stringToSign(this.query, this.mode, this.httpMethod, this.secret, this.xurl);
    const urlStr = signMap["url"];
    const signStr = signMap["signUrl"];
    const sign = this.calcSign(this.client_id, this.access_token, this.timestamp, this.nonce, this.signStr, this.secret);
    return this.api.get('/v1.0/iot-03/devices/' + device_id, {
      headers: {
        'sign': sign.sign,
        't': sign.timestamp,
        'access_token': this.access_token,
      },
    }).then((res) => res.data.result.status[0].value ? 100 : 0);
  }
}
