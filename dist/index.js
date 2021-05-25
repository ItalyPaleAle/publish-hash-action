(() => {
  var __create = Object.create;
  var __defProp = Object.defineProperty;
  var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
  var __getOwnPropNames = Object.getOwnPropertyNames;
  var __getProtoOf = Object.getPrototypeOf;
  var __hasOwnProp = Object.prototype.hasOwnProperty;
  var __markAsModule = (target) => __defProp(target, "__esModule", { value: true });
  var __require = (x) => {
    if (typeof require !== "undefined")
      return require(x);
    throw new Error('Dynamic require of "' + x + '" is not supported');
  };
  var __commonJS = (cb, mod) => function __require2() {
    return mod || (0, cb[Object.keys(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
  };
  var __reExport = (target, module, desc) => {
    if (module && typeof module === "object" || typeof module === "function") {
      for (let key of __getOwnPropNames(module))
        if (!__hasOwnProp.call(target, key) && key !== "default")
          __defProp(target, key, { get: () => module[key], enumerable: !(desc = __getOwnPropDesc(module, key)) || desc.enumerable });
    }
    return target;
  };
  var __toModule = (module) => {
    return __reExport(__markAsModule(__defProp(module != null ? __create(__getProtoOf(module)) : {}, "default", module && module.__esModule && "default" in module ? { get: () => module.default, enumerable: true } : { value: module, enumerable: true })), module);
  };

  // node_modules/@actions/core/lib/utils.js
  var require_utils = __commonJS({
    "node_modules/@actions/core/lib/utils.js"(exports) {
      "use strict";
      Object.defineProperty(exports, "__esModule", { value: true });
      exports.toCommandValue = void 0;
      function toCommandValue(input) {
        if (input === null || input === void 0) {
          return "";
        } else if (typeof input === "string" || input instanceof String) {
          return input;
        }
        return JSON.stringify(input);
      }
      exports.toCommandValue = toCommandValue;
    }
  });

  // node_modules/@actions/core/lib/command.js
  var require_command = __commonJS({
    "node_modules/@actions/core/lib/command.js"(exports) {
      "use strict";
      var __createBinding = exports && exports.__createBinding || (Object.create ? function(o, m, k, k2) {
        if (k2 === void 0)
          k2 = k;
        Object.defineProperty(o, k2, { enumerable: true, get: function() {
          return m[k];
        } });
      } : function(o, m, k, k2) {
        if (k2 === void 0)
          k2 = k;
        o[k2] = m[k];
      });
      var __setModuleDefault = exports && exports.__setModuleDefault || (Object.create ? function(o, v) {
        Object.defineProperty(o, "default", { enumerable: true, value: v });
      } : function(o, v) {
        o["default"] = v;
      });
      var __importStar = exports && exports.__importStar || function(mod) {
        if (mod && mod.__esModule)
          return mod;
        var result = {};
        if (mod != null) {
          for (var k in mod)
            if (k !== "default" && Object.hasOwnProperty.call(mod, k))
              __createBinding(result, mod, k);
        }
        __setModuleDefault(result, mod);
        return result;
      };
      Object.defineProperty(exports, "__esModule", { value: true });
      exports.issue = exports.issueCommand = void 0;
      var os = __importStar(__require("os"));
      var utils_1 = require_utils();
      function issueCommand(command, properties, message) {
        const cmd = new Command(command, properties, message);
        process.stdout.write(cmd.toString() + os.EOL);
      }
      exports.issueCommand = issueCommand;
      function issue(name, message = "") {
        issueCommand(name, {}, message);
      }
      exports.issue = issue;
      var CMD_STRING = "::";
      var Command = class {
        constructor(command, properties, message) {
          if (!command) {
            command = "missing.command";
          }
          this.command = command;
          this.properties = properties;
          this.message = message;
        }
        toString() {
          let cmdStr = CMD_STRING + this.command;
          if (this.properties && Object.keys(this.properties).length > 0) {
            cmdStr += " ";
            let first = true;
            for (const key in this.properties) {
              if (this.properties.hasOwnProperty(key)) {
                const val = this.properties[key];
                if (val) {
                  if (first) {
                    first = false;
                  } else {
                    cmdStr += ",";
                  }
                  cmdStr += `${key}=${escapeProperty(val)}`;
                }
              }
            }
          }
          cmdStr += `${CMD_STRING}${escapeData(this.message)}`;
          return cmdStr;
        }
      };
      function escapeData(s) {
        return utils_1.toCommandValue(s).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
      }
      function escapeProperty(s) {
        return utils_1.toCommandValue(s).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A").replace(/:/g, "%3A").replace(/,/g, "%2C");
      }
    }
  });

  // node_modules/@actions/core/lib/file-command.js
  var require_file_command = __commonJS({
    "node_modules/@actions/core/lib/file-command.js"(exports) {
      "use strict";
      var __createBinding = exports && exports.__createBinding || (Object.create ? function(o, m, k, k2) {
        if (k2 === void 0)
          k2 = k;
        Object.defineProperty(o, k2, { enumerable: true, get: function() {
          return m[k];
        } });
      } : function(o, m, k, k2) {
        if (k2 === void 0)
          k2 = k;
        o[k2] = m[k];
      });
      var __setModuleDefault = exports && exports.__setModuleDefault || (Object.create ? function(o, v) {
        Object.defineProperty(o, "default", { enumerable: true, value: v });
      } : function(o, v) {
        o["default"] = v;
      });
      var __importStar = exports && exports.__importStar || function(mod) {
        if (mod && mod.__esModule)
          return mod;
        var result = {};
        if (mod != null) {
          for (var k in mod)
            if (k !== "default" && Object.hasOwnProperty.call(mod, k))
              __createBinding(result, mod, k);
        }
        __setModuleDefault(result, mod);
        return result;
      };
      Object.defineProperty(exports, "__esModule", { value: true });
      exports.issueCommand = void 0;
      var fs = __importStar(__require("fs"));
      var os = __importStar(__require("os"));
      var utils_1 = require_utils();
      function issueCommand(command, message) {
        const filePath = process.env[`GITHUB_${command}`];
        if (!filePath) {
          throw new Error(`Unable to find environment variable for file command ${command}`);
        }
        if (!fs.existsSync(filePath)) {
          throw new Error(`Missing file at path: ${filePath}`);
        }
        fs.appendFileSync(filePath, `${utils_1.toCommandValue(message)}${os.EOL}`, {
          encoding: "utf8"
        });
      }
      exports.issueCommand = issueCommand;
    }
  });

  // node_modules/@actions/core/lib/core.js
  var require_core = __commonJS({
    "node_modules/@actions/core/lib/core.js"(exports) {
      "use strict";
      var __createBinding = exports && exports.__createBinding || (Object.create ? function(o, m, k, k2) {
        if (k2 === void 0)
          k2 = k;
        Object.defineProperty(o, k2, { enumerable: true, get: function() {
          return m[k];
        } });
      } : function(o, m, k, k2) {
        if (k2 === void 0)
          k2 = k;
        o[k2] = m[k];
      });
      var __setModuleDefault = exports && exports.__setModuleDefault || (Object.create ? function(o, v) {
        Object.defineProperty(o, "default", { enumerable: true, value: v });
      } : function(o, v) {
        o["default"] = v;
      });
      var __importStar = exports && exports.__importStar || function(mod) {
        if (mod && mod.__esModule)
          return mod;
        var result = {};
        if (mod != null) {
          for (var k in mod)
            if (k !== "default" && Object.hasOwnProperty.call(mod, k))
              __createBinding(result, mod, k);
        }
        __setModuleDefault(result, mod);
        return result;
      };
      var __awaiter = exports && exports.__awaiter || function(thisArg, _arguments, P, generator) {
        function adopt(value) {
          return value instanceof P ? value : new P(function(resolve) {
            resolve(value);
          });
        }
        return new (P || (P = Promise))(function(resolve, reject) {
          function fulfilled(value) {
            try {
              step(generator.next(value));
            } catch (e) {
              reject(e);
            }
          }
          function rejected(value) {
            try {
              step(generator["throw"](value));
            } catch (e) {
              reject(e);
            }
          }
          function step(result) {
            result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected);
          }
          step((generator = generator.apply(thisArg, _arguments || [])).next());
        });
      };
      Object.defineProperty(exports, "__esModule", { value: true });
      exports.getState = exports.saveState = exports.group = exports.endGroup = exports.startGroup = exports.info = exports.warning = exports.error = exports.debug = exports.isDebug = exports.setFailed = exports.setCommandEcho = exports.setOutput = exports.getBooleanInput = exports.getInput = exports.addPath = exports.setSecret = exports.exportVariable = exports.ExitCode = void 0;
      var command_1 = require_command();
      var file_command_1 = require_file_command();
      var utils_1 = require_utils();
      var os = __importStar(__require("os"));
      var path = __importStar(__require("path"));
      var ExitCode;
      (function(ExitCode2) {
        ExitCode2[ExitCode2["Success"] = 0] = "Success";
        ExitCode2[ExitCode2["Failure"] = 1] = "Failure";
      })(ExitCode = exports.ExitCode || (exports.ExitCode = {}));
      function exportVariable(name, val) {
        const convertedVal = utils_1.toCommandValue(val);
        process.env[name] = convertedVal;
        const filePath = process.env["GITHUB_ENV"] || "";
        if (filePath) {
          const delimiter = "_GitHubActionsFileCommandDelimeter_";
          const commandValue = `${name}<<${delimiter}${os.EOL}${convertedVal}${os.EOL}${delimiter}`;
          file_command_1.issueCommand("ENV", commandValue);
        } else {
          command_1.issueCommand("set-env", { name }, convertedVal);
        }
      }
      exports.exportVariable = exportVariable;
      function setSecret(secret) {
        command_1.issueCommand("add-mask", {}, secret);
      }
      exports.setSecret = setSecret;
      function addPath(inputPath) {
        const filePath = process.env["GITHUB_PATH"] || "";
        if (filePath) {
          file_command_1.issueCommand("PATH", inputPath);
        } else {
          command_1.issueCommand("add-path", {}, inputPath);
        }
        process.env["PATH"] = `${inputPath}${path.delimiter}${process.env["PATH"]}`;
      }
      exports.addPath = addPath;
      function getInput2(name, options) {
        const val = process.env[`INPUT_${name.replace(/ /g, "_").toUpperCase()}`] || "";
        if (options && options.required && !val) {
          throw new Error(`Input required and not supplied: ${name}`);
        }
        if (options && options.trimWhitespace === false) {
          return val;
        }
        return val.trim();
      }
      exports.getInput = getInput2;
      function getBooleanInput(name, options) {
        const trueValue = ["true", "True", "TRUE"];
        const falseValue = ["false", "False", "FALSE"];
        const val = getInput2(name, options);
        if (trueValue.includes(val))
          return true;
        if (falseValue.includes(val))
          return false;
        throw new TypeError(`Input does not meet YAML 1.2 "Core Schema" specification: ${name}
Support boolean input list: \`true | True | TRUE | false | False | FALSE\``);
      }
      exports.getBooleanInput = getBooleanInput;
      function setOutput2(name, value) {
        process.stdout.write(os.EOL);
        command_1.issueCommand("set-output", { name }, value);
      }
      exports.setOutput = setOutput2;
      function setCommandEcho(enabled) {
        command_1.issue("echo", enabled ? "on" : "off");
      }
      exports.setCommandEcho = setCommandEcho;
      function setFailed2(message) {
        process.exitCode = ExitCode.Failure;
        error(message);
      }
      exports.setFailed = setFailed2;
      function isDebug() {
        return process.env["RUNNER_DEBUG"] === "1";
      }
      exports.isDebug = isDebug;
      function debug(message) {
        command_1.issueCommand("debug", {}, message);
      }
      exports.debug = debug;
      function error(message) {
        command_1.issue("error", message instanceof Error ? message.toString() : message);
      }
      exports.error = error;
      function warning(message) {
        command_1.issue("warning", message instanceof Error ? message.toString() : message);
      }
      exports.warning = warning;
      function info(message) {
        process.stdout.write(message + os.EOL);
      }
      exports.info = info;
      function startGroup(name) {
        command_1.issue("group", name);
      }
      exports.startGroup = startGroup;
      function endGroup() {
        command_1.issue("endgroup");
      }
      exports.endGroup = endGroup;
      function group(name, fn) {
        return __awaiter(this, void 0, void 0, function* () {
          startGroup(name);
          let result;
          try {
            result = yield fn();
          } finally {
            endGroup();
          }
          return result;
        });
      }
      exports.group = group;
      function saveState(name, value) {
        command_1.issueCommand("save-state", { name }, value);
      }
      exports.saveState = saveState;
      function getState(name) {
        return process.env[`STATE_${name}`] || "";
      }
      exports.getState = getState;
    }
  });

  // node_modules/oauth/lib/sha1.js
  var require_sha1 = __commonJS({
    "node_modules/oauth/lib/sha1.js"(exports) {
      var b64pad = "=";
      function b64_hmac_sha1(k, d) {
        return rstr2b64(rstr_hmac_sha1(str2rstr_utf8(k), str2rstr_utf8(d)));
      }
      function rstr_hmac_sha1(key, data) {
        var bkey = rstr2binb(key);
        if (bkey.length > 16)
          bkey = binb_sha1(bkey, key.length * 8);
        var ipad = Array(16), opad = Array(16);
        for (var i = 0; i < 16; i++) {
          ipad[i] = bkey[i] ^ 909522486;
          opad[i] = bkey[i] ^ 1549556828;
        }
        var hash = binb_sha1(ipad.concat(rstr2binb(data)), 512 + data.length * 8);
        return binb2rstr(binb_sha1(opad.concat(hash), 512 + 160));
      }
      function rstr2b64(input) {
        try {
          b64pad;
        } catch (e) {
          b64pad = "";
        }
        var tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        var output = "";
        var len = input.length;
        for (var i = 0; i < len; i += 3) {
          var triplet = input.charCodeAt(i) << 16 | (i + 1 < len ? input.charCodeAt(i + 1) << 8 : 0) | (i + 2 < len ? input.charCodeAt(i + 2) : 0);
          for (var j = 0; j < 4; j++) {
            if (i * 8 + j * 6 > input.length * 8)
              output += b64pad;
            else
              output += tab.charAt(triplet >>> 6 * (3 - j) & 63);
          }
        }
        return output;
      }
      function str2rstr_utf8(input) {
        var output = "";
        var i = -1;
        var x, y;
        while (++i < input.length) {
          x = input.charCodeAt(i);
          y = i + 1 < input.length ? input.charCodeAt(i + 1) : 0;
          if (55296 <= x && x <= 56319 && 56320 <= y && y <= 57343) {
            x = 65536 + ((x & 1023) << 10) + (y & 1023);
            i++;
          }
          if (x <= 127)
            output += String.fromCharCode(x);
          else if (x <= 2047)
            output += String.fromCharCode(192 | x >>> 6 & 31, 128 | x & 63);
          else if (x <= 65535)
            output += String.fromCharCode(224 | x >>> 12 & 15, 128 | x >>> 6 & 63, 128 | x & 63);
          else if (x <= 2097151)
            output += String.fromCharCode(240 | x >>> 18 & 7, 128 | x >>> 12 & 63, 128 | x >>> 6 & 63, 128 | x & 63);
        }
        return output;
      }
      function rstr2binb(input) {
        var output = Array(input.length >> 2);
        for (var i = 0; i < output.length; i++)
          output[i] = 0;
        for (var i = 0; i < input.length * 8; i += 8)
          output[i >> 5] |= (input.charCodeAt(i / 8) & 255) << 24 - i % 32;
        return output;
      }
      function binb2rstr(input) {
        var output = "";
        for (var i = 0; i < input.length * 32; i += 8)
          output += String.fromCharCode(input[i >> 5] >>> 24 - i % 32 & 255);
        return output;
      }
      function binb_sha1(x, len) {
        x[len >> 5] |= 128 << 24 - len % 32;
        x[(len + 64 >> 9 << 4) + 15] = len;
        var w = Array(80);
        var a = 1732584193;
        var b = -271733879;
        var c = -1732584194;
        var d = 271733878;
        var e = -1009589776;
        for (var i = 0; i < x.length; i += 16) {
          var olda = a;
          var oldb = b;
          var oldc = c;
          var oldd = d;
          var olde = e;
          for (var j = 0; j < 80; j++) {
            if (j < 16)
              w[j] = x[i + j];
            else
              w[j] = bit_rol(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
            var t = safe_add(safe_add(bit_rol(a, 5), sha1_ft(j, b, c, d)), safe_add(safe_add(e, w[j]), sha1_kt(j)));
            e = d;
            d = c;
            c = bit_rol(b, 30);
            b = a;
            a = t;
          }
          a = safe_add(a, olda);
          b = safe_add(b, oldb);
          c = safe_add(c, oldc);
          d = safe_add(d, oldd);
          e = safe_add(e, olde);
        }
        return Array(a, b, c, d, e);
      }
      function sha1_ft(t, b, c, d) {
        if (t < 20)
          return b & c | ~b & d;
        if (t < 40)
          return b ^ c ^ d;
        if (t < 60)
          return b & c | b & d | c & d;
        return b ^ c ^ d;
      }
      function sha1_kt(t) {
        return t < 20 ? 1518500249 : t < 40 ? 1859775393 : t < 60 ? -1894007588 : -899497514;
      }
      function safe_add(x, y) {
        var lsw = (x & 65535) + (y & 65535);
        var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
        return msw << 16 | lsw & 65535;
      }
      function bit_rol(num, cnt) {
        return num << cnt | num >>> 32 - cnt;
      }
      exports.HMACSHA1 = function(key, data) {
        return b64_hmac_sha1(key, data);
      };
    }
  });

  // node_modules/oauth/lib/_utils.js
  var require_utils2 = __commonJS({
    "node_modules/oauth/lib/_utils.js"(exports, module) {
      module.exports.isAnEarlyCloseHost = function(hostName) {
        return hostName && hostName.match(".*google(apis)?.com$");
      };
    }
  });

  // node_modules/oauth/lib/oauth.js
  var require_oauth = __commonJS({
    "node_modules/oauth/lib/oauth.js"(exports) {
      var crypto = __require("crypto");
      var sha1 = require_sha1();
      var http = __require("http");
      var https = __require("https");
      var URL = __require("url");
      var querystring = __require("querystring");
      var OAuthUtils = require_utils2();
      exports.OAuth = function(requestUrl, accessUrl, consumerKey, consumerSecret, version, authorize_callback, signatureMethod, nonceSize, customHeaders) {
        this._isEcho = false;
        this._requestUrl = requestUrl;
        this._accessUrl = accessUrl;
        this._consumerKey = consumerKey;
        this._consumerSecret = this._encodeData(consumerSecret);
        if (signatureMethod == "RSA-SHA1") {
          this._privateKey = consumerSecret;
        }
        this._version = version;
        if (authorize_callback === void 0) {
          this._authorize_callback = "oob";
        } else {
          this._authorize_callback = authorize_callback;
        }
        if (signatureMethod != "PLAINTEXT" && signatureMethod != "HMAC-SHA1" && signatureMethod != "RSA-SHA1")
          throw new Error("Un-supported signature method: " + signatureMethod);
        this._signatureMethod = signatureMethod;
        this._nonceSize = nonceSize || 32;
        this._headers = customHeaders || {
          "Accept": "*/*",
          "Connection": "close",
          "User-Agent": "Node authentication"
        };
        this._clientOptions = this._defaultClientOptions = {
          "requestTokenHttpMethod": "POST",
          "accessTokenHttpMethod": "POST",
          "followRedirects": true
        };
        this._oauthParameterSeperator = ",";
      };
      exports.OAuthEcho = function(realm, verify_credentials, consumerKey, consumerSecret, version, signatureMethod, nonceSize, customHeaders) {
        this._isEcho = true;
        this._realm = realm;
        this._verifyCredentials = verify_credentials;
        this._consumerKey = consumerKey;
        this._consumerSecret = this._encodeData(consumerSecret);
        if (signatureMethod == "RSA-SHA1") {
          this._privateKey = consumerSecret;
        }
        this._version = version;
        if (signatureMethod != "PLAINTEXT" && signatureMethod != "HMAC-SHA1" && signatureMethod != "RSA-SHA1")
          throw new Error("Un-supported signature method: " + signatureMethod);
        this._signatureMethod = signatureMethod;
        this._nonceSize = nonceSize || 32;
        this._headers = customHeaders || {
          "Accept": "*/*",
          "Connection": "close",
          "User-Agent": "Node authentication"
        };
        this._oauthParameterSeperator = ",";
      };
      exports.OAuthEcho.prototype = exports.OAuth.prototype;
      exports.OAuth.prototype._getTimestamp = function() {
        return Math.floor(new Date().getTime() / 1e3);
      };
      exports.OAuth.prototype._encodeData = function(toEncode) {
        if (toEncode == null || toEncode == "")
          return "";
        else {
          var result = encodeURIComponent(toEncode);
          return result.replace(/\!/g, "%21").replace(/\'/g, "%27").replace(/\(/g, "%28").replace(/\)/g, "%29").replace(/\*/g, "%2A");
        }
      };
      exports.OAuth.prototype._decodeData = function(toDecode) {
        if (toDecode != null) {
          toDecode = toDecode.replace(/\+/g, " ");
        }
        return decodeURIComponent(toDecode);
      };
      exports.OAuth.prototype._getSignature = function(method, url, parameters, tokenSecret) {
        var signatureBase = this._createSignatureBase(method, url, parameters);
        return this._createSignature(signatureBase, tokenSecret);
      };
      exports.OAuth.prototype._normalizeUrl = function(url) {
        var parsedUrl = URL.parse(url, true);
        var port = "";
        if (parsedUrl.port) {
          if (parsedUrl.protocol == "http:" && parsedUrl.port != "80" || parsedUrl.protocol == "https:" && parsedUrl.port != "443") {
            port = ":" + parsedUrl.port;
          }
        }
        if (!parsedUrl.pathname || parsedUrl.pathname == "")
          parsedUrl.pathname = "/";
        return parsedUrl.protocol + "//" + parsedUrl.hostname + port + parsedUrl.pathname;
      };
      exports.OAuth.prototype._isParameterNameAnOAuthParameter = function(parameter) {
        var m = parameter.match("^oauth_");
        if (m && m[0] === "oauth_") {
          return true;
        } else {
          return false;
        }
      };
      exports.OAuth.prototype._buildAuthorizationHeaders = function(orderedParameters) {
        var authHeader = "OAuth ";
        if (this._isEcho) {
          authHeader += 'realm="' + this._realm + '",';
        }
        for (var i = 0; i < orderedParameters.length; i++) {
          if (this._isParameterNameAnOAuthParameter(orderedParameters[i][0])) {
            authHeader += "" + this._encodeData(orderedParameters[i][0]) + '="' + this._encodeData(orderedParameters[i][1]) + '"' + this._oauthParameterSeperator;
          }
        }
        authHeader = authHeader.substring(0, authHeader.length - this._oauthParameterSeperator.length);
        return authHeader;
      };
      exports.OAuth.prototype._makeArrayOfArgumentsHash = function(argumentsHash) {
        var argument_pairs = [];
        for (var key in argumentsHash) {
          if (argumentsHash.hasOwnProperty(key)) {
            var value = argumentsHash[key];
            if (Array.isArray(value)) {
              for (var i = 0; i < value.length; i++) {
                argument_pairs[argument_pairs.length] = [key, value[i]];
              }
            } else {
              argument_pairs[argument_pairs.length] = [key, value];
            }
          }
        }
        return argument_pairs;
      };
      exports.OAuth.prototype._sortRequestParams = function(argument_pairs) {
        argument_pairs.sort(function(a, b) {
          if (a[0] == b[0]) {
            return a[1] < b[1] ? -1 : 1;
          } else
            return a[0] < b[0] ? -1 : 1;
        });
        return argument_pairs;
      };
      exports.OAuth.prototype._normaliseRequestParams = function(args) {
        var argument_pairs = this._makeArrayOfArgumentsHash(args);
        for (var i = 0; i < argument_pairs.length; i++) {
          argument_pairs[i][0] = this._encodeData(argument_pairs[i][0]);
          argument_pairs[i][1] = this._encodeData(argument_pairs[i][1]);
        }
        argument_pairs = this._sortRequestParams(argument_pairs);
        var args = "";
        for (var i = 0; i < argument_pairs.length; i++) {
          args += argument_pairs[i][0];
          args += "=";
          args += argument_pairs[i][1];
          if (i < argument_pairs.length - 1)
            args += "&";
        }
        return args;
      };
      exports.OAuth.prototype._createSignatureBase = function(method, url, parameters) {
        url = this._encodeData(this._normalizeUrl(url));
        parameters = this._encodeData(parameters);
        return method.toUpperCase() + "&" + url + "&" + parameters;
      };
      exports.OAuth.prototype._createSignature = function(signatureBase, tokenSecret) {
        if (tokenSecret === void 0)
          var tokenSecret = "";
        else
          tokenSecret = this._encodeData(tokenSecret);
        var key = this._consumerSecret + "&" + tokenSecret;
        var hash = "";
        if (this._signatureMethod == "PLAINTEXT") {
          hash = key;
        } else if (this._signatureMethod == "RSA-SHA1") {
          key = this._privateKey || "";
          hash = crypto.createSign("RSA-SHA1").update(signatureBase).sign(key, "base64");
        } else {
          if (crypto.Hmac) {
            hash = crypto.createHmac("sha1", key).update(signatureBase).digest("base64");
          } else {
            hash = sha1.HMACSHA1(key, signatureBase);
          }
        }
        return hash;
      };
      exports.OAuth.prototype.NONCE_CHARS = [
        "a",
        "b",
        "c",
        "d",
        "e",
        "f",
        "g",
        "h",
        "i",
        "j",
        "k",
        "l",
        "m",
        "n",
        "o",
        "p",
        "q",
        "r",
        "s",
        "t",
        "u",
        "v",
        "w",
        "x",
        "y",
        "z",
        "A",
        "B",
        "C",
        "D",
        "E",
        "F",
        "G",
        "H",
        "I",
        "J",
        "K",
        "L",
        "M",
        "N",
        "O",
        "P",
        "Q",
        "R",
        "S",
        "T",
        "U",
        "V",
        "W",
        "X",
        "Y",
        "Z",
        "0",
        "1",
        "2",
        "3",
        "4",
        "5",
        "6",
        "7",
        "8",
        "9"
      ];
      exports.OAuth.prototype._getNonce = function(nonceSize) {
        var result = [];
        var chars = this.NONCE_CHARS;
        var char_pos;
        var nonce_chars_length = chars.length;
        for (var i = 0; i < nonceSize; i++) {
          char_pos = Math.floor(Math.random() * nonce_chars_length);
          result[i] = chars[char_pos];
        }
        return result.join("");
      };
      exports.OAuth.prototype._createClient = function(port, hostname, method, path, headers, sslEnabled) {
        var options = {
          host: hostname,
          port,
          path,
          method,
          headers
        };
        var httpModel;
        if (sslEnabled) {
          httpModel = https;
        } else {
          httpModel = http;
        }
        return httpModel.request(options);
      };
      exports.OAuth.prototype._prepareParameters = function(oauth_token, oauth_token_secret, method, url, extra_params) {
        var oauthParameters = {
          "oauth_timestamp": this._getTimestamp(),
          "oauth_nonce": this._getNonce(this._nonceSize),
          "oauth_version": this._version,
          "oauth_signature_method": this._signatureMethod,
          "oauth_consumer_key": this._consumerKey
        };
        if (oauth_token) {
          oauthParameters["oauth_token"] = oauth_token;
        }
        var sig;
        if (this._isEcho) {
          sig = this._getSignature("GET", this._verifyCredentials, this._normaliseRequestParams(oauthParameters), oauth_token_secret);
        } else {
          if (extra_params) {
            for (var key in extra_params) {
              if (extra_params.hasOwnProperty(key))
                oauthParameters[key] = extra_params[key];
            }
          }
          var parsedUrl = URL.parse(url, false);
          if (parsedUrl.query) {
            var key2;
            var extraParameters = querystring.parse(parsedUrl.query);
            for (var key in extraParameters) {
              var value = extraParameters[key];
              if (typeof value == "object") {
                for (key2 in value) {
                  oauthParameters[key + "[" + key2 + "]"] = value[key2];
                }
              } else {
                oauthParameters[key] = value;
              }
            }
          }
          sig = this._getSignature(method, url, this._normaliseRequestParams(oauthParameters), oauth_token_secret);
        }
        var orderedParameters = this._sortRequestParams(this._makeArrayOfArgumentsHash(oauthParameters));
        orderedParameters[orderedParameters.length] = ["oauth_signature", sig];
        return orderedParameters;
      };
      exports.OAuth.prototype._performSecureRequest = function(oauth_token, oauth_token_secret, method, url, extra_params, post_body, post_content_type, callback) {
        var orderedParameters = this._prepareParameters(oauth_token, oauth_token_secret, method, url, extra_params);
        if (!post_content_type) {
          post_content_type = "application/x-www-form-urlencoded";
        }
        var parsedUrl = URL.parse(url, false);
        if (parsedUrl.protocol == "http:" && !parsedUrl.port)
          parsedUrl.port = 80;
        if (parsedUrl.protocol == "https:" && !parsedUrl.port)
          parsedUrl.port = 443;
        var headers = {};
        var authorization = this._buildAuthorizationHeaders(orderedParameters);
        if (this._isEcho) {
          headers["X-Verify-Credentials-Authorization"] = authorization;
        } else {
          headers["Authorization"] = authorization;
        }
        headers["Host"] = parsedUrl.host;
        for (var key in this._headers) {
          if (this._headers.hasOwnProperty(key)) {
            headers[key] = this._headers[key];
          }
        }
        for (var key in extra_params) {
          if (this._isParameterNameAnOAuthParameter(key)) {
            delete extra_params[key];
          }
        }
        if ((method == "POST" || method == "PUT") && (post_body == null && extra_params != null)) {
          post_body = querystring.stringify(extra_params).replace(/\!/g, "%21").replace(/\'/g, "%27").replace(/\(/g, "%28").replace(/\)/g, "%29").replace(/\*/g, "%2A");
        }
        if (post_body) {
          if (Buffer.isBuffer(post_body)) {
            headers["Content-length"] = post_body.length;
          } else {
            headers["Content-length"] = Buffer.byteLength(post_body);
          }
        } else {
          headers["Content-length"] = 0;
        }
        headers["Content-Type"] = post_content_type;
        var path;
        if (!parsedUrl.pathname || parsedUrl.pathname == "")
          parsedUrl.pathname = "/";
        if (parsedUrl.query)
          path = parsedUrl.pathname + "?" + parsedUrl.query;
        else
          path = parsedUrl.pathname;
        var request;
        if (parsedUrl.protocol == "https:") {
          request = this._createClient(parsedUrl.port, parsedUrl.hostname, method, path, headers, true);
        } else {
          request = this._createClient(parsedUrl.port, parsedUrl.hostname, method, path, headers);
        }
        var clientOptions = this._clientOptions;
        if (callback) {
          var data = "";
          var self = this;
          var allowEarlyClose = OAuthUtils.isAnEarlyCloseHost(parsedUrl.hostname);
          var callbackCalled = false;
          var passBackControl = function(response) {
            if (!callbackCalled) {
              callbackCalled = true;
              if (response.statusCode >= 200 && response.statusCode <= 299) {
                callback(null, data, response);
              } else {
                if ((response.statusCode == 301 || response.statusCode == 302) && clientOptions.followRedirects && response.headers && response.headers.location) {
                  self._performSecureRequest(oauth_token, oauth_token_secret, method, response.headers.location, extra_params, post_body, post_content_type, callback);
                } else {
                  callback({ statusCode: response.statusCode, data }, data, response);
                }
              }
            }
          };
          request.on("response", function(response) {
            response.setEncoding("utf8");
            response.on("data", function(chunk) {
              data += chunk;
            });
            response.on("end", function() {
              passBackControl(response);
            });
            response.on("close", function() {
              if (allowEarlyClose) {
                passBackControl(response);
              }
            });
          });
          request.on("error", function(err) {
            if (!callbackCalled) {
              callbackCalled = true;
              callback(err);
            }
          });
          if ((method == "POST" || method == "PUT") && post_body != null && post_body != "") {
            request.write(post_body);
          }
          request.end();
        } else {
          if ((method == "POST" || method == "PUT") && post_body != null && post_body != "") {
            request.write(post_body);
          }
          return request;
        }
        return;
      };
      exports.OAuth.prototype.setClientOptions = function(options) {
        var key, mergedOptions = {}, hasOwnProperty = Object.prototype.hasOwnProperty;
        for (key in this._defaultClientOptions) {
          if (!hasOwnProperty.call(options, key)) {
            mergedOptions[key] = this._defaultClientOptions[key];
          } else {
            mergedOptions[key] = options[key];
          }
        }
        this._clientOptions = mergedOptions;
      };
      exports.OAuth.prototype.getOAuthAccessToken = function(oauth_token, oauth_token_secret, oauth_verifier, callback) {
        var extraParams = {};
        if (typeof oauth_verifier == "function") {
          callback = oauth_verifier;
        } else {
          extraParams.oauth_verifier = oauth_verifier;
        }
        this._performSecureRequest(oauth_token, oauth_token_secret, this._clientOptions.accessTokenHttpMethod, this._accessUrl, extraParams, null, null, function(error, data, response) {
          if (error)
            callback(error);
          else {
            var results = querystring.parse(data);
            var oauth_access_token = results["oauth_token"];
            delete results["oauth_token"];
            var oauth_access_token_secret = results["oauth_token_secret"];
            delete results["oauth_token_secret"];
            callback(null, oauth_access_token, oauth_access_token_secret, results);
          }
        });
      };
      exports.OAuth.prototype.getProtectedResource = function(url, method, oauth_token, oauth_token_secret, callback) {
        this._performSecureRequest(oauth_token, oauth_token_secret, method, url, null, "", null, callback);
      };
      exports.OAuth.prototype.delete = function(url, oauth_token, oauth_token_secret, callback) {
        return this._performSecureRequest(oauth_token, oauth_token_secret, "DELETE", url, null, "", null, callback);
      };
      exports.OAuth.prototype.get = function(url, oauth_token, oauth_token_secret, callback) {
        return this._performSecureRequest(oauth_token, oauth_token_secret, "GET", url, null, "", null, callback);
      };
      exports.OAuth.prototype._putOrPost = function(method, url, oauth_token, oauth_token_secret, post_body, post_content_type, callback) {
        var extra_params = null;
        if (typeof post_content_type == "function") {
          callback = post_content_type;
          post_content_type = null;
        }
        if (typeof post_body != "string" && !Buffer.isBuffer(post_body)) {
          post_content_type = "application/x-www-form-urlencoded";
          extra_params = post_body;
          post_body = null;
        }
        return this._performSecureRequest(oauth_token, oauth_token_secret, method, url, extra_params, post_body, post_content_type, callback);
      };
      exports.OAuth.prototype.put = function(url, oauth_token, oauth_token_secret, post_body, post_content_type, callback) {
        return this._putOrPost("PUT", url, oauth_token, oauth_token_secret, post_body, post_content_type, callback);
      };
      exports.OAuth.prototype.post = function(url, oauth_token, oauth_token_secret, post_body, post_content_type, callback) {
        return this._putOrPost("POST", url, oauth_token, oauth_token_secret, post_body, post_content_type, callback);
      };
      exports.OAuth.prototype.getOAuthRequestToken = function(extraParams, callback) {
        if (typeof extraParams == "function") {
          callback = extraParams;
          extraParams = {};
        }
        if (this._authorize_callback) {
          extraParams["oauth_callback"] = this._authorize_callback;
        }
        this._performSecureRequest(null, null, this._clientOptions.requestTokenHttpMethod, this._requestUrl, extraParams, null, null, function(error, data, response) {
          if (error)
            callback(error);
          else {
            var results = querystring.parse(data);
            var oauth_token = results["oauth_token"];
            var oauth_token_secret = results["oauth_token_secret"];
            delete results["oauth_token"];
            delete results["oauth_token_secret"];
            callback(null, oauth_token, oauth_token_secret, results);
          }
        });
      };
      exports.OAuth.prototype.signUrl = function(url, oauth_token, oauth_token_secret, method) {
        if (method === void 0) {
          var method = "GET";
        }
        var orderedParameters = this._prepareParameters(oauth_token, oauth_token_secret, method, url, {});
        var parsedUrl = URL.parse(url, false);
        var query = "";
        for (var i = 0; i < orderedParameters.length; i++) {
          query += orderedParameters[i][0] + "=" + this._encodeData(orderedParameters[i][1]) + "&";
        }
        query = query.substring(0, query.length - 1);
        return parsedUrl.protocol + "//" + parsedUrl.host + parsedUrl.pathname + "?" + query;
      };
      exports.OAuth.prototype.authHeader = function(url, oauth_token, oauth_token_secret, method) {
        if (method === void 0) {
          var method = "GET";
        }
        var orderedParameters = this._prepareParameters(oauth_token, oauth_token_secret, method, url, {});
        return this._buildAuthorizationHeaders(orderedParameters);
      };
    }
  });

  // node_modules/oauth/lib/oauth2.js
  var require_oauth2 = __commonJS({
    "node_modules/oauth/lib/oauth2.js"(exports) {
      var querystring = __require("querystring");
      var crypto = __require("crypto");
      var https = __require("https");
      var http = __require("http");
      var URL = __require("url");
      var OAuthUtils = require_utils2();
      exports.OAuth2 = function(clientId, clientSecret, baseSite, authorizePath, accessTokenPath, customHeaders) {
        this._clientId = clientId;
        this._clientSecret = clientSecret;
        this._baseSite = baseSite;
        this._authorizeUrl = authorizePath || "/oauth/authorize";
        this._accessTokenUrl = accessTokenPath || "/oauth/access_token";
        this._accessTokenName = "access_token";
        this._authMethod = "Bearer";
        this._customHeaders = customHeaders || {};
        this._useAuthorizationHeaderForGET = false;
        this._agent = void 0;
      };
      exports.OAuth2.prototype.setAgent = function(agent) {
        this._agent = agent;
      };
      exports.OAuth2.prototype.setAccessTokenName = function(name) {
        this._accessTokenName = name;
      };
      exports.OAuth2.prototype.setAuthMethod = function(authMethod) {
        this._authMethod = authMethod;
      };
      exports.OAuth2.prototype.useAuthorizationHeaderforGET = function(useIt) {
        this._useAuthorizationHeaderForGET = useIt;
      };
      exports.OAuth2.prototype._getAccessTokenUrl = function() {
        return this._baseSite + this._accessTokenUrl;
      };
      exports.OAuth2.prototype.buildAuthHeader = function(token) {
        return this._authMethod + " " + token;
      };
      exports.OAuth2.prototype._chooseHttpLibrary = function(parsedUrl) {
        var http_library = https;
        if (parsedUrl.protocol != "https:") {
          http_library = http;
        }
        return http_library;
      };
      exports.OAuth2.prototype._request = function(method, url, headers, post_body, access_token, callback) {
        var parsedUrl = URL.parse(url, true);
        if (parsedUrl.protocol == "https:" && !parsedUrl.port) {
          parsedUrl.port = 443;
        }
        var http_library = this._chooseHttpLibrary(parsedUrl);
        var realHeaders = {};
        for (var key in this._customHeaders) {
          realHeaders[key] = this._customHeaders[key];
        }
        if (headers) {
          for (var key in headers) {
            realHeaders[key] = headers[key];
          }
        }
        realHeaders["Host"] = parsedUrl.host;
        if (!realHeaders["User-Agent"]) {
          realHeaders["User-Agent"] = "Node-oauth";
        }
        if (post_body) {
          if (Buffer.isBuffer(post_body)) {
            realHeaders["Content-Length"] = post_body.length;
          } else {
            realHeaders["Content-Length"] = Buffer.byteLength(post_body);
          }
        } else {
          realHeaders["Content-length"] = 0;
        }
        if (access_token && !("Authorization" in realHeaders)) {
          if (!parsedUrl.query)
            parsedUrl.query = {};
          parsedUrl.query[this._accessTokenName] = access_token;
        }
        var queryStr = querystring.stringify(parsedUrl.query);
        if (queryStr)
          queryStr = "?" + queryStr;
        var options = {
          host: parsedUrl.hostname,
          port: parsedUrl.port,
          path: parsedUrl.pathname + queryStr,
          method,
          headers: realHeaders
        };
        this._executeRequest(http_library, options, post_body, callback);
      };
      exports.OAuth2.prototype._executeRequest = function(http_library, options, post_body, callback) {
        var allowEarlyClose = OAuthUtils.isAnEarlyCloseHost(options.host);
        var callbackCalled = false;
        function passBackControl(response, result2) {
          if (!callbackCalled) {
            callbackCalled = true;
            if (!(response.statusCode >= 200 && response.statusCode <= 299) && response.statusCode != 301 && response.statusCode != 302) {
              callback({ statusCode: response.statusCode, data: result2 });
            } else {
              callback(null, result2, response);
            }
          }
        }
        var result = "";
        if (this._agent) {
          options.agent = this._agent;
        }
        var request = http_library.request(options);
        request.on("response", function(response) {
          response.on("data", function(chunk) {
            result += chunk;
          });
          response.on("close", function(err) {
            if (allowEarlyClose) {
              passBackControl(response, result);
            }
          });
          response.addListener("end", function() {
            passBackControl(response, result);
          });
        });
        request.on("error", function(e) {
          callbackCalled = true;
          callback(e);
        });
        if ((options.method == "POST" || options.method == "PUT") && post_body) {
          request.write(post_body);
        }
        request.end();
      };
      exports.OAuth2.prototype.getAuthorizeUrl = function(params) {
        var params = params || {};
        params["client_id"] = this._clientId;
        return this._baseSite + this._authorizeUrl + "?" + querystring.stringify(params);
      };
      exports.OAuth2.prototype.getOAuthAccessToken = function(code, params, callback) {
        var params = params || {};
        params["client_id"] = this._clientId;
        params["client_secret"] = this._clientSecret;
        var codeParam = params.grant_type === "refresh_token" ? "refresh_token" : "code";
        params[codeParam] = code;
        var post_data = querystring.stringify(params);
        var post_headers = {
          "Content-Type": "application/x-www-form-urlencoded"
        };
        this._request("POST", this._getAccessTokenUrl(), post_headers, post_data, null, function(error, data, response) {
          if (error)
            callback(error);
          else {
            var results;
            try {
              results = JSON.parse(data);
            } catch (e) {
              results = querystring.parse(data);
            }
            var access_token = results["access_token"];
            var refresh_token = results["refresh_token"];
            delete results["refresh_token"];
            callback(null, access_token, refresh_token, results);
          }
        });
      };
      exports.OAuth2.prototype.getProtectedResource = function(url, access_token, callback) {
        this._request("GET", url, {}, "", access_token, callback);
      };
      exports.OAuth2.prototype.get = function(url, access_token, callback) {
        if (this._useAuthorizationHeaderForGET) {
          var headers = { "Authorization": this.buildAuthHeader(access_token) };
          access_token = null;
        } else {
          headers = {};
        }
        this._request("GET", url, headers, "", access_token, callback);
      };
    }
  });

  // node_modules/oauth/index.js
  var require_oauth3 = __commonJS({
    "node_modules/oauth/index.js"(exports) {
      exports.OAuth = require_oauth().OAuth;
      exports.OAuthEcho = require_oauth().OAuthEcho;
      exports.OAuth2 = require_oauth2().OAuth2;
    }
  });

  // node_modules/object-sizeof/byte_size.js
  var require_byte_size = __commonJS({
    "node_modules/object-sizeof/byte_size.js"(exports, module) {
      module.exports = {
        STRING: 2,
        BOOLEAN: 4,
        NUMBER: 8
      };
    }
  });

  // node_modules/object-sizeof/index.js
  var require_object_sizeof = __commonJS({
    "node_modules/object-sizeof/index.js"(exports, module) {
      "use strict";
      var ECMA_SIZES = require_byte_size();
      var Buffer2 = __require("buffer").Buffer;
      function allProperties(obj) {
        const stringProperties = [];
        for (var prop in obj) {
          stringProperties.push(prop);
        }
        if (Object.getOwnPropertySymbols) {
          var symbolProperties = Object.getOwnPropertySymbols(obj);
          Array.prototype.push.apply(stringProperties, symbolProperties);
        }
        return stringProperties;
      }
      function sizeOfObject(seen, object) {
        if (object == null) {
          return 0;
        }
        var bytes = 0;
        var properties = allProperties(object);
        for (var i = 0; i < properties.length; i++) {
          var key = properties[i];
          if (typeof object[key] === "object" && object[key] !== null) {
            if (seen.has(object[key])) {
              continue;
            }
            seen.add(object[key]);
          }
          bytes += getCalculator(seen)(key);
          try {
            bytes += getCalculator(seen)(object[key]);
          } catch (ex) {
            if (ex instanceof RangeError) {
              bytes = 0;
            }
          }
        }
        return bytes;
      }
      function getCalculator(seen) {
        return function calculator(object) {
          if (Buffer2.isBuffer(object)) {
            return object.length;
          }
          var objectType = typeof object;
          switch (objectType) {
            case "string":
              return object.length * ECMA_SIZES.STRING;
            case "boolean":
              return ECMA_SIZES.BOOLEAN;
            case "number":
              return ECMA_SIZES.NUMBER;
            case "symbol":
              const isGlobalSymbol = Symbol.keyFor && Symbol.keyFor(object);
              return isGlobalSymbol ? Symbol.keyFor(object).length * ECMA_SIZES.STRING : (object.toString().length - 8) * ECMA_SIZES.STRING;
            case "object":
              if (Array.isArray(object)) {
                return object.map(getCalculator(seen)).reduce(function(acc, curr) {
                  return acc + curr;
                }, 0);
              } else {
                return sizeOfObject(seen, object);
              }
            default:
              return 0;
          }
        };
      }
      function sizeof(object) {
        return getCalculator(new WeakSet())(object);
      }
      module.exports = sizeof;
    }
  });

  // node_modules/twitter-api-client/dist/base/utils.js
  var require_utils3 = __commonJS({
    "node_modules/twitter-api-client/dist/base/utils.js"(exports) {
      "use strict";
      Object.defineProperty(exports, "__esModule", { value: true });
      exports.parse = exports.formatURL = exports.generateHash = exports.createParams = void 0;
      exports.createParams = function(params, exclude) {
        if (!params) {
          return "";
        }
        var searchParams = new URLSearchParams();
        Object.entries(params).forEach(function(_a) {
          var key = _a[0], value = _a[1];
          if (exclude === null || exclude === void 0 ? void 0 : exclude.includes(key)) {
            return;
          }
          if (typeof value === "boolean") {
            searchParams.append(key, value ? "true" : "false");
            return;
          }
          searchParams.append(key, "" + value);
        });
        return "?" + searchParams.toString();
      };
      exports.generateHash = function(token) {
        var seed = 56852;
        var h1 = 3735928559 ^ seed;
        var h2 = 1103547991 ^ seed;
        for (var i = 0, ch = void 0; i < token.length; i++) {
          ch = token.charCodeAt(i);
          h1 = Math.imul(h1 ^ ch, 2654435761);
          h2 = Math.imul(h2 ^ ch, 1597334677);
        }
        h1 = Math.imul(h1 ^ h1 >>> 16, 2246822507) ^ Math.imul(h2 ^ h2 >>> 13, 3266489909);
        h2 = Math.imul(h2 ^ h2 >>> 16, 2246822507) ^ Math.imul(h1 ^ h1 >>> 13, 3266489909);
        return (4294967296 * (2097151 & h2) + (h1 >>> 0)).toString(16);
      };
      exports.formatURL = function(url) {
        return url.replace(/!/g, "%21").replace(/'/g, "%27").replace(/\(/g, "%28").replace(/\)/g, "%29").replace(/\*/g, "%2A");
      };
      exports.parse = function(body) {
        var parsed = void 0;
        try {
          parsed = JSON.parse(body);
        } catch (error) {
        }
        if (parsed) {
          return parsed;
        }
        try {
          parsed = JSON.parse('{"' + decodeURI(body).replace(/"/g, '\\"').replace(/&/g, '","').replace(/=/g, '":"') + '"}');
        } catch (error) {
        }
        if (parsed) {
          return parsed;
        }
        return body;
      };
    }
  });

  // node_modules/twitter-api-client/dist/base/Cache.js
  var require_Cache = __commonJS({
    "node_modules/twitter-api-client/dist/base/Cache.js"(exports) {
      "use strict";
      var __importDefault = exports && exports.__importDefault || function(mod) {
        return mod && mod.__esModule ? mod : { "default": mod };
      };
      Object.defineProperty(exports, "__esModule", { value: true });
      var object_sizeof_1 = __importDefault(require_object_sizeof());
      var utils_1 = require_utils3();
      var windowSessionStorage = typeof sessionStorage !== "undefined" ? sessionStorage : void 0;
      var Cache = function() {
        function Cache2(ttl, maxByteSize) {
          if (ttl === void 0) {
            ttl = 360;
          }
          if (maxByteSize === void 0) {
            maxByteSize = 16e6;
          }
          this.cache = new Map();
          this.ttl = ttl;
          this.maxByteSize = maxByteSize;
        }
        Cache2.prototype.add = function(query, data) {
          var hashedKey = utils_1.generateHash(query);
          var added = new Date();
          var entry = {
            added,
            data
          };
          this.cache.set(hashedKey, entry);
          windowSessionStorage === null || windowSessionStorage === void 0 ? void 0 : windowSessionStorage.setItem(hashedKey, JSON.stringify(entry));
          this.clearSpace();
        };
        Cache2.prototype.get = function(query) {
          var hashedKey = utils_1.generateHash(query);
          if (!this.has(query)) {
            return null;
          }
          try {
            var entry = this.cache.get(hashedKey);
            if (!entry) {
              var sessionData = windowSessionStorage === null || windowSessionStorage === void 0 ? void 0 : windowSessionStorage.getItem(hashedKey);
              if (!sessionData) {
                return;
              }
              return JSON.parse(sessionData);
            }
            return entry.data;
          } catch (error) {
            return null;
          }
        };
        Cache2.prototype.has = function(query) {
          var hashedKey = utils_1.generateHash(query);
          try {
            var now = new Date();
            var data = this.cache.get(hashedKey);
            if (!data) {
              var sessionData = windowSessionStorage === null || windowSessionStorage === void 0 ? void 0 : windowSessionStorage.getItem(hashedKey);
              if (!sessionData) {
                return false;
              }
              data = JSON.parse(sessionData);
            }
            var entryAdded = new Date(data.added);
            if (now.getTime() > entryAdded.getTime() + this.ttl * 1e3) {
              windowSessionStorage === null || windowSessionStorage === void 0 ? void 0 : windowSessionStorage.removeItem(hashedKey);
              this.cache.delete(hashedKey);
              return false;
            }
            return true;
          } catch (error) {
            return false;
          }
        };
        Cache2.prototype.clearSpace = function() {
          var cacheArray = Array.from(this.cache);
          if (object_sizeof_1.default(cacheArray) < this.maxByteSize) {
            return;
          }
          cacheArray.sort(function(a, b) {
            return a[1].added.getTime() - b[1].added.getTime();
          });
          var reducedCacheArray = cacheArray.slice(1);
          this.cache = new Map(reducedCacheArray);
          this.clearSpace();
        };
        return Cache2;
      }();
      exports.default = Cache;
    }
  });

  // node_modules/twitter-api-client/dist/base/Transport.js
  var require_Transport = __commonJS({
    "node_modules/twitter-api-client/dist/base/Transport.js"(exports) {
      "use strict";
      var __awaiter = exports && exports.__awaiter || function(thisArg, _arguments, P, generator) {
        function adopt(value) {
          return value instanceof P ? value : new P(function(resolve) {
            resolve(value);
          });
        }
        return new (P || (P = Promise))(function(resolve, reject) {
          function fulfilled(value) {
            try {
              step(generator.next(value));
            } catch (e) {
              reject(e);
            }
          }
          function rejected(value) {
            try {
              step(generator["throw"](value));
            } catch (e) {
              reject(e);
            }
          }
          function step(result) {
            result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected);
          }
          step((generator = generator.apply(thisArg, _arguments || [])).next());
        });
      };
      var __generator = exports && exports.__generator || function(thisArg, body) {
        var _ = { label: 0, sent: function() {
          if (t[0] & 1)
            throw t[1];
          return t[1];
        }, trys: [], ops: [] }, f, y, t, g;
        return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() {
          return this;
        }), g;
        function verb(n) {
          return function(v) {
            return step([n, v]);
          };
        }
        function step(op) {
          if (f)
            throw new TypeError("Generator is already executing.");
          while (_)
            try {
              if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done)
                return t;
              if (y = 0, t)
                op = [op[0] & 2, t.value];
              switch (op[0]) {
                case 0:
                case 1:
                  t = op;
                  break;
                case 4:
                  _.label++;
                  return { value: op[1], done: false };
                case 5:
                  _.label++;
                  y = op[1];
                  op = [0];
                  continue;
                case 7:
                  op = _.ops.pop();
                  _.trys.pop();
                  continue;
                default:
                  if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) {
                    _ = 0;
                    continue;
                  }
                  if (op[0] === 3 && (!t || op[1] > t[0] && op[1] < t[3])) {
                    _.label = op[1];
                    break;
                  }
                  if (op[0] === 6 && _.label < t[1]) {
                    _.label = t[1];
                    t = op;
                    break;
                  }
                  if (t && _.label < t[2]) {
                    _.label = t[2];
                    _.ops.push(op);
                    break;
                  }
                  if (t[2])
                    _.ops.pop();
                  _.trys.pop();
                  continue;
              }
              op = body.call(thisArg, _);
            } catch (e) {
              op = [6, e];
              y = 0;
            } finally {
              f = t = 0;
            }
          if (op[0] & 5)
            throw op[1];
          return { value: op[0] ? op[1] : void 0, done: true };
        }
      };
      var __rest = exports && exports.__rest || function(s, e) {
        var t = {};
        for (var p in s)
          if (Object.prototype.hasOwnProperty.call(s, p) && e.indexOf(p) < 0)
            t[p] = s[p];
        if (s != null && typeof Object.getOwnPropertySymbols === "function")
          for (var i = 0, p = Object.getOwnPropertySymbols(s); i < p.length; i++) {
            if (e.indexOf(p[i]) < 0 && Object.prototype.propertyIsEnumerable.call(s, p[i]))
              t[p[i]] = s[p[i]];
          }
        return t;
      };
      var __importDefault = exports && exports.__importDefault || function(mod) {
        return mod && mod.__esModule ? mod : { "default": mod };
      };
      Object.defineProperty(exports, "__esModule", { value: true });
      var oauth_1 = __importDefault(require_oauth3());
      var Cache_1 = __importDefault(require_Cache());
      var utils_1 = require_utils3();
      var Transport = function() {
        function Transport2(options) {
          this.credentials = options;
          this.oauth = new oauth_1.default.OAuth("https://api.twitter.com/oauth/request_token", "https://api.twitter.com/oauth/access_token", this.credentials.apiKey, this.credentials.apiSecret, "1.0A", null, "HMAC-SHA1");
          if (!(options === null || options === void 0 ? void 0 : options.disableCache)) {
            this.cache = new Cache_1.default(options === null || options === void 0 ? void 0 : options.ttl, options.maxByteSize);
          }
        }
        Transport2.prototype.updateOptions = function(options) {
          var _this = this;
          var apiKey = options.apiKey, apiSecret = options.apiSecret, rest = __rest(options, ["apiKey", "apiSecret"]);
          var cleanOptions = rest;
          Object.keys(cleanOptions).forEach(function(key) {
            if (cleanOptions[key]) {
              _this.credentials[key] = cleanOptions[key];
            }
          });
        };
        Transport2.prototype.doDeleteRequest = function(url) {
          return __awaiter(this, void 0, void 0, function() {
            var _this = this;
            return __generator(this, function(_a) {
              if (!this.oauth) {
                throw Error("Unable to make request. Authentication has not been established");
              }
              return [2, new Promise(function(resolve, reject) {
                if (!_this.credentials.accessToken || !_this.credentials.accessTokenSecret) {
                  reject(new Error("Unable to make request. Authentication has not been established"));
                  return;
                }
                var formattedUrl = utils_1.formatURL(url);
                _this.oauth.delete(formattedUrl, _this.credentials.accessToken, _this.credentials.accessTokenSecret, function(err, body) {
                  if (err) {
                    reject(err);
                    return;
                  }
                  if (!body) {
                    resolve({});
                    return;
                  }
                  var result = utils_1.parse(body.toString());
                  resolve(result);
                });
              })];
            });
          });
        };
        Transport2.prototype.doGetRequest = function(url) {
          var _a;
          return __awaiter(this, void 0, void 0, function() {
            var _this = this;
            return __generator(this, function(_b) {
              if (!this.oauth) {
                throw Error("Unable to make request. Authentication has not been established");
              }
              if ((_a = this.cache) === null || _a === void 0 ? void 0 : _a.has(url)) {
                return [2, this.cache.get(url)];
              }
              return [2, new Promise(function(resolve, reject) {
                if (!_this.credentials.accessToken || !_this.credentials.accessTokenSecret) {
                  reject(new Error("Unable to make request. Authentication has not been established"));
                  return;
                }
                var formattedUrl = utils_1.formatURL(url);
                _this.oauth.get(formattedUrl, _this.credentials.accessToken, _this.credentials.accessTokenSecret, function(err, body) {
                  var _a2;
                  if (err) {
                    reject(err);
                    return;
                  }
                  if (!body) {
                    resolve({});
                    return;
                  }
                  var result = utils_1.parse(body.toString());
                  (_a2 = _this.cache) === null || _a2 === void 0 ? void 0 : _a2.add(url, result);
                  resolve(result);
                });
              })];
            });
          });
        };
        Transport2.prototype.doPostRequest = function(url, body, contentType) {
          if (contentType === void 0) {
            contentType = "application/x-www-form-urlencoded";
          }
          return __awaiter(this, void 0, void 0, function() {
            var _this = this;
            return __generator(this, function(_a) {
              if (!this.oauth || !this.credentials) {
                throw Error("Unable to make request. Authentication has not been established");
              }
              return [2, new Promise(function(resolve, reject) {
                if (!_this.credentials.accessToken || !_this.credentials.accessTokenSecret) {
                  reject(new Error("Unable to make request. Authentication has not been established"));
                  return;
                }
                var formattedUrl = utils_1.formatURL(url);
                var formattedBody = contentType === "application/json" ? JSON.stringify(body) : body;
                _this.oauth.post(formattedUrl, _this.credentials.accessToken, _this.credentials.accessTokenSecret, formattedBody, contentType, function(err, body2) {
                  if (err) {
                    reject(err);
                    return;
                  }
                  if (!body2) {
                    resolve({});
                    return;
                  }
                  var result = utils_1.parse(body2.toString());
                  resolve(result);
                });
              })];
            });
          });
        };
        return Transport2;
      }();
      exports.default = Transport;
    }
  });

  // node_modules/twitter-api-client/dist/clients/BasicsClient.js
  var require_BasicsClient = __commonJS({
    "node_modules/twitter-api-client/dist/clients/BasicsClient.js"(exports) {
      "use strict";
      var __awaiter = exports && exports.__awaiter || function(thisArg, _arguments, P, generator) {
        function adopt(value) {
          return value instanceof P ? value : new P(function(resolve) {
            resolve(value);
          });
        }
        return new (P || (P = Promise))(function(resolve, reject) {
          function fulfilled(value) {
            try {
              step(generator.next(value));
            } catch (e) {
              reject(e);
            }
          }
          function rejected(value) {
            try {
              step(generator["throw"](value));
            } catch (e) {
              reject(e);
            }
          }
          function step(result) {
            result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected);
          }
          step((generator = generator.apply(thisArg, _arguments || [])).next());
        });
      };
      var __generator = exports && exports.__generator || function(thisArg, body) {
        var _ = { label: 0, sent: function() {
          if (t[0] & 1)
            throw t[1];
          return t[1];
        }, trys: [], ops: [] }, f, y, t, g;
        return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() {
          return this;
        }), g;
        function verb(n) {
          return function(v) {
            return step([n, v]);
          };
        }
        function step(op) {
          if (f)
            throw new TypeError("Generator is already executing.");
          while (_)
            try {
              if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done)
                return t;
              if (y = 0, t)
                op = [op[0] & 2, t.value];
              switch (op[0]) {
                case 0:
                case 1:
                  t = op;
                  break;
                case 4:
                  _.label++;
                  return { value: op[1], done: false };
                case 5:
                  _.label++;
                  y = op[1];
                  op = [0];
                  continue;
                case 7:
                  op = _.ops.pop();
                  _.trys.pop();
                  continue;
                default:
                  if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) {
                    _ = 0;
                    continue;
                  }
                  if (op[0] === 3 && (!t || op[1] > t[0] && op[1] < t[3])) {
                    _.label = op[1];
                    break;
                  }
                  if (op[0] === 6 && _.label < t[1]) {
                    _.label = t[1];
                    t = op;
                    break;
                  }
                  if (t && _.label < t[2]) {
                    _.label = t[2];
                    _.ops.push(op);
                    break;
                  }
                  if (t[2])
                    _.ops.pop();
                  _.trys.pop();
                  continue;
              }
              op = body.call(thisArg, _);
            } catch (e) {
              op = [6, e];
              y = 0;
            } finally {
              f = t = 0;
            }
          if (op[0] & 5)
            throw op[1];
          return { value: op[0] ? op[1] : void 0, done: true };
        }
      };
      Object.defineProperty(exports, "__esModule", { value: true });
      var utils_1 = require_utils3();
      var BasicsClient = function() {
        function BasicsClient2(transport) {
          if (!transport) {
            throw Error("Transport class needs to be provided.");
          }
          this.transport = transport;
        }
        BasicsClient2.prototype.oauthAuthenticate = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters);
                  return [4, this.transport.doGetRequest("https://api.twitter.com/oauth/authenticate" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        BasicsClient2.prototype.oauthAuthorize = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters);
                  return [4, this.transport.doGetRequest("https://api.twitter.com/oauth/authorize" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        BasicsClient2.prototype.oauthAccessToken = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://api.twitter.com/oauth/access_token", parameters)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        BasicsClient2.prototype.oauthInvalidateToken = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://api.twitter.com/1.1/oauth/invalidate_token", parameters)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        BasicsClient2.prototype.oauth2InvalidateToken = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://api.twitter.com/oauth2/invalidate_token", parameters)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        BasicsClient2.prototype.oauthRequestToken = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://api.twitter.com/oauth/request_token", parameters)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        BasicsClient2.prototype.oauth2Token = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://api.twitter.com/oauth2/token", parameters)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        return BasicsClient2;
      }();
      exports.default = BasicsClient;
    }
  });

  // node_modules/twitter-api-client/dist/clients/AccountsAndUsersClient.js
  var require_AccountsAndUsersClient = __commonJS({
    "node_modules/twitter-api-client/dist/clients/AccountsAndUsersClient.js"(exports) {
      "use strict";
      var __awaiter = exports && exports.__awaiter || function(thisArg, _arguments, P, generator) {
        function adopt(value) {
          return value instanceof P ? value : new P(function(resolve) {
            resolve(value);
          });
        }
        return new (P || (P = Promise))(function(resolve, reject) {
          function fulfilled(value) {
            try {
              step(generator.next(value));
            } catch (e) {
              reject(e);
            }
          }
          function rejected(value) {
            try {
              step(generator["throw"](value));
            } catch (e) {
              reject(e);
            }
          }
          function step(result) {
            result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected);
          }
          step((generator = generator.apply(thisArg, _arguments || [])).next());
        });
      };
      var __generator = exports && exports.__generator || function(thisArg, body) {
        var _ = { label: 0, sent: function() {
          if (t[0] & 1)
            throw t[1];
          return t[1];
        }, trys: [], ops: [] }, f, y, t, g;
        return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() {
          return this;
        }), g;
        function verb(n) {
          return function(v) {
            return step([n, v]);
          };
        }
        function step(op) {
          if (f)
            throw new TypeError("Generator is already executing.");
          while (_)
            try {
              if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done)
                return t;
              if (y = 0, t)
                op = [op[0] & 2, t.value];
              switch (op[0]) {
                case 0:
                case 1:
                  t = op;
                  break;
                case 4:
                  _.label++;
                  return { value: op[1], done: false };
                case 5:
                  _.label++;
                  y = op[1];
                  op = [0];
                  continue;
                case 7:
                  op = _.ops.pop();
                  _.trys.pop();
                  continue;
                default:
                  if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) {
                    _ = 0;
                    continue;
                  }
                  if (op[0] === 3 && (!t || op[1] > t[0] && op[1] < t[3])) {
                    _.label = op[1];
                    break;
                  }
                  if (op[0] === 6 && _.label < t[1]) {
                    _.label = t[1];
                    t = op;
                    break;
                  }
                  if (t && _.label < t[2]) {
                    _.label = t[2];
                    _.ops.push(op);
                    break;
                  }
                  if (t[2])
                    _.ops.pop();
                  _.trys.pop();
                  continue;
              }
              op = body.call(thisArg, _);
            } catch (e) {
              op = [6, e];
              y = 0;
            } finally {
              f = t = 0;
            }
          if (op[0] & 5)
            throw op[1];
          return { value: op[0] ? op[1] : void 0, done: true };
        }
      };
      Object.defineProperty(exports, "__esModule", { value: true });
      var utils_1 = require_utils3();
      var AccountsAndUsersClient = function() {
        function AccountsAndUsersClient2(transport) {
          if (!transport) {
            throw Error("Transport class needs to be provided.");
          }
          this.transport = transport;
        }
        AccountsAndUsersClient2.prototype.listsList = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters);
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/lists/list.json" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.listsMembers = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters);
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/lists/members.json" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.listsMembersShow = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters);
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/lists/members/show.json" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.listsMemberships = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters);
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/lists/memberships.json" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.listsOwnerships = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters);
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/lists/ownerships.json" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.listsShow = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters);
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/lists/show.json" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.listsStatuses = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters);
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/lists/statuses.json" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.listsSubscribers = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters);
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/lists/subscribers.json" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.listsSubscribersShow = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters);
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/lists/subscribers/show.json" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.listsSubscriptions = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters);
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/lists/subscriptions.json" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.listsCreate = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://api.twitter.com/1.1/lists/create.json", parameters)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.listsDestroy = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://api.twitter.com/1.1/lists/destroy.json", parameters)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.listsMembersCreate = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://api.twitter.com/1.1/lists/members/create.json", parameters)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.listsMembersCreateAll = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://api.twitter.com/1.1/lists/members/create_all.json", parameters)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.listsMembersDestroy = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://api.twitter.com/1.1/lists/members/destroy.json", parameters)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.listsMembersDestroyAll = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://api.twitter.com/1.1/lists/members/destroy_all.json", parameters)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.listsSubscribersCreate = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://api.twitter.com/1.1/lists/subscribers/create.json", parameters)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.listsSubscribersDestroy = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://api.twitter.com/1.1/lists/subscribers/destroy.json", parameters)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.listsUpdate = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://api.twitter.com/1.1/lists/update.json", parameters)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.followersIds = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters);
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/followers/ids.json" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.followersList = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters);
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/followers/list.json" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.friendsIds = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters);
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/friends/ids.json" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.friendsList = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters);
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/friends/list.json" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.friendshipsIncoming = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters);
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/friendships/incoming.json" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.friendshipsLookup = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters);
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/friendships/lookup.json" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.friendshipsNoRetweetsIds = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters);
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/friendships/no_retweets/ids.json" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.friendshipsOutgoing = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters);
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/friendships/outgoing.format" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.friendshipsShow = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters);
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/friendships/show.json" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.usersLookup = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters);
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/users/lookup.json" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.usersSearch = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters);
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/users/search.json" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.usersShow = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters);
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/users/show.json" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.friendshipsCreate = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://api.twitter.com/1.1/friendships/create.json", parameters)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.friendshipsDestroy = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://api.twitter.com/1.1/friendships/destroy.json", parameters)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.friendshipsUpdate = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://api.twitter.com/1.1/friendships/update.json", parameters)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.accountSettings = function() {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/account/settings.json")];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.accountVerifyCredentials = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters);
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/account/verify_credentials.json" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.savedSearchesList = function() {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/saved_searches/list.json")];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.savedSearchesShowById = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters, ["id"]);
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/saved_searches/show/" + parameters.id + ".json" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.usersProfileBanner = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters);
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/users/profile_banner.json" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.accountRemoveProfileBanner = function() {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://api.twitter.com/1.1/account/remove_profile_banner.json")];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.accountUpdateProfile = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://api.twitter.com/1.1/account/update_profile.json", parameters)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.accountUpdateProfileBackgroundImageRetired = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://api.twitter.com/1.1/account/update_profile_background_image.json", parameters)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.accountUpdateProfileBanner = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://api.twitter.com/1.1/account/update_profile_banner.json", parameters)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.accountUpdateProfileImage = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://api.twitter.com/1.1/account/update_profile_image.json", parameters)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.savedSearchesCreate = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://api.twitter.com/1.1/saved_searches/create.json", parameters)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.savedSearchesDestroyById = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://api.twitter.com/1.1/saved_searches/destroy/" + parameters.id + ".json", parameters)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.blocksIds = function() {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/blocks/ids.json")];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.blocksList = function() {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/blocks/list.json")];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.mutesUsersIds = function() {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/mutes/users/ids.json")];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.mutesUsersList = function() {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/mutes/users/list.json")];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.blocksCreate = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://api.twitter.com/1.1/blocks/create.json", parameters)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.mutesUsersCreate = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://api.twitter.com/1.1/mutes/users/create.json", parameters)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.mutesUsersDestroy = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://api.twitter.com/1.1/mutes/users/destroy.json", parameters)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        AccountsAndUsersClient2.prototype.usersReportSpam = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://api.twitter.com/1.1/users/report_spam.json", parameters)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        return AccountsAndUsersClient2;
      }();
      exports.default = AccountsAndUsersClient;
    }
  });

  // node_modules/twitter-api-client/dist/clients/TweetsClient.js
  var require_TweetsClient = __commonJS({
    "node_modules/twitter-api-client/dist/clients/TweetsClient.js"(exports) {
      "use strict";
      var __awaiter = exports && exports.__awaiter || function(thisArg, _arguments, P, generator) {
        function adopt(value) {
          return value instanceof P ? value : new P(function(resolve) {
            resolve(value);
          });
        }
        return new (P || (P = Promise))(function(resolve, reject) {
          function fulfilled(value) {
            try {
              step(generator.next(value));
            } catch (e) {
              reject(e);
            }
          }
          function rejected(value) {
            try {
              step(generator["throw"](value));
            } catch (e) {
              reject(e);
            }
          }
          function step(result) {
            result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected);
          }
          step((generator = generator.apply(thisArg, _arguments || [])).next());
        });
      };
      var __generator = exports && exports.__generator || function(thisArg, body) {
        var _ = { label: 0, sent: function() {
          if (t[0] & 1)
            throw t[1];
          return t[1];
        }, trys: [], ops: [] }, f, y, t, g;
        return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() {
          return this;
        }), g;
        function verb(n) {
          return function(v) {
            return step([n, v]);
          };
        }
        function step(op) {
          if (f)
            throw new TypeError("Generator is already executing.");
          while (_)
            try {
              if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done)
                return t;
              if (y = 0, t)
                op = [op[0] & 2, t.value];
              switch (op[0]) {
                case 0:
                case 1:
                  t = op;
                  break;
                case 4:
                  _.label++;
                  return { value: op[1], done: false };
                case 5:
                  _.label++;
                  y = op[1];
                  op = [0];
                  continue;
                case 7:
                  op = _.ops.pop();
                  _.trys.pop();
                  continue;
                default:
                  if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) {
                    _ = 0;
                    continue;
                  }
                  if (op[0] === 3 && (!t || op[1] > t[0] && op[1] < t[3])) {
                    _.label = op[1];
                    break;
                  }
                  if (op[0] === 6 && _.label < t[1]) {
                    _.label = t[1];
                    t = op;
                    break;
                  }
                  if (t && _.label < t[2]) {
                    _.label = t[2];
                    _.ops.push(op);
                    break;
                  }
                  if (t[2])
                    _.ops.pop();
                  _.trys.pop();
                  continue;
              }
              op = body.call(thisArg, _);
            } catch (e) {
              op = [6, e];
              y = 0;
            } finally {
              f = t = 0;
            }
          if (op[0] & 5)
            throw op[1];
          return { value: op[0] ? op[1] : void 0, done: true };
        }
      };
      Object.defineProperty(exports, "__esModule", { value: true });
      var utils_1 = require_utils3();
      var TweetsClient = function() {
        function TweetsClient2(transport) {
          if (!transport) {
            throw Error("Transport class needs to be provided.");
          }
          this.transport = transport;
        }
        TweetsClient2.prototype.collectionsEntries = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters);
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/collections/entries.json" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        TweetsClient2.prototype.collectionsList = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters);
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/collections/list.json" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        TweetsClient2.prototype.collectionsShow = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters);
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/collections/show.json" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        TweetsClient2.prototype.collectionsCreate = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://api.twitter.com/1.1/collections/create.json", parameters)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        TweetsClient2.prototype.collectionsDestroy = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://api.twitter.com/1.1/collections/destroy.json", parameters)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        TweetsClient2.prototype.collectionsEntriesAdd = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://api.twitter.com/1.1/collections/entries/add.json", parameters)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        TweetsClient2.prototype.collectionsEntriesCurate = function() {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://api.twitter.com/1.1/collections/entries/curate.json")];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        TweetsClient2.prototype.collectionsEntriesMove = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://api.twitter.com/1.1/collections/entries/move.json", parameters)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        TweetsClient2.prototype.collectionsEntriesRemove = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://api.twitter.com/1.1/collections/entries/remove.json", parameters)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        TweetsClient2.prototype.collectionsUpdate = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://api.twitter.com/1.1/collections/update.json", parameters)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        TweetsClient2.prototype.statusesHomeTimeline = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters);
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/statuses/home_timeline.json" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        TweetsClient2.prototype.statusesMentionsTimeline = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters);
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/statuses/mentions_timeline.json" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        TweetsClient2.prototype.statusesUserTimeline = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters);
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/statuses/user_timeline.json" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        TweetsClient2.prototype.favoritesList = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters);
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/favorites/list.json" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        TweetsClient2.prototype.statusesLookup = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters);
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/statuses/lookup.json" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        TweetsClient2.prototype.statusesRetweetersIds = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters);
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/statuses/retweeters/ids.json" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        TweetsClient2.prototype.statusesRetweetsById = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters, ["id"]);
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/statuses/retweets/" + parameters.id + ".json" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        TweetsClient2.prototype.statusesRetweetsOfMe = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters);
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/statuses/retweets_of_me.json" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        TweetsClient2.prototype.statusesShow = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters);
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/statuses/show.json" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        TweetsClient2.prototype.favoritesCreate = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://api.twitter.com/1.1/favorites/create.json", parameters)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        TweetsClient2.prototype.favoritesDestroy = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://api.twitter.com/1.1/favorites/destroy.json", parameters)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        TweetsClient2.prototype.statusesDestroyById = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://api.twitter.com/1.1/statuses/destroy/" + parameters.id + ".json", parameters)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        TweetsClient2.prototype.statusesOembed = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters);
                  return [4, this.transport.doGetRequest("https://publish.twitter.com/oembed" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        TweetsClient2.prototype.statusesRetweetById = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://api.twitter.com/1.1/statuses/retweet/" + parameters.id + ".json", parameters)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        TweetsClient2.prototype.statusesUnretweetById = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://api.twitter.com/1.1/statuses/unretweet/" + parameters.id + ".json", parameters)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        TweetsClient2.prototype.statusesUpdate = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://api.twitter.com/1.1/statuses/update.json", parameters)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        TweetsClient2.prototype.search = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters);
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/search/tweets.json" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        return TweetsClient2;
      }();
      exports.default = TweetsClient;
    }
  });

  // node_modules/twitter-api-client/dist/clients/DirectMessagesClient.js
  var require_DirectMessagesClient = __commonJS({
    "node_modules/twitter-api-client/dist/clients/DirectMessagesClient.js"(exports) {
      "use strict";
      var __awaiter = exports && exports.__awaiter || function(thisArg, _arguments, P, generator) {
        function adopt(value) {
          return value instanceof P ? value : new P(function(resolve) {
            resolve(value);
          });
        }
        return new (P || (P = Promise))(function(resolve, reject) {
          function fulfilled(value) {
            try {
              step(generator.next(value));
            } catch (e) {
              reject(e);
            }
          }
          function rejected(value) {
            try {
              step(generator["throw"](value));
            } catch (e) {
              reject(e);
            }
          }
          function step(result) {
            result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected);
          }
          step((generator = generator.apply(thisArg, _arguments || [])).next());
        });
      };
      var __generator = exports && exports.__generator || function(thisArg, body) {
        var _ = { label: 0, sent: function() {
          if (t[0] & 1)
            throw t[1];
          return t[1];
        }, trys: [], ops: [] }, f, y, t, g;
        return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() {
          return this;
        }), g;
        function verb(n) {
          return function(v) {
            return step([n, v]);
          };
        }
        function step(op) {
          if (f)
            throw new TypeError("Generator is already executing.");
          while (_)
            try {
              if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done)
                return t;
              if (y = 0, t)
                op = [op[0] & 2, t.value];
              switch (op[0]) {
                case 0:
                case 1:
                  t = op;
                  break;
                case 4:
                  _.label++;
                  return { value: op[1], done: false };
                case 5:
                  _.label++;
                  y = op[1];
                  op = [0];
                  continue;
                case 7:
                  op = _.ops.pop();
                  _.trys.pop();
                  continue;
                default:
                  if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) {
                    _ = 0;
                    continue;
                  }
                  if (op[0] === 3 && (!t || op[1] > t[0] && op[1] < t[3])) {
                    _.label = op[1];
                    break;
                  }
                  if (op[0] === 6 && _.label < t[1]) {
                    _.label = t[1];
                    t = op;
                    break;
                  }
                  if (t && _.label < t[2]) {
                    _.label = t[2];
                    _.ops.push(op);
                    break;
                  }
                  if (t[2])
                    _.ops.pop();
                  _.trys.pop();
                  continue;
              }
              op = body.call(thisArg, _);
            } catch (e) {
              op = [6, e];
              y = 0;
            } finally {
              f = t = 0;
            }
          if (op[0] & 5)
            throw op[1];
          return { value: op[0] ? op[1] : void 0, done: true };
        }
      };
      Object.defineProperty(exports, "__esModule", { value: true });
      var utils_1 = require_utils3();
      var DirectMessagesClient = function() {
        function DirectMessagesClient2(transport) {
          if (!transport) {
            throw Error("Transport class needs to be provided.");
          }
          this.transport = transport;
        }
        DirectMessagesClient2.prototype.customProfilesById = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters, ["id"]);
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/custom_profiles/" + parameters.id + ".json" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        DirectMessagesClient2.prototype.eventsDestroy = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters);
                  return [4, this.transport.doDeleteRequest("https://api.twitter.com/1.1/direct_messages/events/destroy.json" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        DirectMessagesClient2.prototype.eventsShow = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters);
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/direct_messages/events/show.json" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        DirectMessagesClient2.prototype.eventsNew = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://api.twitter.com/1.1/direct_messages/events/new.json", parameters, "application/json")];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        DirectMessagesClient2.prototype.indicateTyping = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://api.twitter.com/1.1/direct_messages/indicate_typing.json", parameters)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        DirectMessagesClient2.prototype.welcomeMessagesRulesShow = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters);
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/direct_messages/welcome_messages/rules/show.json" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        DirectMessagesClient2.prototype.welcomeMessagesShow = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters);
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/direct_messages/welcome_messages/show.json" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        DirectMessagesClient2.prototype.welcomeMessagesNew = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://api.twitter.com/1.1/direct_messages/welcome_messages/new.json", parameters, "application/json")];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        DirectMessagesClient2.prototype.welcomeMessagesRulesNew = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://api.twitter.com/1.1/direct_messages/welcome_messages/rules/new.json", parameters, "application/json")];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        DirectMessagesClient2.prototype.welcomeMessagesList = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters);
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/direct_messages/welcome_messages/list.json" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        DirectMessagesClient2.prototype.welcomeMessagesDestroy = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters);
                  return [4, this.transport.doDeleteRequest("https://api.twitter.com/1.1/direct_messages/welcome_messages/destroy.json" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        DirectMessagesClient2.prototype.welcomeMessagesRulesDestroy = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters);
                  return [4, this.transport.doDeleteRequest("https://api.twitter.com/1.1/direct_messages/welcome_messages/rules/destroy.json" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        return DirectMessagesClient2;
      }();
      exports.default = DirectMessagesClient;
    }
  });

  // node_modules/twitter-api-client/dist/clients/MediaClient.js
  var require_MediaClient = __commonJS({
    "node_modules/twitter-api-client/dist/clients/MediaClient.js"(exports) {
      "use strict";
      var __awaiter = exports && exports.__awaiter || function(thisArg, _arguments, P, generator) {
        function adopt(value) {
          return value instanceof P ? value : new P(function(resolve) {
            resolve(value);
          });
        }
        return new (P || (P = Promise))(function(resolve, reject) {
          function fulfilled(value) {
            try {
              step(generator.next(value));
            } catch (e) {
              reject(e);
            }
          }
          function rejected(value) {
            try {
              step(generator["throw"](value));
            } catch (e) {
              reject(e);
            }
          }
          function step(result) {
            result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected);
          }
          step((generator = generator.apply(thisArg, _arguments || [])).next());
        });
      };
      var __generator = exports && exports.__generator || function(thisArg, body) {
        var _ = { label: 0, sent: function() {
          if (t[0] & 1)
            throw t[1];
          return t[1];
        }, trys: [], ops: [] }, f, y, t, g;
        return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() {
          return this;
        }), g;
        function verb(n) {
          return function(v) {
            return step([n, v]);
          };
        }
        function step(op) {
          if (f)
            throw new TypeError("Generator is already executing.");
          while (_)
            try {
              if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done)
                return t;
              if (y = 0, t)
                op = [op[0] & 2, t.value];
              switch (op[0]) {
                case 0:
                case 1:
                  t = op;
                  break;
                case 4:
                  _.label++;
                  return { value: op[1], done: false };
                case 5:
                  _.label++;
                  y = op[1];
                  op = [0];
                  continue;
                case 7:
                  op = _.ops.pop();
                  _.trys.pop();
                  continue;
                default:
                  if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) {
                    _ = 0;
                    continue;
                  }
                  if (op[0] === 3 && (!t || op[1] > t[0] && op[1] < t[3])) {
                    _.label = op[1];
                    break;
                  }
                  if (op[0] === 6 && _.label < t[1]) {
                    _.label = t[1];
                    t = op;
                    break;
                  }
                  if (t && _.label < t[2]) {
                    _.label = t[2];
                    _.ops.push(op);
                    break;
                  }
                  if (t[2])
                    _.ops.pop();
                  _.trys.pop();
                  continue;
              }
              op = body.call(thisArg, _);
            } catch (e) {
              op = [6, e];
              y = 0;
            } finally {
              f = t = 0;
            }
          if (op[0] & 5)
            throw op[1];
          return { value: op[0] ? op[1] : void 0, done: true };
        }
      };
      Object.defineProperty(exports, "__esModule", { value: true });
      var utils_1 = require_utils3();
      var MediaClient = function() {
        function MediaClient2(transport) {
          if (!transport) {
            throw Error("Transport class needs to be provided.");
          }
          this.transport = transport;
        }
        MediaClient2.prototype.mediaUploadInit = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://upload.twitter.com/1.1/media/upload.json", parameters)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        MediaClient2.prototype.mediaUploadAppend = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://upload.twitter.com/1.1/media/upload.json", parameters)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        MediaClient2.prototype.mediaUploadStatus = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters);
                  return [4, this.transport.doGetRequest("https://upload.twitter.com/1.1/media/upload.json" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        MediaClient2.prototype.mediaUploadFinalize = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://upload.twitter.com/1.1/media/upload.json", parameters)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        MediaClient2.prototype.mediaUpload = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://upload.twitter.com/1.1/media/upload.json", parameters)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        MediaClient2.prototype.mediaMetadataCreate = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://upload.twitter.com/1.1/media/metadata/create.json", parameters, "application/json")];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        MediaClient2.prototype.mediaSubtitlesDelete = function() {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://upload.twitter.com/1.1/media/subtitles/delete.json")];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        MediaClient2.prototype.mediaSubtitlesCreate = function() {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doPostRequest("https://upload.twitter.com/1.1/media/subtitles/create.json")];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        return MediaClient2;
      }();
      exports.default = MediaClient;
    }
  });

  // node_modules/twitter-api-client/dist/clients/TrendsClient.js
  var require_TrendsClient = __commonJS({
    "node_modules/twitter-api-client/dist/clients/TrendsClient.js"(exports) {
      "use strict";
      var __awaiter = exports && exports.__awaiter || function(thisArg, _arguments, P, generator) {
        function adopt(value) {
          return value instanceof P ? value : new P(function(resolve) {
            resolve(value);
          });
        }
        return new (P || (P = Promise))(function(resolve, reject) {
          function fulfilled(value) {
            try {
              step(generator.next(value));
            } catch (e) {
              reject(e);
            }
          }
          function rejected(value) {
            try {
              step(generator["throw"](value));
            } catch (e) {
              reject(e);
            }
          }
          function step(result) {
            result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected);
          }
          step((generator = generator.apply(thisArg, _arguments || [])).next());
        });
      };
      var __generator = exports && exports.__generator || function(thisArg, body) {
        var _ = { label: 0, sent: function() {
          if (t[0] & 1)
            throw t[1];
          return t[1];
        }, trys: [], ops: [] }, f, y, t, g;
        return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() {
          return this;
        }), g;
        function verb(n) {
          return function(v) {
            return step([n, v]);
          };
        }
        function step(op) {
          if (f)
            throw new TypeError("Generator is already executing.");
          while (_)
            try {
              if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done)
                return t;
              if (y = 0, t)
                op = [op[0] & 2, t.value];
              switch (op[0]) {
                case 0:
                case 1:
                  t = op;
                  break;
                case 4:
                  _.label++;
                  return { value: op[1], done: false };
                case 5:
                  _.label++;
                  y = op[1];
                  op = [0];
                  continue;
                case 7:
                  op = _.ops.pop();
                  _.trys.pop();
                  continue;
                default:
                  if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) {
                    _ = 0;
                    continue;
                  }
                  if (op[0] === 3 && (!t || op[1] > t[0] && op[1] < t[3])) {
                    _.label = op[1];
                    break;
                  }
                  if (op[0] === 6 && _.label < t[1]) {
                    _.label = t[1];
                    t = op;
                    break;
                  }
                  if (t && _.label < t[2]) {
                    _.label = t[2];
                    _.ops.push(op);
                    break;
                  }
                  if (t[2])
                    _.ops.pop();
                  _.trys.pop();
                  continue;
              }
              op = body.call(thisArg, _);
            } catch (e) {
              op = [6, e];
              y = 0;
            } finally {
              f = t = 0;
            }
          if (op[0] & 5)
            throw op[1];
          return { value: op[0] ? op[1] : void 0, done: true };
        }
      };
      Object.defineProperty(exports, "__esModule", { value: true });
      var utils_1 = require_utils3();
      var TrendsClient = function() {
        function TrendsClient2(transport) {
          if (!transport) {
            throw Error("Transport class needs to be provided.");
          }
          this.transport = transport;
        }
        TrendsClient2.prototype.trendsAvailable = function() {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/trends/available.json")];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        TrendsClient2.prototype.trendsClosest = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters);
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/trends/closest.json" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        TrendsClient2.prototype.trendsPlace = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters);
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/trends/place.json" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        return TrendsClient2;
      }();
      exports.default = TrendsClient;
    }
  });

  // node_modules/twitter-api-client/dist/clients/GeoClient.js
  var require_GeoClient = __commonJS({
    "node_modules/twitter-api-client/dist/clients/GeoClient.js"(exports) {
      "use strict";
      var __awaiter = exports && exports.__awaiter || function(thisArg, _arguments, P, generator) {
        function adopt(value) {
          return value instanceof P ? value : new P(function(resolve) {
            resolve(value);
          });
        }
        return new (P || (P = Promise))(function(resolve, reject) {
          function fulfilled(value) {
            try {
              step(generator.next(value));
            } catch (e) {
              reject(e);
            }
          }
          function rejected(value) {
            try {
              step(generator["throw"](value));
            } catch (e) {
              reject(e);
            }
          }
          function step(result) {
            result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected);
          }
          step((generator = generator.apply(thisArg, _arguments || [])).next());
        });
      };
      var __generator = exports && exports.__generator || function(thisArg, body) {
        var _ = { label: 0, sent: function() {
          if (t[0] & 1)
            throw t[1];
          return t[1];
        }, trys: [], ops: [] }, f, y, t, g;
        return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() {
          return this;
        }), g;
        function verb(n) {
          return function(v) {
            return step([n, v]);
          };
        }
        function step(op) {
          if (f)
            throw new TypeError("Generator is already executing.");
          while (_)
            try {
              if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done)
                return t;
              if (y = 0, t)
                op = [op[0] & 2, t.value];
              switch (op[0]) {
                case 0:
                case 1:
                  t = op;
                  break;
                case 4:
                  _.label++;
                  return { value: op[1], done: false };
                case 5:
                  _.label++;
                  y = op[1];
                  op = [0];
                  continue;
                case 7:
                  op = _.ops.pop();
                  _.trys.pop();
                  continue;
                default:
                  if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) {
                    _ = 0;
                    continue;
                  }
                  if (op[0] === 3 && (!t || op[1] > t[0] && op[1] < t[3])) {
                    _.label = op[1];
                    break;
                  }
                  if (op[0] === 6 && _.label < t[1]) {
                    _.label = t[1];
                    t = op;
                    break;
                  }
                  if (t && _.label < t[2]) {
                    _.label = t[2];
                    _.ops.push(op);
                    break;
                  }
                  if (t[2])
                    _.ops.pop();
                  _.trys.pop();
                  continue;
              }
              op = body.call(thisArg, _);
            } catch (e) {
              op = [6, e];
              y = 0;
            } finally {
              f = t = 0;
            }
          if (op[0] & 5)
            throw op[1];
          return { value: op[0] ? op[1] : void 0, done: true };
        }
      };
      Object.defineProperty(exports, "__esModule", { value: true });
      var utils_1 = require_utils3();
      var GeoClient = function() {
        function GeoClient2(transport) {
          if (!transport) {
            throw Error("Transport class needs to be provided.");
          }
          this.transport = transport;
        }
        GeoClient2.prototype.geoIdByPlaceId = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters, ["place_id"]);
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/geo/id/" + parameters.place_id + ".json" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        GeoClient2.prototype.geoReverseGeocode = function() {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/geo/reverse_geocode.json")];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        GeoClient2.prototype.geoSearch = function() {
          return __awaiter(this, void 0, void 0, function() {
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  return [4, this.transport.doGetRequest("https://api.twitter.com/1.1/geo/search.json")];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        return GeoClient2;
      }();
      exports.default = GeoClient;
    }
  });

  // node_modules/twitter-api-client/dist/clients/MetricsClient.js
  var require_MetricsClient = __commonJS({
    "node_modules/twitter-api-client/dist/clients/MetricsClient.js"(exports) {
      "use strict";
      var __awaiter = exports && exports.__awaiter || function(thisArg, _arguments, P, generator) {
        function adopt(value) {
          return value instanceof P ? value : new P(function(resolve) {
            resolve(value);
          });
        }
        return new (P || (P = Promise))(function(resolve, reject) {
          function fulfilled(value) {
            try {
              step(generator.next(value));
            } catch (e) {
              reject(e);
            }
          }
          function rejected(value) {
            try {
              step(generator["throw"](value));
            } catch (e) {
              reject(e);
            }
          }
          function step(result) {
            result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected);
          }
          step((generator = generator.apply(thisArg, _arguments || [])).next());
        });
      };
      var __generator = exports && exports.__generator || function(thisArg, body) {
        var _ = { label: 0, sent: function() {
          if (t[0] & 1)
            throw t[1];
          return t[1];
        }, trys: [], ops: [] }, f, y, t, g;
        return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() {
          return this;
        }), g;
        function verb(n) {
          return function(v) {
            return step([n, v]);
          };
        }
        function step(op) {
          if (f)
            throw new TypeError("Generator is already executing.");
          while (_)
            try {
              if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done)
                return t;
              if (y = 0, t)
                op = [op[0] & 2, t.value];
              switch (op[0]) {
                case 0:
                case 1:
                  t = op;
                  break;
                case 4:
                  _.label++;
                  return { value: op[1], done: false };
                case 5:
                  _.label++;
                  y = op[1];
                  op = [0];
                  continue;
                case 7:
                  op = _.ops.pop();
                  _.trys.pop();
                  continue;
                default:
                  if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) {
                    _ = 0;
                    continue;
                  }
                  if (op[0] === 3 && (!t || op[1] > t[0] && op[1] < t[3])) {
                    _.label = op[1];
                    break;
                  }
                  if (op[0] === 6 && _.label < t[1]) {
                    _.label = t[1];
                    t = op;
                    break;
                  }
                  if (t && _.label < t[2]) {
                    _.label = t[2];
                    _.ops.push(op);
                    break;
                  }
                  if (t[2])
                    _.ops.pop();
                  _.trys.pop();
                  continue;
              }
              op = body.call(thisArg, _);
            } catch (e) {
              op = [6, e];
              y = 0;
            } finally {
              f = t = 0;
            }
          if (op[0] & 5)
            throw op[1];
          return { value: op[0] ? op[1] : void 0, done: true };
        }
      };
      Object.defineProperty(exports, "__esModule", { value: true });
      var utils_1 = require_utils3();
      var MetricsClient = function() {
        function MetricsClient2(transport) {
          if (!transport) {
            throw Error("Transport class needs to be provided.");
          }
          this.transport = transport;
        }
        MetricsClient2.prototype.tweets = function(parameters) {
          return __awaiter(this, void 0, void 0, function() {
            var params;
            return __generator(this, function(_a) {
              switch (_a.label) {
                case 0:
                  params = utils_1.createParams(parameters);
                  return [4, this.transport.doGetRequest("https://api.twitter.com/2/tweets" + params)];
                case 1:
                  return [2, _a.sent()];
              }
            });
          });
        };
        return MetricsClient2;
      }();
      exports.default = MetricsClient;
    }
  });

  // node_modules/twitter-api-client/dist/index.js
  var require_dist = __commonJS({
    "node_modules/twitter-api-client/dist/index.js"(exports) {
      "use strict";
      var __importDefault = exports && exports.__importDefault || function(mod) {
        return mod && mod.__esModule ? mod : { "default": mod };
      };
      Object.defineProperty(exports, "__esModule", { value: true });
      exports.TwitterClient = void 0;
      var Transport_1 = __importDefault(require_Transport());
      var BasicsClient_1 = __importDefault(require_BasicsClient());
      var AccountsAndUsersClient_1 = __importDefault(require_AccountsAndUsersClient());
      var TweetsClient_1 = __importDefault(require_TweetsClient());
      var DirectMessagesClient_1 = __importDefault(require_DirectMessagesClient());
      var MediaClient_1 = __importDefault(require_MediaClient());
      var TrendsClient_1 = __importDefault(require_TrendsClient());
      var GeoClient_1 = __importDefault(require_GeoClient());
      var MetricsClient_1 = __importDefault(require_MetricsClient());
      var TwitterClient2 = function() {
        function TwitterClient3(options) {
          if (!options.apiKey) {
            throw Error("API KEY needs to be provided.");
          }
          if (!options.apiSecret) {
            throw Error("API SECRET needs to be provided.");
          }
          if (!options.accessToken) {
            throw Error("ACCESS TOKEN needs to be provided.");
          }
          if (!options.accessTokenSecret) {
            throw Error("ACCESS TOKEN SECRET needs to be provided.");
          }
          this.transport = new Transport_1.default(options);
        }
        Object.defineProperty(TwitterClient3.prototype, "basics", {
          get: function() {
            if (!this.basicsClient) {
              this.basicsClient = new BasicsClient_1.default(this.transport);
            }
            return this.basicsClient;
          },
          enumerable: false,
          configurable: true
        });
        Object.defineProperty(TwitterClient3.prototype, "accountsAndUsers", {
          get: function() {
            if (!this.accountsAndUsersClient) {
              this.accountsAndUsersClient = new AccountsAndUsersClient_1.default(this.transport);
            }
            return this.accountsAndUsersClient;
          },
          enumerable: false,
          configurable: true
        });
        Object.defineProperty(TwitterClient3.prototype, "tweets", {
          get: function() {
            if (!this.tweetsClient) {
              this.tweetsClient = new TweetsClient_1.default(this.transport);
            }
            return this.tweetsClient;
          },
          enumerable: false,
          configurable: true
        });
        Object.defineProperty(TwitterClient3.prototype, "directMessages", {
          get: function() {
            if (!this.directMessagesClient) {
              this.directMessagesClient = new DirectMessagesClient_1.default(this.transport);
            }
            return this.directMessagesClient;
          },
          enumerable: false,
          configurable: true
        });
        Object.defineProperty(TwitterClient3.prototype, "media", {
          get: function() {
            if (!this.mediaClient) {
              this.mediaClient = new MediaClient_1.default(this.transport);
            }
            return this.mediaClient;
          },
          enumerable: false,
          configurable: true
        });
        Object.defineProperty(TwitterClient3.prototype, "trends", {
          get: function() {
            if (!this.trendsClient) {
              this.trendsClient = new TrendsClient_1.default(this.transport);
            }
            return this.trendsClient;
          },
          enumerable: false,
          configurable: true
        });
        Object.defineProperty(TwitterClient3.prototype, "geo", {
          get: function() {
            if (!this.geoClient) {
              this.geoClient = new GeoClient_1.default(this.transport);
            }
            return this.geoClient;
          },
          enumerable: false,
          configurable: true
        });
        Object.defineProperty(TwitterClient3.prototype, "metrics", {
          get: function() {
            if (!this.metricsClient) {
              this.metricsClient = new MetricsClient_1.default(this.transport);
            }
            return this.metricsClient;
          },
          enumerable: false,
          configurable: true
        });
        return TwitterClient3;
      }();
      exports.TwitterClient = TwitterClient2;
    }
  });

  // src/index.ts
  var import_core = __toModule(require_core());
  var import_twitter_api_client = __toModule(require_dist());
  var import_crypto = __toModule(__require("crypto"));
  var import_fs = __toModule(__require("fs"));
  (async () => {
    try {
      const twitterUrl = await new Worker().Start();
      console.log(twitterUrl);
    } catch (err) {
      (0, import_core.setFailed)(err.message || err);
    }
  })();
  var Worker = class {
    constructor() {
      this.file = this.getRequiredInput("file");
      this.twitterClient = new import_twitter_api_client.TwitterClient({
        apiKey: this.getRequiredInput("consumer-key"),
        apiSecret: this.getRequiredInput("consumer-secret"),
        accessToken: this.getRequiredInput("access-token"),
        accessTokenSecret: this.getRequiredInput("access-token-secret")
      });
    }
    async Start() {
      const hash = await this.hashFile(this.file);
      const res = await this.twitterClient.tweets.statusesUpdate({
        status: "Hash is " + hash
      });
      console.log(res);
      const tweetUrl = "https://twitter.com/" + res.user.name + "/status/" + res.id_str;
      (0, import_core.setOutput)("tweet-id", res.id_str);
      (0, import_core.setOutput)("tweet-url", tweetUrl);
      return tweetUrl;
    }
    hashFile(file) {
      const read = (0, import_fs.createReadStream)(file);
      return new Promise((resolve, reject) => {
        const hash = (0, import_crypto.createHash)("sha256");
        read.on("error", (err) => {
          reject(err);
        });
        read.on("end", () => {
          resolve(hash.digest("hex"));
        });
        read.pipe(hash);
      });
    }
    getRequiredInput(name) {
      const val = (0, import_core.getInput)(name);
      if (!val) {
        throw Error("Input " + name + " is required");
      }
      return val;
    }
  };
})();
