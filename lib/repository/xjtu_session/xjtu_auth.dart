// Copyright 2026 XJTU fork authors.
// SPDX-License-Identifier: MPL-2.0

// 西安交通大学统一身份认证（login.xjtu.edu.cn，2025-07-17 起启用的新系统）。
//
// 逻辑对照 XJTUToolBox/auth/new_login.py 与 db 参考实现 xjtu_core 逐条对齐。
// 与西电 IDS 的差别（也就是本 fork 必须重写的部分）：
//   西电：AES-CBC 加密密码（salt 取自表单）+ 滑块验证码 + 短信/企业微信二次认证
//   西交：RSA(PKCS#1 v1.5) 加密密码（公钥取自 /cas/jwt/publicKey）+ 图形验证码
//         + /cas/mfa/detect 二次认证 + Safety Verify + 多身份选择
//
// 登录链路（实测）：
//   目标业务地址
//     → 302 org.xjtu.edu.cn/openplatform/oauth/authorize?appId=1675
//     → 302 login.xjtu.edu.cn/cas/oauth2.0/authorize?client_id=1675
//     → 302 login.xjtu.edu.cn/cas/login?service=...
//   登录成功后原路返回，每一跳都会下发各自域名的 cookie（关键是 jwxt 的
//   GS_SESSIONID），所以**必须手动逐跳跟随**，不能交给底层自动重定向。

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:dio/dio.dart';
import 'package:html/parser.dart' as html_parser;
import 'package:pointycastle/asn1.dart';
import 'package:pointycastle/asymmetric/api.dart' show RSAPublicKey;
import 'package:pointycastle/export.dart'
    show PKCS1Encoding, PublicKeyParameter, RSAEngine;

import 'package:watermeter/repository/logger.dart';
import 'package:watermeter/repository/network_client.dart';
import 'package:watermeter/repository/preference.dart' as preference;

const String xjtuCasOrigin = 'https://login.xjtu.edu.cn';

/// 本科教务入口。未登录时会 302 到 CAS，登录成功后回到这里。
const String jwxtHome = 'https://jwxt.xjtu.edu.cn/jwapp/sys/homeapp/index.do';

/// 需要用户输入时的回调。UI 层注册，登录流程在需要时同步等待。
typedef XjtuMfaCodeProvider = Future<String?> Function(String maskedPhone);
typedef XjtuCaptchaProvider = Future<String?> Function(Uint8List image);
typedef XjtuAccountChoiceProvider = Future<bool> Function(
    List<XjtuAccountChoice> choices);

class XjtuAccountChoice {
  const XjtuAccountChoice({required this.name, required this.label});

  final String name;
  final String label;
}

/// 登录流程状态（与 IDSLoginState 并存，供 UI 区分）。
enum XjtuLoginState {
  success,
  fail,
  passwordWrong,
  needMfa,
  needCaptcha,
  needAccountChoice,
  cancelled,
}

class XjtuLoginResult {
  const XjtuLoginResult(this.state, {this.message});

  final XjtuLoginState state;
  final String? message;
}

class XjtuAuthException implements Exception {
  const XjtuAuthException(this.message);

  final String message;

  @override
  String toString() => message;
}

class XjtuPasswordWrongException extends XjtuAuthException {
  const XjtuPasswordWrongException(super.message);
}

class XjtuNeedMfaException extends XjtuAuthException {
  const XjtuNeedMfaException(super.message);
}

/// 重定向链路在打转（同一个地址反复出现）。
///
/// 与「跳数用尽」区分开，因为两者的处理方式不同：
/// 打转几乎都是会话 cookie 脏了，清掉 cookie 重走一次通常就好了。
class XjtuRedirectLoopException extends XjtuAuthException {
  const XjtuRedirectLoopException(super.message, {this.trail = const <String>[]});

  /// 出错时的重定向链路，便于排查。
  final List<String> trail;
}

/// 统一身份认证客户端。进程内共用一个实例。
class XjtuAuth {
  XjtuAuth._();

  static final XjtuAuth instance = XjtuAuth._();

  /// 单次请求允许跟随的最大跳数。
  ///
  /// 正常链路很短（实测：未登录 3 跳落到 CAS 登录页，登录成功后再 4 跳回教务，
  /// 合计 7 跳左右）。留到 20 是为了容忍学校加了网关 / WebVPN 之类的额外跳转。
  static const int _maxRedirects = 20;

  /// 同一个 host+path 出现多少次就判定为打转。
  ///
  /// 不能用「完整 URL 相同」来判断：西交的 OAuth 链每跳都带一个随机的
  /// `state`，地址每轮都不一样，只有 host+path 是稳定的。
  static const int _loopThreshold = 4;

  /// 需要用户输入短信验证码时调用，返回验证码；返回 null 视为取消登录。
  static XjtuMfaCodeProvider? mfaCodeProvider;

  /// 需要用户识别图形验证码时调用。
  static XjtuCaptchaProvider? captchaProvider;

  /// 账号有多个身份时调用，返回 true 表示选本科。
  static XjtuAccountChoiceProvider? accountChoiceProvider;

  Dio get _dio => NetworkClients.idsDio;

  bool _loggedIn = false;
  bool get isLoggedIn => _loggedIn;
  void markLoggedOut() => _loggedIn = false;

  /// 设备指纹：必须是稳定值，否则每次登录都要过二次验证。
  static Future<String> visitorId() async {
    final saved = preference.getString(preference.Preference.idsBrowserFingerprint);
    if (saved.isNotEmpty) return saved;
    final seed = _newSeed();
    await preference.setString(
      preference.Preference.idsBrowserFingerprint,
      seed,
    );
    return seed;
  }

  static String _newSeed() {
    final random = Random.secure();
    final bytes = List<int>.generate(32, (_) => random.nextInt(256));
    return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }

  /// 完整登录流程。成功返回 null，失败抛 [XjtuAuthException]。
  Future<void> login({
    required String username,
    required String password,
    bool trustAgent = true,
  }) async {
    final id = await visitorId();
    final postUrl = await _bootstrap();
    log.info('[XjtuAuth] 登录表单：$postUrl');

    // 已经是登录态（_bootstrap 落到的不是 CAS 登录页）就直接收工。
    // 否则会拿教务首页当登录表单去 POST 一堆无意义字段。
    if (!postUrl.contains('/cas/login')) {
      log.info('[XjtuAuth] 检测到已有有效会话，跳过认证流程');
      _loggedIn = true;
      return;
    }

    final execution = _extractInputValue(await _fetchText(postUrl), 'execution');
    final passwordValue = await _encryptPassword(password, postUrl);

    // 二次认证检测：一次 /cas/mfa/detect 同时拿到 need 与 state。
    //
    // ⚠️ 关键：不管 need 是真是假，detect 返回的 state 都必须原样回传到登录表单。
    //    服务端在 detect 时会把「本次登录的 MFA 会话」挂在 state 上，登录表单不带
    //    这个 state 就会直接判 MFA failed（与密码是否正确无关）。
    //    这一点对齐 XJTUToolBox/auth/new_login.py：它同样无条件保存 mfa_context.state。
    String mfaState = '';
    final mfa = await _detectMfa(username, passwordValue, id, postUrl);
    mfaState = mfa.state ?? '';
    if (mfa.need && mfa.state != null) {
      await _requestMfaCode(mfa.state!);
    }
    log.info('[XjtuAuth] MFA 检测：need=${mfa.need} mfaState=${mfaState.isEmpty ? '（空）' : '已获取'}');

    final trustAgentValue = mfa.need ? (trustAgent ? 'true' : 'false') : '';

    final response = await _follow(
      Uri.parse(postUrl),
      method: 'POST',
      data: <String, dynamic>{
        'username': username,
        'password': passwordValue,
        'execution': execution,
        '_eventId': 'submit',
        'submit1': 'Login1',
        'fpVisitorId': id,
        'captcha': '',
        'currentMenu': '1',
        'failN': '0',
        'mfaState': mfaState,
        'geolocation': '',
        'trustAgent': trustAgentValue,
      },
    );

    final body = response.data ?? '';
    if (response.statusCode == 401) {
      throw XjtuPasswordWrongException(
        _localize(_extractAlertMessage(body)) ?? '用户名或密码错误',
      );
    }
    final alert = _extractAlertMessage(body);
    if (alert != null) {
      throw XjtuAuthException(_localize(alert)!);
    }
    if (_isSafetyVerifyPage(body)) {
      throw const XjtuAuthException('需要完成安全二次认证，请在浏览器登录一次后再试');
    }

    // 多身份选择
    final choices = _extractAccountChoices(body);
    if (choices.isNotEmpty) {
      final undergraduate = await _chooseAccount(choices);
      final chosen = choices.firstWhere(
        (XjtuAccountChoice c) => undergraduate
            ? c.name.contains('本科')
            : c.name.contains('研究'),
        orElse: () => choices.first,
      );
      final choiceResponse = await _follow(
        Uri.parse('$xjtuCasOrigin/cas/login'),
        method: 'POST',
        data: <String, dynamic>{
          'execution': _extractInputValue(body, 'execution'),
          '_eventId': 'submit',
          'geolocation': '',
          'fpVisitorId': id,
          'trustAgent': trustAgentValue,
          'username': chosen.label,
          'useDefault': 'false',
        },
      );
      final choiceBody = choiceResponse.data ?? '';
      if (_extractAlertMessage(choiceBody) != null) {
        throw XjtuAuthException(_extractAlertMessage(choiceBody)!);
      }
    }

    _loggedIn = true;
    log.info('[XjtuAuth] 登录成功，会话 cookie 已写入 NetworkCookieJars.ids');
  }

  /// 从业务地址出发，跟随重定向落到 CAS 登录页，返回登录表单地址。
  ///
  /// 链路若在打转，先清掉会话 cookie 再走一次。打转基本都是上一轮失败
  /// 登录留下的半成品 cookie 造成的（只剩 CAS 的 SESSION、没有教务的会话，
  /// 服务端就会在两个地址之间来回 302，自己永远走不出来）。
  Future<String> _bootstrap() async {
    Response<String> response;
    try {
      response = await _follow(Uri.parse(jwxtHome));
    } on XjtuRedirectLoopException catch (e) {
      log.warning('[XjtuAuth] 登录链路打转，清空会话 cookie 后重试一次');
      if (e.trail.isNotEmpty) {
        log.warning('[XjtuAuth] 打转链路：${e.trail.join(' → ')}');
      }
      await _clearCookies();
      response = await _follow(Uri.parse(jwxtHome));
    }

    final postUrl = response.realUri.toString();
    if (!postUrl.contains('/cas/login')) {
      // 已有有效会话
      _loggedIn = true;
    }
    return postUrl;
  }

  /// 清空会话 cookie。失败不致命，只是这次登录可能还是走不通。
  static Future<void> _clearCookies() async {
    try {
      await NetworkCookieJars.ids.deleteAll();
    } catch (e) {
      log.warning('[XjtuAuth] 清空会话 cookie 失败：$e');
    }
  }

  /// 二次认证检测：返回是否需要以及本次认证的 state。
  Future<_MfaProbe> _detectMfa(
    String username,
    String password,
    String visitorId,
    String postUrl,
  ) async {
    final html = await _fetchText(postUrl);
    if (!_extractMfaEnabled(html)) return const _MfaProbe(need: false, state: null);

    final response = await _dio.post<String>(
      '$xjtuCasOrigin/cas/mfa/detect',
      data: <String, dynamic>{
        'username': username,
        'password': password,
        'fpVisitorId': visitorId,
        'loginType': 'passwordLogin',
      },
      options: Options(
        headers: <String, dynamic>{'Referer': postUrl},
        contentType: Headers.formUrlEncodedContentType,
        responseType: ResponseType.plain,
      ),
    );
    final map = _asMap(response.data);
    final data = map['data'];
    // 解析不出来就报错，绝不能静默降级成「不需要 MFA」——
    // 那会让我们漏带 mfaState，服务端只会回一句 MFA failed，反而更难查。
    if (data is! Map || data['state'] == null) {
      throw const XjtuAuthException('服务器在 MFA 检测时返回了无法解析的信息');
    }
    return _MfaProbe(
      need: data['need'] == true || data['need'] == 'true',
      state: data['state'].toString(),
    );
  }

  /// 发码并请用户输入验证码，校验通过后返回。
  Future<void> _requestMfaCode(String state) async {
    final init = await _dio.get<String>(
      '$xjtuCasOrigin/cas/mfa/initByType/securephone',
      queryParameters: <String, dynamic>{'state': state},
      options: Options(responseType: ResponseType.plain),
    );
    final initMap = _asMap(init.data);
    if (initMap['code'] != null && initMap['code'] != 0) {
      throw XjtuAuthException(
        initMap['message']?.toString() ?? '无法获取绑定手机信息',
      );
    }
    final data = initMap['data'];
    if (data is! Map || data['gid'] == null) {
      throw const XjtuAuthException('无法获取绑定手机信息');
    }
    final gid = data['gid'].toString();
    final phone = data['securePhone']?.toString() ?? '****';

    final send = await _dio.post<String>(
      '$xjtuCasOrigin/attest/api/guard/securephone/send',
      data: <String, dynamic>{'gid': gid},
      options: Options(contentType: Headers.jsonContentType),
    );
    if (_asMap(send.data)['code'] != 0) {
      throw XjtuAuthException(
        _asMap(send.data)['message']?.toString() ?? '验证码发送失败',
      );
    }

    final provider = mfaCodeProvider;
    if (provider == null) {
      throw XjtuNeedMfaException('登录需要短信验证码（当前界面未提供输入入口）');
    }
    final code = await provider(phone);
    if (code == null || code.isEmpty) {
      throw const XjtuAuthException('已取消二次认证');
    }

    final valid = await _dio.post<String>(
      '$xjtuCasOrigin/attest/api/guard/securephone/valid',
      data: <String, dynamic>{'gid': gid, 'code': code},
      options: Options(contentType: Headers.jsonContentType),
    );
    final validMap = _asMap(valid.data);
    if (validMap['code'] != 0) {
      throw XjtuAuthException(
        validMap['message']?.toString() ?? '验证码校验失败',
      );
    }
    // code == 0 并不代表通过：必须看 data.status == 2。
    // 这一点同样对齐 XJTUToolBox —— 它专门校验了 status，缺了会把错码当成功，
    // 然后带着未通过 MFA 的会话去提交登录表单，服务端只回一句 MFA failed。
    final validData = validMap['data'];
    if (validData is Map) {
      final status = validData['status'];
      if (status != null && status.toString() != '2') {
        throw XjtuAuthException(
          validMap['message']?.toString() ?? '验证码错误，请重新输入',
        );
      }
    }
  }

  Future<bool> _chooseAccount(List<XjtuAccountChoice> choices) async {
    final provider = accountChoiceProvider;
    if (provider == null) return true;
    return provider(choices);
  }

  // ------------------------------------------------------------ 加密与请求

  static Future<String> _encryptPassword(
    String password,
    String postUrl,
  ) async {
    final pem = (await NetworkClients.idsDio.get<String>(
      '$xjtuCasOrigin/cas/jwt/publicKey',
      options: Options(
        headers: <String, dynamic>{'Referer': postUrl},
        responseType: ResponseType.plain,
      ),
    ))
        .data;
    final key = _parsePublicKeyFromPem(pem ?? '');
    final engine = PKCS1Encoding(RSAEngine())
      ..init(true, PublicKeyParameter<RSAPublicKey>(key));
    final encrypted = engine.process(
      Uint8List.fromList(utf8.encode(password)),
    );
    return '__RSA__${base64.encode(encrypted)}';
  }

  static RSAPublicKey _parsePublicKeyFromPem(String pem) {
    final body = pem
        .replaceAll(RegExp(r'-----[^-]+-----'), '')
        .replaceAll(RegExp(r'\s'), '');
    if (body.isEmpty) throw const XjtuAuthException('RSA 公钥为空');

    final top = ASN1Parser(base64.decode(body)).nextObject();
    if (top is ASN1Sequence) {
      for (final element in top.elements ?? const <ASN1Object>[]) {
        if (element is ASN1BitString) {
          final innerBytes = element.stringValues ?? const <int>[];
          if (innerBytes.isEmpty) continue;
          final integers = _collectIntegers(
            ASN1Parser(Uint8List.fromList(innerBytes)).nextObject(),
          );
          if (integers.length >= 2) {
            return RSAPublicKey(integers[0], integers[1]);
          }
        }
      }
    }
    final integers = _collectIntegers(top);
    if (integers.length >= 2) return RSAPublicKey(integers[0], integers[1]);
    throw const XjtuAuthException('无法解析 RSA 公钥');
  }

  static List<BigInt> _collectIntegers(ASN1Object? object, [List<BigInt>? acc]) {
    final out = acc ?? <BigInt>[];
    if (object == null) return out;
    if (object is ASN1Integer) {
      final value = object.integer;
      if (value != null) out.add(value);
    } else if (object is ASN1Sequence) {
      for (final child in object.elements ?? const <ASN1Object>[]) {
        _collectIntegers(child, out);
      }
    }
    return out;
  }

  Future<String> _fetchText(String url) async {
    final response = await _follow(Uri.parse(url));
    return response.data ?? '';
  }

  /// 手动逐跳跟随重定向。idsDio 已关闭自动重定向，这里保证每一跳的
  /// Set-Cookie 都能被 CookieManager 捕获。
  ///
  /// 出错时会把链路塞进异常消息里 —— iOS 上取日志不方便，让用户截个图
  /// 就能看出链子在哪一段打转。
  Future<Response<String>> _follow(
    Uri start, {
    String method = 'GET',
    Map<String, dynamic>? data,
  }) async {
    var current = start;
    var currentMethod = method;
    Map<String, dynamic>? currentData = data;

    // 链路记录与打转计数。key 用 host+path，因为 OAuth 每跳的 state 都变。
    final trail = <String>[];
    final seen = <String, int>{};

    for (var hop = 0; hop <= _maxRedirects; hop++) {
      final response = await _dio.requestUri<String>(
        current,
        data: currentData,
        options: Options(
          method: currentMethod,
          followRedirects: false,
          responseType: ResponseType.plain,
          contentType:
              currentData == null ? null : Headers.formUrlEncodedContentType,
          validateStatus: (int? status) =>
              status != null && status > 0 && status < 600,
        ),
      );

      final code = response.statusCode ?? 0;
      final location = response.headers.value('location');
      final isRedirect = code == 301 || code == 302 || code == 303 ||
          code == 307 || code == 308;
      if (!isRedirect || location == null || location.isEmpty) {
        return response;
      }

      final next = response.realUri.resolve(location.toString());
      final normalized =
          next.scheme == 'http' ? next.replace(scheme: 'https') : next;

      final key = '${normalized.host}${normalized.path}';
      final count = (seen[key] ?? 0) + 1;
      seen[key] = count;
      trail.add('$code→$key');

      if (count >= _loopThreshold) {
        throw XjtuRedirectLoopException(
          '登录链路在打转（$key 重复 $count 次）。'
          '通常是会话 cookie 失效或被网关拦截。',
          trail: List<String>.unmodifiable(trail),
        );
      }

      current = normalized;
      if (code == 302 || code == 303) {
        currentMethod = 'GET';
        currentData = null;
      }
    }

    throw XjtuAuthException(
      '登录重定向超过 $_maxRedirects 跳，登录链路可能已变更。'
      '链路：${trail.join(' → ')}',
    );
  }

  // ---------------------------------------------------------------- 解析

  static Map<String, dynamic> _asMap(dynamic raw) {
    if (raw == null) return <String, dynamic>{};
    if (raw is Map<String, dynamic>) return raw;
    if (raw is Map) return raw.map((k, v) => MapEntry(k.toString(), v));
    if (raw is String && raw.isNotEmpty) {
      try {
        final decoded = jsonDecode(raw);
        if (decoded is Map) {
          return decoded.map((k, v) => MapEntry(k.toString(), v));
        }
      } catch (_) {
        // ignore
      }
    }
    return <String, dynamic>{};
  }

  static String? _extractInputValue(String html, String name) {
    try {
      return html_parser
          .parse(html)
          .querySelector('input[name="$name"]')
          ?.attributes['value'];
    } catch (_) {
      return null;
    }
  }

  static String? _extractAlertMessage(String html) {
    try {
      final alert = html_parser.parse(html).querySelector('el-alert');
      if (alert == null) return null;
      final title = alert.attributes['title']?.trim();
      if (title != null && title.isNotEmpty) return title;
      final text = alert.text.trim();
      return text.isEmpty ? null : text;
    } catch (_) {
      return null;
    }
  }

  /// 服务端错误提示汉化。认不出来的原文照旧返回，方便排查。
  static const Map<String, String> _messageZh = <String, String>{
    'MFA failed': '二次验证未通过。请重新登录；若弹出短信验证码，请完整输入后再提交。',
    'Invalid captcha': '图形验证码错误',
    'Username or password is incorrect': '学号或密码错误',
    'Account is locked': '账号已被锁定，请稍后再试',
    'Account is disabled': '账号已被停用',
  };

  static String? _localize(String? raw) {
    if (raw == null) return null;
    final key = raw.trim();
    return _messageZh[key] ?? raw;
  }

  static List<XjtuAccountChoice> _extractAccountChoices(String html) {
    final result = <XjtuAccountChoice>[];
    try {
      final document = html_parser.parse(html);
      for (final wrap in document.querySelectorAll('div.account-wrap')) {
        final name = wrap.querySelector('div.name')?.text.trim();
        final label = wrap.querySelector('el-radio')?.attributes['label']?.trim();
        if (name != null && name.isNotEmpty && label != null && label.isNotEmpty) {
          result.add(XjtuAccountChoice(name: name, label: label));
        }
      }
    } catch (_) {
      // 解析失败视为没有身份选择页
    }
    return result;
  }

  static bool _isSafetyVerifyPage(String html) {
    if (html.isEmpty) return false;
    try {
      final document = html_parser.parse(html);
      final hasSecState = document.querySelector('input[name="secState"]') != null;
      final hasExecution = document.querySelector('input[name="execution"]') != null;
      final hasEventId = document.querySelector('input[name="_eventId"]') != null;
      return hasSecState && hasExecution && hasEventId;
    } catch (_) {
      return false;
    }
  }

  static bool _extractMfaEnabled(String html) {
    final loose = RegExp(
      'mfaEnabled\\\\?"?\\s*[:=]\\s*\\\\?"?(true|false)',
    ).firstMatch(html);
    if (loose != null) return loose.group(1) == 'true';
    // 与 Python 实现一致：默认按需要 MFA 处理
    return true;
  }
}

class _MfaProbe {
  const _MfaProbe({required this.need, required this.state});

  final bool need;
  final String? state;
}
