// Copyright 2026 XJTU fork authors.
// SPDX-License-Identifier: MPL-2.0

// 西安交通大学版登录会话。
//
// 【重要】对外接口刻意保持与西电版完全一致：
//   - dio / dioNoOfflineCheck
//   - checkAndLogin({target, sliderCaptcha, reAuthHandler})
//   - followIDSRedirects({initialLocation, ...})
//   - loginState / IDSLoginState / offline / PasswordWrongException ...
// 这样 classtable / score / exam / semester / empty_classroom 等所有业务
// session 都不需要改动，只需要替换这一层内部实现。
//
// 与西电的机制差异：
//   西电是 CAS + service ticket：checkAndLogin 拿到 ticket 跳转地址，
//   再由 followIDSRedirects 跟随跳转把 cookie 落进 jar。
//   西交是 CAS + OAuth2 开放平台：一次 login() 就完成全部跳转与 cookie 写入，
//   因此 checkAndLogin 直接返回 target，followIDSRedirects 只做一次请求兜底。

import 'package:dio/dio.dart';
import 'package:synchronized/synchronized.dart';
import 'package:watermeter/repository/ids_session/ids_auth_protocol.dart';
import 'package:watermeter/repository/ids_session/ids_reauth_client.dart';
import 'package:watermeter/repository/logger.dart';
import 'package:watermeter/repository/network_client.dart';
import 'package:watermeter/repository/preference.dart' as preference;
import 'package:watermeter/repository/xjtu_session/xjtu_auth.dart';

enum LoginProcessStep {
  readyPage,
  getEncrypt,
  readyLogin,
  slider,
  secondFactor,
  afterProcess,
}

enum IDSLoginState {
  none,
  requesting,
  success,
  fail,
  passwordWrong,
  cancelled,

  /// Indicate that the user will login via LoginWindow
  manual,
}

IDSLoginState loginState = IDSLoginState.none;

bool get offline =>
    loginState != IDSLoginState.success && loginState != IDSLoginState.manual;

class IDSSession {
  /// 业务请求客户端（教务系统）。
  Dio get dio {
    log.info('[IDSSession][OfflineCheck] Offline status: $offline');
    if (offline) {
      throw DioException.requestCancelled(
        reason: 'Offline mode, all IDS functions are unavailable.',
        requestOptions: RequestOptions(path: ''),
      );
    }
    return NetworkClients.ehallDio;
  }

  /// 认证流程使用，不受 offline 保护。
  Dio get dioNoOfflineCheck => NetworkClients.idsDio;

  /// 西交已不区分服务（一次统一身份认证即可访问教务），保留占位。
  String aesEncrypt(String toEnc, String key) => toEnc;

  /// 重定向跟随上限，与西电版保持一致（业务层 library_session 会引用它）。
  static const maxAuthRedirects = 30;

  /// 会话级重认证锁：多个业务请求同时被弹回登录页时，只走一次登录。
  static final _reAuthLock = Lock();

  /// 西交版重新认证。
  ///
  /// 西电是在既有会话内单独走一次 reAuth（短信/企业微信），西交没有这一步：
  /// 会话失效时直接整站弹回 CAS，所以这里做的是「重走一次统一身份认证」。
  /// 成功返回原 uri，失败抛 [IDSReAuthRequiredException] 交给登录 UI 处理。
  Future<Uri> resolveIDSReAuthIfNeeded(
    Uri uri, {
    String? service,
    String? username,
    Object? reAuthHandler,
    void Function(int, LoginProcessStep)? onResponse,
  }) {
    if (!isIDSReAuthLocation(uri.toString())) return Future.value(uri);
    return _reAuthLock.synchronized(() async {
      final previous = loginState;
      loginState = IDSLoginState.requesting;

      final user =
          username ?? preference.getString(preference.Preference.idsAccount);
      final pass = preference.getString(preference.Preference.idsPassword);
      if (user.isEmpty || pass.isEmpty) {
        loginState = IDSLoginState.fail;
        throw const IDSReAuthRequiredException();
      }

      try {
        onResponse?.call(55, LoginProcessStep.secondFactor);
        await XjtuAuth.instance.login(username: user, password: pass);
        loginState = previous == IDSLoginState.manual
            ? IDSLoginState.manual
            : IDSLoginState.success;
        return uri;
      } on XjtuPasswordWrongException catch (e) {
        loginState = IDSLoginState.passwordWrong;
        throw PasswordWrongException(msg: e.message);
      } on XjtuAuthException {
        loginState = IDSLoginState.fail;
        throw const IDSReAuthRequiredException();
      }
    });
  }

  /// 兼容西电版签名。西交版不使用滑块验证码，参数忽略。
  Future<String> checkAndLogin({
    required String target,
    required Future<void> Function(String) sliderCaptcha,
    Object? reAuthHandler,
  }) async {
    if (loginState == IDSLoginState.success || XjtuAuth.instance.isLoggedIn) {
      return target;
    }
    final username = preference.getString(preference.Preference.idsAccount);
    final password = preference.getString(preference.Preference.idsPassword);
    await _loginWith(username: username, password: password);
    return target;
  }

  /// 兼容西电版签名。西交没有 CAS 跳转链，这里直接请求目标地址。
  Future<Response<dynamic>> followIDSRedirects({
    required String initialLocation,
    Dio? client,
    String? service,
    String? username,
    Object? reAuthHandler,
  }) async {
    final usedDio = client ?? dioNoOfflineCheck;
    final uri = Uri.tryParse(initialLocation);
    if (uri == null || !uri.hasScheme) {
      throw LoginFailedException(msg: '非法的跳转地址：$initialLocation');
    }
    return usedDio.getUri<dynamic>(
      uri,
      options: Options(followRedirects: false),
    );
  }

  /// 兼容西电版签名（login_window 调用）。
  Future<String> login({
    required String username,
    required String password,
    Future<void> Function(String)? sliderCaptcha,
    bool forceReLogin = false,
    void Function(int, LoginProcessStep)? onResponse,
    String? target,
    Object? reAuthHandler,
  }) async {
    if (forceReLogin) {
      XjtuAuth.instance.markLoggedOut();
    }
    await _loginWith(
      username: username,
      password: password,
      onResponse: onResponse,
    );
    return target ?? jwxtHome;
  }

  Future<void> _loginWith({
    required String username,
    required String password,
    void Function(int, LoginProcessStep)? onResponse,
  }) async {
    if (username.isEmpty || password.isEmpty) {
      loginState = IDSLoginState.fail;
      throw const LoginFailedException(msg: '请先填写学号与密码');
    }

    // 登录前清掉上一轮残留的会话 cookie。
    //
    // login_window 那条「用户手动点登录」的路径自己清过，但开机自动登录、
    // 首页卡片、空闲教室这些走 checkAndLogin 的路径不会。带着半成品 cookie
    // 去走 OAuth 链，服务端会在两个地址之间来回 302，用户看到的就是
    // 「重定向次数超过上限，登录链路可能已变更」。
    try {
      await NetworkCookieJars.ids.deleteAll();
      log.info('[IDSSession] 登录前已清空会话 cookie');
    } catch (e) {
      // 清不掉也不中断登录流程
      log.warning('[IDSSession] 清空会话 cookie 失败：$e');
    }

    loginState = IDSLoginState.requesting;
    onResponse?.call(10, LoginProcessStep.readyPage);

    try {
      onResponse?.call(40, LoginProcessStep.readyLogin);
      await XjtuAuth.instance.login(username: username, password: password);
      loginState = IDSLoginState.success;
      onResponse?.call(90, LoginProcessStep.afterProcess);
    } on XjtuPasswordWrongException catch (e) {
      loginState = IDSLoginState.passwordWrong;
      throw PasswordWrongException(msg: e.message);
    } on XjtuAuthException catch (e) {
      loginState = IDSLoginState.fail;
      throw LoginFailedException(msg: e.message);
    } on DioException catch (e) {
      loginState = IDSLoginState.fail;
      throw LoginFailedException(msg: '网络错误：${e.message ?? e.type.name}');
    }
  }

  /// 西交的本科生/研究生区分来自账号身份，不再通过单独的系统探测。
  Future<bool> checkWhetherPostgraduate({Object? reAuthHandler}) async {
    return preference.getBool(preference.Preference.role);
  }
}

class NeedCaptchaException implements Exception {}

class PasswordWrongException implements Exception {
  final String msg;
  const PasswordWrongException({required this.msg});
  @override
  String toString() => msg;
}

class LoginFailedException implements Exception {
  final String msg;
  const LoginFailedException({required this.msg});
  @override
  String toString() => msg;
}
