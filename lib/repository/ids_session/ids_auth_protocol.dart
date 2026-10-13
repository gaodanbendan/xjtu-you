// Copyright 2026 Traintime PDA authors.
// SPDX-License-Identifier: MPL-2.0

/// 西交统一身份认证入口（CAS + OAuth2 开放平台）。
///
/// 西电的二次认证有独立页面 `/authserver/reAuthCheck/reAuthLoginView.do`，
/// 西交没有对应页面：会话失效时业务请求会被整体弹回 CAS 登录页。
/// 因此判据改为「是否落在 login.xjtu.edu.cn 的登录/授权路径上」。
const _xjtuLoginOrigin = 'https://login.xjtu.edu.cn';

bool isIDSReAuthLocation(String location, {Uri? baseUri}) {
  final uri = (baseUri ?? Uri.parse(_xjtuLoginOrigin)).resolve(location);
  if (uri.scheme != 'https' || uri.host != 'login.xjtu.edu.cn') return false;
  final path = uri.path;
  return path.startsWith('/cas/login') ||
      path.startsWith('/cas/oauth2.0/authorize') ||
      path.startsWith('/cas/oauth2.0/callbackAuthorize') ||
      path.startsWith('/cas/mfa/');
}

enum IDSReAuthSubmitStatus { success, failed, unauthorized }

enum IDSReAuthCodeType {
  sms(reAuthType: '3', authCodeTypeName: 'reAuthDynamicCodeType'),
  enterpriseWechat(
    reAuthType: '4',
    authCodeTypeName: 'reAuthWChatDynamicCodeType',
  );

  const IDSReAuthCodeType({
    required this.reAuthType,
    required this.authCodeTypeName,
  });

  final String reAuthType;
  final String authCodeTypeName;
}

class IDSReAuthSubmitResult {
  const IDSReAuthSubmitResult({required this.status, required this.message});

  final IDSReAuthSubmitStatus status;
  final String message;
}

IDSReAuthSubmitResult parseIDSReAuthSubmit(Map<dynamic, dynamic> json) {
  final code = json['code']?.toString();
  final message = json['msg']?.toString() ?? '二次认证失败';
  final status = switch (code) {
    'reAuth_success' => IDSReAuthSubmitStatus.success,
    'reAuth_failed' => IDSReAuthSubmitStatus.failed,
    'reAuth_unauthorized' => IDSReAuthSubmitStatus.unauthorized,
    _ => throw const IDSProtocolException('统一认证返回了未知的二次认证状态'),
  };
  return IDSReAuthSubmitResult(status: status, message: message);
}

class IDSCodeDelivery {
  const IDSCodeDelivery({
    required this.message,
    required this.maskedMobile,
    required this.retryAfter,
    required this.wasAlreadySent,
  });

  final String message;
  final String? maskedMobile;
  final Duration retryAfter;
  final bool wasAlreadySent;
}

IDSCodeDelivery parseIDSCodeDelivery(Map<dynamic, dynamic> json) {
  final result = json['res']?.toString();
  if (result != 'success' &&
      result != 'other_success' &&
      result != 'wechat_success' &&
      result != 'code_time_fail') {
    throw IDSProtocolException(json['returnMessage']?.toString() ?? '验证码发送失败');
  }

  final rawSeconds = int.tryParse(json['codeTime']?.toString() ?? '');
  final seconds = rawSeconds == null || rawSeconds < 0
      ? (result == 'wechat_success' ? 120 : 0)
      : rawSeconds;
  final mobile = json['mobile']?.toString();
  return IDSCodeDelivery(
    message: json['returnMessage']?.toString() ?? '验证码已发送',
    maskedMobile: mobile == null || mobile.isEmpty
        ? null
        : maskIDSPhoneNumber(mobile),
    retryAfter: Duration(seconds: seconds),
    wasAlreadySent: result == 'code_time_fail',
  );
}

String maskIDSPhoneNumber(String value) {
  if (value.length < 7) return '****';
  return '${value.substring(0, 3)}****${value.substring(value.length - 4)}';
}

class IDSProtocolException implements Exception {
  const IDSProtocolException(this.message);

  final String message;

  @override
  String toString() => message;
}
