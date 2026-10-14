// Copyright 2023-2025 BenderBlog Rodriguez and contributors
// Copyright 2025 Traintime PDA authors.
// Copyright 2026 XJTU fork authors.
// SPDX-License-Identifier: MPL-2.0

import 'dart:convert';

import 'package:dio/dio.dart';
import 'package:watermeter/repository/ids_session/ids_session.dart';
import 'package:watermeter/repository/logger.dart';

class SemesterSession extends IDSSession {
  /// 让 dio 原样返回响应体，JSON 解析由我们自己做。
  ///
  /// 【重要】不要依赖 dio 的自动解析。原来的写法是
  /// ```dart
  /// String code = await dio.post(url).then((v) => v.data['datas']...['DM']);
  /// ```
  /// 赋值目标的 String 类型会让 Dart 把泛型 T 推断成 String，dio 于是把已经
  /// 解析好的对象又 toString 了一遍，`v.data['datas']` 就成了「对 String 做
  /// 下标取值」，抛出：
  ///     type 'String' is not a subtype of type 'int' of 'index'
  /// 固定 `post<dynamic>` + `ResponseType.plain` + 手动 jsonDecode 就没这问题。
  static final Options _plainOptions = Options(
    responseType: ResponseType.plain,
    contentType: Headers.formUrlEncodedContentType,
  );

  /// 研究生（西交 GMIS 尚未适配，保留原西电实现作为占位）。
  Future<String> getSemesterInfoYjspt() async {
    final location = await checkAndLogin(
      target: "https://yjspt.xidian.edu.cn/",
      sliderCaptcha: (String _) async {},
    );

    log.info(
      "[PersonalInfoSession][getSemesterInfoYjspt] "
      "Location is $location",
    );
    await followIDSRedirects(initialLocation: location, client: dio);

    log.info(
      "[PersonalInfoSession][getSemesterInfoYjspt] "
      "Getting the current semester info.",
    );

    final response = await dio.post<dynamic>(
      "https://yjspt.xidian.edu.cn/gsapp/sys/yjsemaphome/modules/pubWork/getUserInfo.do",
      options: _plainOptions,
    );
    final detailed = _decode(response.data);
    if (detailed["code"] != "0") {
      throw GetInformationFailedException(
        detailed["msg"]?.toString() ?? "研究生系统返回错误",
      );
    }
    return detailed["data"]["xnxqdm"].toString();
  }

  /// 本科：西交教务的当前学期代码，例如 `2026-2027-1`。
  Future<String> getSemesterInfoEhall() async {
    log.info(
      "[ehall_session][getSemesterInfoEhall] "
      "Get the semester information.",
    );

    await checkAndLogin(
      target: "https://jwxt.xjtu.edu.cn/jwapp/sys/homeapp/index.do",
      sliderCaptcha: (String _) async {},
    ).then((location) async {
      await followIDSRedirects(initialLocation: location, client: dio);
    });

    final response = await dio.post<dynamic>(
      "https://jwxt.xjtu.edu.cn/jwapp/sys/wdkb/modules/jshkcb/dqxnxq.do",
      options: _plainOptions,
    );
    final decoded = _decode(response.data);

    final datas = decoded['datas'];
    final section = datas is Map ? datas['dqxnxq'] : null;
    final rows = section is Map ? section['rows'] : null;
    if (rows is! List || rows.isEmpty) {
      throw const GetInformationFailedException('教务系统未返回当前学期');
    }
    final first = rows.first;
    if (first is! Map || first['DM'] == null) {
      throw const GetInformationFailedException('教务系统返回的学期信息不完整');
    }
    final code = first['DM'].toString().trim();
    log.info('[ehall_session] 当前学期：$code');
    return code;
  }

  /// 兼容「已经解析成对象」与「还是字符串」两种情况。
  static Map<String, dynamic> _decode(dynamic raw) {
    dynamic decoded = raw;
    if (decoded is String) {
      if (decoded.trim().isEmpty) {
        throw const GetInformationFailedException('教务系统返回了空响应');
      }
      try {
        decoded = jsonDecode(decoded);
      } catch (_) {
        throw GetInformationFailedException(
          '教务系统返回了无法解析的内容：'
          '${decoded.length > 100 ? decoded.substring(0, 100) : decoded}',
        );
      }
    }
    if (decoded is! Map) {
      throw const GetInformationFailedException('教务系统返回的结构不是对象');
    }
    return decoded.map((k, v) => MapEntry(k.toString(), v));
  }
}

class GetInformationFailedException implements Exception {
  final String msg;
  const GetInformationFailedException(this.msg);

  @override
  String toString() => msg;
}
