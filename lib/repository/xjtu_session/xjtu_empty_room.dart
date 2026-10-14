// Copyright 2026 XJTU fork authors.
// SPDX-License-Identifier: MPL-2.0

// 西安交通大学空闲教室查询（kxjas 模块）。
//
// 接口逐条对照 XJTUToolBox 的 `jwxt/empty_room.py` 与 `jwxt/util.py`，
// 已在本机用真实账号验证通过（2026-10-14）：
//
//   校区字典  POST /jwapp/code/83a986fc-e677-400e-99a4-c7bb39c2ca35.do   (key = code)
//   教学楼字典 POST /jwapp/code/551fbcc3-cf07-4566-af1e-fc7ce272ddc1.do  (key = code)
//   空闲教室  POST /jwapp/sys/kxjas/modules/kxjscx/cxkxjs.do              (key = cxkxjs)
//
// 与西电的空闲教室实现是两套东西（西电走
// `sys/kxjas/modules/kxjas/cxjsqk.do`，一次返回全天占用表），所以这块不能
// 靠换域名复用，必须重写。
//
// 两个必须注意的点：
// 1. 空闲教室只在「学生」身份下可用，在「移动应用学生」身份下查不到数据，
//    所以进页面前要 [ensureStudentRole]。
// 2. 西交接口一次只能回答「第 X 到第 Y 节是否空闲」，拿不到全天占用表。
//    全天表格靠对 11 个节次并发查询后反推（实测主楼A 全程约 0.5 秒）。

import 'dart:convert';

import 'package:dio/dio.dart';

/// 一栋教学楼及其校区归属。
class XjtuBuilding {
  const XjtuBuilding({
    required this.id,
    required this.name,
    required this.campusCode,
    required this.campusName,
  });

  /// 教学楼代码（`JXLDM`），查询空闲教室时使用。
  final String id;

  /// 教学楼简称（`JXLJC`），例如「主楼A」。
  final String name;

  /// 校区代码（`XXXQDM`）。
  final String campusCode;

  /// 校区名（`XXXQDM_DISPLAY`）。
  final String campusName;
}

/// 一间空闲教室。
class XjtuEmptyRoomInfo {
  const XjtuEmptyRoomInfo({
    required this.name,
    required this.type,
    required this.capacity,
    required this.examCapacity,
    required this.timeRange,
  });

  /// 教室全名，例如「主楼A-304」。
  final String name;

  /// 教室类型，例如「多媒体教室」。
  final String type;

  /// 座位数。
  final int capacity;

  /// 考试座位数。
  final int examCapacity;

  /// 空闲时段，例如「08:00-08:50」。
  final String timeRange;
}

class XjtuEmptyRoomClient {
  XjtuEmptyRoomClient(this.dio);

  final Dio dio;

  static const String origin = 'https://jwxt.xjtu.edu.cn';

  /// 兴庆校区。当前只实现这个校区（用户 2026-10-14 确认）。
  static const String xingqingCampusCode = '1';

  static const String _buildingCodePath =
      '/jwapp/code/551fbcc3-cf07-4566-af1e-fc7ce272ddc1.do';
  static const String _emptyRoomPath =
      '/jwapp/sys/kxjas/modules/kxjscx/cxkxjs.do';
  static const String _currentUserPath =
      '/jwapp/sys/homeapp/api/home/currentUser.do';
  static const String _changeRolePath =
      '/jwapp/sys/homeapp/api/home/changeAppRole.do';

  static const String _referer =
      '$origin/jwapp/sys/kxjas/*default/index.do';
  static const String _homeReferer =
      '$origin/jwapp/sys/homeapp/home/index.html?av=&contextPath=/jwapp';

  static const Map<String, String> _jsonHeaders = <String, String>{
    'Accept': 'application/json, text/javascript, */*; q=0.01',
    'X-Requested-With': 'XMLHttpRequest',
  };

  /// 确保当前身份是「学生」。已经是学生身份时什么都不做。
  ///
  /// 空闲教室在「移动应用学生」身份下查不到任何数据 —— 教务的坑，
  /// XJTUToolBox 的 `JWXTUtil.setRoleToStudent()` 专门处理了它。
  Future<void> ensureStudentRole() async {
    final response = await dio.get<String>(
      '$origin$_currentUserPath',
      options: Options(
        responseType: ResponseType.plain,
        headers: <String, dynamic>{..._jsonHeaders, 'Referer': _homeReferer},
      ),
    );
    final map = _decodeBody(response);

    final datas = map['datas'];
    final groups = datas is Map ? datas['userGroups'] : null;
    if (groups is! List) {
      throw const XjtuEmptyRoomException('教务系统未返回用户身份信息');
    }

    final roles = groups
        .whereType<Map>()
        .map((Map e) => e.map((k, v) => MapEntry(k.toString(), v)))
        .toList();

    Map<String, dynamic>? current;
    for (final role in roles) {
      if (role['currentRole'] == true) {
        current = role;
        break;
      }
    }
    if (current == null) {
      throw const XjtuEmptyRoomException('无法确定当前用户身份');
    }
    if (current['roleName']?.toString() == '学生') return;

    Map<String, dynamic>? student;
    for (final role in roles) {
      if (role['roleName']?.toString() == '学生') {
        student = role;
        break;
      }
    }
    if (student == null) {
      throw const XjtuEmptyRoomException('当前账号不包含「学生」身份，无法查询空闲教室');
    }

    await dio.post<String>(
      '$origin$_changeRolePath',
      data: <String, dynamic>{'appRole': student['roleId']},
      options: Options(
        contentType: Headers.formUrlEncodedContentType,
        responseType: ResponseType.plain,
        headers: <String, dynamic>{..._jsonHeaders, 'Referer': _homeReferer},
      ),
    );
  }

  /// 教学楼列表。[campusCode] 为空时返回全部校区。
  Future<List<XjtuBuilding>> fetchBuildings({String? campusCode}) async {
    final rows = await _postRows(_buildingCodePath, key: 'code');
    final result = <XjtuBuilding>[];
    for (final row in rows) {
      final id = row['id']?.toString();
      final name = row['name']?.toString();
      if (id == null || name == null || id.isEmpty || name.isEmpty) continue;

      final other = row['otherFields'];
      final otherMap = other is Map
          ? other.map((k, v) => MapEntry(k.toString(), v))
          : const <String, dynamic>{};
      final code = otherMap['XXXQDM']?.toString() ?? '';
      if (campusCode != null && campusCode.isNotEmpty && code != campusCode) {
        continue;
      }
      result.add(
        XjtuBuilding(
          id: id,
          name: name,
          campusCode: code,
          campusName: otherMap['XXXQDM_DISPLAY']?.toString() ?? '',
        ),
      );
    }
    return result;
  }

  /// 查询某校区某教学楼在某天某个节次区间内空闲的教室。
  Future<List<XjtuEmptyRoomInfo>> fetchEmptyRooms({
    required String campusCode,
    required String buildingCode,
    required String date,
    required int startJie,
    required int endJie,
  }) async {
    final rows = await _postRows(
      _emptyRoomPath,
      key: 'cxkxjs',
      data: <String, dynamic>{
        'XXXQDM': campusCode,
        'JXLDM': buildingCode,
        'KXRQ': date,
        'KSJC': '$startJie',
        'JSJC': '$endJie',
        'pageSize': '500',
        'pageNumber': '1',
      },
    );

    final result = <XjtuEmptyRoomInfo>[];
    for (final row in rows) {
      // 没有「教室类型」的行是接口造出来的幽灵教室，过滤掉。
      if (row['JASLXDM'] == null) continue;
      final name = row['JASMC']?.toString() ?? '';
      // 系统里存在名为「测试专用」的测试教室，同样过滤。
      if (name.contains('测试专用')) continue;
      result.add(
        XjtuEmptyRoomInfo(
          name: name,
          type: row['JASLXDM_DISPLAY']?.toString() ?? '',
          capacity: int.tryParse(row['SKZWS']?.toString() ?? '') ?? 0,
          examCapacity: int.tryParse(row['KSZWS']?.toString() ?? '') ?? 0,
          timeRange: row['KXSJ']?.toString() ?? '',
        ),
      );
    }
    return result;
  }

  /// 查一整天的空闲教室，返回 `节次(1..11) -> 该节空闲教室列表`。
  ///
  /// 11 个节次并发请求；实测主楼A 全天约 0.5 秒。
  Future<Map<int, List<XjtuEmptyRoomInfo>>> fetchRoomsInDay({
    required String campusCode,
    required String buildingCode,
    required String date,
    void Function(int done, int total)? onProgress,
  }) async {
    var done = 0;
    final futures = <int, Future<List<XjtuEmptyRoomInfo>>>{};
    for (var jie = 1; jie <= 11; jie++) {
      futures[jie] = fetchEmptyRooms(
        campusCode: campusCode,
        buildingCode: buildingCode,
        date: date,
        startJie: jie,
        endJie: jie,
      ).then((List<XjtuEmptyRoomInfo> value) {
        done++;
        onProgress?.call(done, 11);
        return value;
      });
    }

    final result = <int, List<XjtuEmptyRoomInfo>>{};
    for (final entry in futures.entries) {
      result[entry.key] = await entry.value;
    }
    return result;
  }

  // ------------------------------------------------------------------ 内部

  Future<List<Map<String, dynamic>>> _postRows(
    String path, {
    required String key,
    Map<String, dynamic>? data,
  }) async {
    final response = await dio.post<String>(
      '$origin$path',
      data: data,
      options: Options(
        contentType: Headers.formUrlEncodedContentType,
        responseType: ResponseType.plain,
        headers: <String, dynamic>{..._jsonHeaders, 'Referer': _referer},
      ),
    );
    final map = _decodeBody(response);

    final datas = map['datas'];
    if (datas is! Map) {
      throw const XjtuEmptyRoomException('教务系统返回缺少 datas 字段');
    }
    final section = datas[key];
    if (section is! Map) {
      throw XjtuEmptyRoomException('教务系统返回缺少 datas.$key');
    }
    final rows = section['rows'];
    if (rows is! List) {
      // extParams.msg 在有数据时只是「查询成功」这类提示，不能当错误。
      final extParams = section['extParams'];
      final message = extParams is Map ? extParams['msg']?.toString() : null;
      throw XjtuEmptyRoomException(message ?? '教务系统未返回数据');
    }
    return rows
        .whereType<Map>()
        .map((Map e) => e.map((k, v) => MapEntry(k.toString(), v)))
        .toList();
  }

  static Map<String, dynamic> _decodeBody(Response<String> response) {
    final status = response.statusCode ?? 0;
    if (status == 301 || status == 302 || status == 303) {
      throw const XjtuEmptyRoomException('教务系统会话已失效，请重新登录');
    }
    final body = response.data ?? '';
    if (body.trimLeft().startsWith('<')) {
      throw const XjtuEmptyRoomException('教务系统会话已失效，请重新登录');
    }
    dynamic decoded;
    try {
      decoded = jsonDecode(body);
    } catch (_) {
      throw const XjtuEmptyRoomException('教务系统返回了无法解析的内容');
    }
    if (decoded is! Map) {
      throw const XjtuEmptyRoomException('教务系统返回结构不是对象');
    }
    final map = decoded.map((k, v) => MapEntry(k.toString(), v));
    final code = map['code']?.toString();
    if (code != null && code != '0' && code != '200') {
      throw XjtuEmptyRoomException(map['msg']?.toString() ?? '教务系统返回错误');
    }
    return map;
  }
}

class XjtuEmptyRoomException implements Exception {
  const XjtuEmptyRoomException(this.message);

  final String message;

  @override
  String toString() => message;
}
