// Copyright 2023-2025 BenderBlog Rodriguez and contributors
// Copyright 2025 Traintime PDA authors.
// Copyright 2026 XJTU fork authors.
// SPDX-License-Identifier: MPL-2.0

// 空闲教室查询（西安交通大学版）。
//
// 【对外接口刻意保持与西电版一致】：
//   - getBuildingList() -> List<EmptyClassroomPlace>
//   - searchData({buildingCode, date, semesterRange, semesterPart})
//     -> List<EmptyClassroomData>（每间教室 11 个节次的占用情况）
// 所以 lib/page/empty_classroom/ 下的界面一行都不用改。
//
// 内部实现完全换掉了：西电走 `sys/kxjas/modules/kxjas/cxjsqk.do`，一次返回
// 全天占用表；西交走 `sys/kxjas/modules/kxjscx/cxkxjs.do`，一次只能回答一个
// 节次区间，全天表格由 11 个并发查询反推。细节见 xjtu_empty_room.dart。
//
// 当前只实现兴庆校区（用户 2026-10-14 确认）。要加别的校区，把 campusCode
// 换成对应代码即可 —— 校区字典：
//   兴庆=1  雁塔=2  曲江=3  苏州=4  创新港=5  海南国际学院=8

import 'dart:developer' as developer;

import 'package:watermeter/model/xidian_ids/empty_classroom.dart';
import 'package:watermeter/repository/ids_session/ids_session.dart';
import 'package:watermeter/repository/logger.dart';
import 'package:watermeter/repository/xjtu_session/xjtu_empty_room.dart';

class EmptyClassroomSession extends IDSSession {
  /// 兴庆校区。
  static const String campusCode = XjtuEmptyRoomClient.xingqingCampusCode;

  /// 空闲教室页面地址。西交的这个页面挂在 kxjas 下。
  static const String target =
      '${XjtuEmptyRoomClient.origin}/jwapp/sys/kxjas/*default/index.do';

  XjtuEmptyRoomClient get _client => XjtuEmptyRoomClient(dioNoOfflineCheck);

  /// This is the first function we need to execute.
  ///
  /// 只返回兴庆校区的教学楼。
  Future<List<EmptyClassroomPlace>> getBuildingList() async {
    developer.log('Ready to login the system.', name: 'XJTU emptyClassroom');
    await checkAndLogin(
      target: target,
      // 西交不使用滑块验证码，这个回调不会被调用。
      sliderCaptcha: (String _) async {},
    );

    // 空闲教室只在「学生」身份下可用，在「移动应用学生」身份下查不到数据。
    await _client.ensureStudentRole();

    final buildings = await _client.fetchBuildings(campusCode: campusCode);
    log.info('[XJTU emptyClassroom] 兴庆校区教学楼 ${buildings.length} 栋');

    return buildings
        .map(
          (XjtuBuilding building) => EmptyClassroomPlace(
            code: building.id,
            name: building.name,
          ),
        )
        .toList();
  }

  /// 查询某栋教学楼在某天的教室占用情况。
  ///
  /// 参数沿用西电版签名：
  /// - [buildingCode] 教学楼代码，来自 [getBuildingList]。
  /// - [date] `yyyy-MM-dd` 格式的日期。
  /// - [semesterRange] / [semesterPart] 在西交接口里没有对应参数，忽略。
  Future<List<EmptyClassroomData>> searchData({
    required String buildingCode,
    required String date,
    required String semesterRange,
    required String semesterPart,
  }) async {
    // 11 个节次并发查询，实测约 0.5 秒。
    final byJie = await _client.fetchRoomsInDay(
      campusCode: campusCode,
      buildingCode: buildingCode,
      date: date,
    );

    // 汇总全天出现过的教室。全天满课的教室不会出现在任何一节里，
    // 因此自然被排除掉 —— 它本来也不是「空闲教室」。
    final names = <String>{};
    for (final rooms in byJie.values) {
      for (final room in rooms) {
        names.add(room.name);
      }
    }

    final sorted = names.toList()..sort();
    log.info(
      '[XJTU emptyClassroom] $date $buildingCode：'
      '${sorted.length} 间教室有休息时段',
    );

    return sorted
        .map(
          (String name) => EmptyClassroomData(
            name: name,
            isUsed: List<bool>.generate(
              11,
              // 该节次的空闲列表里没有它，就说明那一节被占用。
              (int index) => !(byJie[index + 1] ?? const <XjtuEmptyRoomInfo>[])
                  .any((XjtuEmptyRoomInfo room) => room.name == name),
              growable: false,
            ),
          ),
        )
        .toList();
  }
}
