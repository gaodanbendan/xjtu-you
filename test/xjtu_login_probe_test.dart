// 复现探针：在本机用 flutter test 跑一遍 XDYou 的真实登录流程。
//
// 目的是拿到真机上报的那个异常：
//   type 'String' is not a subtype of type 'int' of 'index'
//
//   flutter test test/xjtu_login_probe_test.dart

// 命令行诊断/测试脚本，输出就该走 stdout。
// ignore_for_file: avoid_print

import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:watermeter/repository/network_client.dart';
import 'package:watermeter/repository/preference.dart' as preference;
import 'package:watermeter/repository/ids_session/ids_session.dart';
import 'package:watermeter/repository/ids_session/semester_session.dart';
import 'package:watermeter/repository/xjtu_session/xjtu_auth.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test('真实登录 + 取学期', () async {
    // ---- 初始化 App 依赖 ----
    final dir = Directory.systemTemp.createTempSync('xjtu-login-probe');
    supportPath = dir;
    // ignore: invalid_use_of_visible_for_testing_member
    SharedPreferences.setMockInitialValues(<String, Object>{});
    preference.prefs = await SharedPreferencesWithCache.create(
      cacheOptions: const SharedPreferencesWithCacheOptions(),
    );

    // 需要验证码时直接放弃（本次不需要）
    XjtuAuth.mfaCodeProvider = (String phone) async {
      print('  [探针] 服务端要求短信验证码 → $phone');
      return null;
    };
    XjtuAuth.accountChoiceProvider = (List<XjtuAccountChoice> c) async {
      print('  [探针] 要求选择身份：${c.map((e) => e.name).toList()}');
      return true;
    };

    // ---- 走 login_window 里那条真实调用链 ----
    const user = '2263712725';
    const pass = '060412Gxr.';

    print('=== [1] IDSSession().login ===');
    try {
      final ses = IDSSession();
      await ses.login(username: user, password: pass, forceReLogin: true);
      print('  ✓ 登录成功，loginState=$loginState');
    } catch (e, s) {
      print('  ✗ 登录崩了：${e.runtimeType}');
      print('    $e');
      print('    堆栈前 12 行：');
      print(s.toString().split('\n').take(12).join('\n'));
      return;
    }

    print('');
    print('=== [2] checkWhetherPostgraduate ===');
    try {
      final isPg = await IDSSession().checkWhetherPostgraduate();
      print('  ✓ isPostGraduate=$isPg');
    } catch (e, s) {
      print('  ✗ 崩了：${e.runtimeType} → $e');
      print(s.toString().split('\n').take(8).join('\n'));
    }

    print('');
    print('=== [3] SemesterSession().getSemesterInfoEhall ===');
    try {
      final code = await SemesterSession().getSemesterInfoEhall();
      print('  ✓ 学期 = $code');
    } catch (e, s) {
      print('  ✗ 崩了：${e.runtimeType}');
      print('    $e');
      print('    堆栈前 12 行：');
      print(s.toString().split('\n').take(12).join('\n'));
    }

    print('');
    print('=== [4] 课表（classtable_session）===');
    try {
      final semester = preference.getString(
        preference.Preference.currentSemester,
      );
      print('  当前学期 = $semester');
    } catch (e) {
      print('  ✗ $e');
    }
  }, timeout: const Timeout(Duration(minutes: 5)));
}
