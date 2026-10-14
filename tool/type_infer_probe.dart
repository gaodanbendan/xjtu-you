// 决定性测试：Dart 的类型推断会不会让 dio 把 JSON 对象 toString 掉。
//
// 照抄 classtable_session.dart 与 semester_session.dart 的原始写法：
//     String x = await dio.post(url).then((v) => v.data['datas']...['字段']);
//
// 如果赋值目标的 String 约束传到泛型 T 上，dio 会把已经解析好的 Map 又
// toString 一遍，于是 v.data['datas'] 变成「对 String 取下标」，抛
//     type 'String' is not a subtype of type 'int' of 'index'
//
//   dart run tool/type_infer_probe.dart [cookie文件]

// 命令行诊断/测试脚本，输出就该走 stdout。
// ignore_for_file: avoid_print

import 'dart:io';

import 'package:dio/dio.dart';

const String ua = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) '
    'AppleWebKit/537.36 (KHTML, like Gecko) '
    'Chrome/130.0.0.0 Safari/537.36 XDYou/2.0.0';

Future<void> main(List<String> args) async {
  final jarPath = args.isNotEmpty ? args.first : '/tmp/cj_login.txt';
  final file = File(jarPath);
  if (!file.existsSync()) {
    stderr.writeln('找不到 cookie 文件：$jarPath');
    exit(2);
  }
  final cookies = <String>[];
  for (final line in file.readAsLinesSync()) {
    if (!line.contains('\t')) continue;
    final fields = line.split('\t');
    if (fields.length < 7) continue;
    cookies.add('${fields[5]}=${fields[6]}');
  }
  print('cookie 条数: ${cookies.length}');

  final dio = Dio(
    BaseOptions(
      followRedirects: false,
      validateStatus: (int? s) => s != null && s > 0 && s < 600,
      headers: <String, dynamic>{
        'User-Agent': ua,
        'Cookie': cookies.join('; '),
      },
    ),
  );

  const termStartUrl =
      'https://jwxt.xjtu.edu.cn/jwapp/sys/wdkb/modules/jshkcb/cxjcs.do';
  const semesterUrl =
      'https://jwxt.xjtu.edu.cn/jwapp/sys/wdkb/modules/jshkcb/dqxnxq.do';

  // ---------- 测试 1：照抄 classtable_session.dart:366 ----------
  print('');
  print('=== 测试 1：String x = await dio.post(..).then((v) => v.data[...]) ===');
  try {
    String termStartDay = await dio
        .post(
          termStartUrl,
          data: <String, dynamic>{'XN': '2026-2027', 'XQ': '1'},
        )
        .then((value) => value.data['datas']['cxjcs']['rows'][0]["XQKSRQ"]);
    print('  ✅ 没崩，值 = $termStartDay');
  } catch (e) {
    print('  ❌ 异常：${e.runtimeType}');
    print('     $e');
  }

  // ---------- 测试 2：照抄 semester_session.dart:52 ----------
  print('');
  print("=== 测试 2：String x = await dio.post(..).then((v) => v.data[...][DM]) ===");
  try {
    String semesterCode = await dio
        .post(semesterUrl)
        .then((value) => value.data['datas']['dqxnxq']['rows'][0]['DM']);
    print('  ✅ 没崩，值 = $semesterCode');
  } catch (e) {
    print('  ❌ 异常：${e.runtimeType}');
    print('     $e');
  }

  // ---------- 测试 3：不约束返回类型 ----------
  print('');
  print('=== 测试 3：final r = await dio.post(..)（无类型约束）===');
  try {
    final r = await dio.post(semesterUrl);
    print('  data 运行时类型 = ${r.data.runtimeType}');
  } catch (e) {
    print('  ❌ 异常：$e');
  }

  // ---------- 测试 4：显式 plain + 手动解析（我们的修法）----------
  print('');
  print('=== 测试 4：post<dynamic> + ResponseType.plain + 手动解析 ===');
  try {
    final r = await dio.post<dynamic>(
      semesterUrl,
      options: Options(
        responseType: ResponseType.plain,
        contentType: Headers.formUrlEncodedContentType,
      ),
    );
    print('  data 运行时类型 = ${r.data.runtimeType}');
    print('  前 80 字 = ${r.data.toString().substring(0, 80)}');
  } catch (e) {
    print('  ❌ 异常：$e');
  }
}
