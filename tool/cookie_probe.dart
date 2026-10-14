// 诊断脚本：验证 XDYou 使用的 cookie 机制（dio_cookie_manager + PersistCookieJar）
// 能否正确保存西交 CAS / jwxt 下发的 Set-Cookie。
//
// 背景：本机 xjtu_core 用的是自写拦截器 + SimpleCookieJar，登录一路畅通；
// 而 App 里用 dio_cookie_manager，登录时会在 jwxt 首页与 OAuth 之间打转 ——
// 典型症状是「拿到了 ticket，但 jwxt 侧的会话 cookie 没落地」。
//
//   dart run tool/cookie_probe.dart
//
// 这是命令行诊断工具，输出就该走 stdout。
// ignore_for_file: avoid_print

import 'dart:io';

import 'package:cookie_jar/cookie_jar.dart';
import 'package:dio/dio.dart';
import 'package:dio_cookie_manager/dio_cookie_manager.dart';

const String ua = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) '
    'AppleWebKit/537.36 (KHTML, like Gecko) '
    'Chrome/130.0.0.0 Safari/537.36 XDYou/2.0.0';

Future<void> main() async {
  final dir = Directory.systemTemp.createTempSync('xjtu-cookie-probe');

  // ---- 用和 App 完全一样的配置 ----
  final jar = PersistCookieJar(
    persistSession: true,
    storage: FileStorage('${dir.path}/cookies'),
  );
  final dio = Dio(
    BaseOptions(
      followRedirects: false,
      validateStatus: (int? s) => s != null && s > 0 && s < 600,
      headers: <String, dynamic>{'User-Agent': ua},
    ),
  );
  dio.interceptors.add(CookieManager(jar, ignoreInvalidCookies: true));

  var url = Uri.parse('https://jwxt.xjtu.edu.cn/jwapp/sys/homeapp/index.do');
  print('== 逐跳请求（模拟 _follow）==');
  for (var hop = 0; hop < 8; hop++) {
    final Response<dynamic> response;
    try {
      response = await dio.getUri<dynamic>(url);
    } catch (e) {
      print('    请求异常：$e');
      break;
    }
    final setCookie = response.headers['set-cookie'];
    final location = response.headers.value('location');
    print('[${response.statusCode}] ${url.host}${url.path}');
    if (setCookie != null) {
      for (final c in setCookie) {
        print('    Set-Cookie: $c');
        // 单独验证 dart:io 的解析器能不能吃下这条 —— 吃不下就会被
        // ignoreInvalidCookies 静默丢掉。
        try {
          final parsed = Cookie.fromSetCookieValue(c);
          print('      → 解析 OK: ${parsed.name}=${parsed.value} '
              'domain=${parsed.domain} path=${parsed.path}');
        } catch (e) {
          print('      → ★ 解析失败: $e');
        }
      }
    }
    if (location == null || location.isEmpty) break;
    var next = url.resolve(location);
    if (next.scheme == 'http') next = next.replace(scheme: 'https');
    url = next;
  }

  print('');
  print('== jar 里实际存下来的 cookie ==');
  for (final probe in <String>[
    'https://jwxt.xjtu.edu.cn/jwapp/sys/homeapp/index.do',
    'https://login.xjtu.edu.cn/cas/login',
    'https://login.xjtu.edu.cn/cas/oauth2.0/authorize',
    'https://org.xjtu.edu.cn/openplatform/oauth/authorize',
  ]) {
    final list = await jar.loadForRequest(Uri.parse(probe));
    print('$probe: ${list.length} 个');
    for (final c in list) {
      print('    ${c.name}=${c.value}  (domain=${c.domain} path=${c.path})');
    }
  }

  print('');
  print('== 再跑一遍（此时 jar 已有 cookie，模拟第二次打开 App）==');
  var url2 = Uri.parse('https://jwxt.xjtu.edu.cn/jwapp/sys/homeapp/index.do');
  for (var hop = 0; hop < 10; hop++) {
    final Response<dynamic> response;
    try {
      response = await dio.getUri<dynamic>(url2);
    } catch (e) {
      print('    请求异常：$e');
      break;
    }
    final location = response.headers.value('location');
    print('[${response.statusCode}] ${url2.host}${url2.path}');
    if (location == null || location.isEmpty) break;
    var next = url2.resolve(location);
    if (next.scheme == 'http') next = next.replace(scheme: 'https');
    url2 = next;
  }

  dir.deleteSync(recursive: true);
}
