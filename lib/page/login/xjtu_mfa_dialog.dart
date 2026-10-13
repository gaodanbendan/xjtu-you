// Copyright 2026 XJTU fork authors.
// SPDX-License-Identifier: MPL-2.0

// 西交统一身份认证的短信验证码输入框。
//
// 西交的二次认证是「向绑定手机发 6 位验证码」，与西电的滑块/企业微信不同，
// 所以单独提供一个最小对话框，由 XjtuAuth.mfaCodeProvider 在登录流程中唤起。

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

Future<String?> showXjtuMfaDialog(
  BuildContext context,
  String maskedPhone,
) async {
  final controller = TextEditingController();
  final result = await showDialog<String>(
    context: context,
    barrierDismissible: false,
    builder: (BuildContext ctx) => AlertDialog(
      title: const Text('短信二次验证'),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: <Widget>[
          Text(
            '验证码已发送到 $maskedPhone，请输入收到的 6 位数字。',
            style: Theme.of(ctx).textTheme.bodyMedium,
          ),
          const SizedBox(height: 12),
          TextField(
            controller: controller,
            autofocus: true,
            keyboardType: TextInputType.number,
            maxLength: 8,
            inputFormatters: <TextInputFormatter>[
              FilteringTextInputFormatter.digitsOnly,
            ],
            decoration: const InputDecoration(
              labelText: '短信验证码',
              border: OutlineInputBorder(),
              counterText: '',
            ),
            onSubmitted: (String value) =>
                Navigator.of(ctx).pop(value.trim()),
          ),
        ],
      ),
      actions: <Widget>[
        TextButton(
          onPressed: () => Navigator.of(ctx).pop(null),
          child: const Text('取消'),
        ),
        FilledButton(
          onPressed: () => Navigator.of(ctx).pop(controller.text.trim()),
          child: const Text('确定'),
        ),
      ],
    ),
  );
  controller.dispose();
  return result;
}

/// 账号有多个身份时让用户选择（西交统一认证特有）。
Future<bool> showXjtuAccountChoiceDialog(
  BuildContext context,
  List<String> descriptions,
) async {
  final result = await showDialog<bool>(
    context: context,
    barrierDismissible: false,
    builder: (BuildContext ctx) => AlertDialog(
      title: const Text('选择身份'),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: <Widget>[
          const Text('该账号下有多个身份，请选择要登录的身份：'),
          const SizedBox(height: 8),
          ...descriptions.map(
            (String description) => Padding(
              padding: const EdgeInsets.symmetric(vertical: 2.0),
              child: Text('· $description'),
            ),
          ),
        ],
      ),
      actions: <Widget>[
        TextButton(
          onPressed: () => Navigator.of(ctx).pop(false),
          child: const Text('研究生'),
        ),
        FilledButton(
          onPressed: () => Navigator.of(ctx).pop(true),
          child: const Text('本科生'),
        ),
      ],
    ),
  );
  return result ?? true;
}
