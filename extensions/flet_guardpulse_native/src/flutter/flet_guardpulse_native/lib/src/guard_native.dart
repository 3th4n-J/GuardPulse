import 'package:flet/flet.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

/// Forwards every Python call on GuardNative to the Kotlin plugin.
class GuardNativeService extends FletService {
  GuardNativeService({required super.control});

  static const MethodChannel _channel = MethodChannel('guardpulse/shield');

  @override
  void init() {
    super.init();
    control.addInvokeMethodListener(_invokeMethod);
  }

  Future<dynamic> _invokeMethod(String name, dynamic args) async {
    final Map<String, dynamic> arguments =
        args is Map ? Map<String, dynamic>.from(args) : <String, dynamic>{};
    try {
      final dynamic result = await _channel.invokeMethod(name, arguments);
      if (result is Map) {
        return Map<String, dynamic>.from(result);
      }
      return result;
    } on PlatformException catch (e) {
      debugPrint("GuardNative.$name failed: ${e.code} ${e.message}");
      rethrow;
    }
  }

  @override
  void dispose() {
    control.removeInvokeMethodListener(_invokeMethod);
    super.dispose();
  }
}
