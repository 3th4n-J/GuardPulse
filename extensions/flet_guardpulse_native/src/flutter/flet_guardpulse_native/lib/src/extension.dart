import 'package:flet/flet.dart';

import 'guard_native.dart';

class Extension extends FletExtension {
  @override
  FletService? createService(Control control) {
    switch (control.type) {
      case "GuardNative":
        return GuardNativeService(control: control);
      default:
        return null;
    }
  }
}
