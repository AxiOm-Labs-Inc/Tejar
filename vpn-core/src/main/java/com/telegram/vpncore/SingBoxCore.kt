package com.telegram.vpncore

/** Facts about the bundled sing-box core (`libs/libbox.aar`). */
object SingBoxCore {

    /**
     * Version string baked into libbox.so (`Libbox.version()` returns it; found in the .so's
     * strings, identical across ABIs). A constant rather than a runtime call: the User-Agent is
     * needed before the native library is loaded. Update together with libbox.aar.
     */
    const val VERSION = "1.13.19"
}
