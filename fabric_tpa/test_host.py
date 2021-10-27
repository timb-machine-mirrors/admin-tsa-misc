from . import host


def test_parse_rewrite_interfaces_diff():
    diff = '''--- /mnt/etc/network/interfaces.bak	2020-04-01 21:11:20.501228991 +0000
+++ /mnt/etc/network/interfaces	2020-04-01 21:11:21.701219470 +0000
@@ -1,11 +1,16 @@
+# This file describes the network interfaces available on your system
+# and how to activate them. For more information, see interfaces(5).
+
+# The loopback network interface
 auto lo
 iface lo inet loopback

-allow-hotplug eth0
+# The primary network interface
+auto eth0
 iface eth0 inet static
-    address 138.201.212.227/28
-    gateway 138.201.212.225
+    address 116.202.120.188/27
+    gateway 116.202.120.161
 iface eth0 inet6 static
     accept_ra 0
-    address 2a01:4f8:172:39ca:0:dad3:3:1/96
-    gateway 2a01:4f8:172:39ca:0:dad3:0:1
+    address 2a01:4f8:fff0:4f:266:37ff:fe80:b04/64
+    gateway 2a01:4f8:fff0:4f::1
'''
    assert ("138.201.212.227", "2a01:4f8:172:39ca:0:dad3:3:1") == host.parse_rewrite_interfaces_diff(diff)
