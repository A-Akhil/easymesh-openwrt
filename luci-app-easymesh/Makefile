# SPDX-License-Identifier: GPL-2.0-only
include $(TOPDIR)/rules.mk

LUCI_TITLE:=LuCI page for the EasyMesh agent (status and WPS pairing button)
LUCI_DEPENDS:=+luci-base +rpcd-mod-ucode +easymesh-agent
LUCI_PKGARCH:=all

PKG_LICENSE:=GPL-2.0-only
LUCI_MAINTAINER:=Akhil Arul <akhilarul324@gmail.com>

# inside the openwrt/luci tree this is "include ../../luci.mk"
include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
