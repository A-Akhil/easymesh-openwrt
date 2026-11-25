# SPDX-License-Identifier: GPL-2.0-only
include $(TOPDIR)/rules.mk

PKG_NAME:=easymesh-agent
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

PKG_LICENSE:=GPL-2.0-only
PKG_LICENSE_FILES:=LICENSE
# PKG_MAINTAINER must be "Name <email>" before submitting upstream

include $(INCLUDE_DIR)/package.mk

define Package/easymesh-agent
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=WirelessAPD
  TITLE:=Wi-Fi EasyMesh (Multi-AP) agent written in ucode
  DEPENDS:=+ucode +ucode-mod-fs +ucode-mod-socket +ucode-mod-struct +ucode-mod-digest \
	+ucode-mod-uci +ucode-mod-ubus +openssl-util +jsonfilter
  PKGARCH:=all
endef

define Package/easymesh-agent/description
  Joins a Wi-Fi EasyMesh controller (for example a TP-Link EasyMesh router) as an agent:
  WPS Multi-AP onboarding of a 4-address backhaul STA, IEEE 1905.1 AP-Autoconfiguration
  (WSC M1/M2) for every radio, replies to the controller's queries, channel following and
  storage of the backhaul credentials in UCI. Needs a full wpad (WPS and Multi-AP support),
  e.g. wpad-openssl or wpad-mbedtls.
endef

define Package/easymesh-agent/conffiles
/etc/config/easymesh
endef

define Build/Compile
endef

define Package/easymesh-agent/install
	$(INSTALL_DIR) $(1)/usr/share/easymesh $(1)/usr/sbin $(1)/etc/init.d $(1)/etc/config
	$(INSTALL_DATA) ./files/agent.uc $(1)/usr/share/easymesh/agent.uc
	$(INSTALL_BIN) ./files/easymesh-pair $(1)/usr/sbin/easymesh-pair
	$(INSTALL_BIN) ./files/easymesh.init $(1)/etc/init.d/easymesh
	$(INSTALL_CONF) ./files/easymesh.config $(1)/etc/config/easymesh
endef

$(eval $(call BuildPackage,easymesh-agent))
