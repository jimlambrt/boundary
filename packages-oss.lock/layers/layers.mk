# ***
# WARNING: Do not EDIT or MERGE this file, it is generated by packagespec.
# ***

LAYER_00-base-b2f59b2d4223729e0cfca83f651ade1039b52e39_ID             := 00-base-b2f59b2d4223729e0cfca83f651ade1039b52e39
LAYER_00-base-b2f59b2d4223729e0cfca83f651ade1039b52e39_TYPE           := base
LAYER_00-base-b2f59b2d4223729e0cfca83f651ade1039b52e39_BASE_LAYER     := 
LAYER_00-base-b2f59b2d4223729e0cfca83f651ade1039b52e39_SOURCE_INCLUDE := 
LAYER_00-base-b2f59b2d4223729e0cfca83f651ade1039b52e39_SOURCE_EXCLUDE := 
LAYER_00-base-b2f59b2d4223729e0cfca83f651ade1039b52e39_CACHE_KEY_FILE := .buildcache/cache-keys/base-b2f59b2d4223729e0cfca83f651ade1039b52e39
LAYER_00-base-b2f59b2d4223729e0cfca83f651ade1039b52e39_ARCHIVE_FILE   := .buildcache/archives/00-base-b2f59b2d4223729e0cfca83f651ade1039b52e39.tar.gz
$(eval $(call LAYER,$(LAYER_00-base-b2f59b2d4223729e0cfca83f651ade1039b52e39_ID),$(LAYER_00-base-b2f59b2d4223729e0cfca83f651ade1039b52e39_TYPE),$(LAYER_00-base-b2f59b2d4223729e0cfca83f651ade1039b52e39_BASE_LAYER),$(LAYER_00-base-b2f59b2d4223729e0cfca83f651ade1039b52e39_SOURCE_INCLUDE),$(LAYER_00-base-b2f59b2d4223729e0cfca83f651ade1039b52e39_SOURCE_EXCLUDE),$(LAYER_00-base-b2f59b2d4223729e0cfca83f651ade1039b52e39_CACHE_KEY_FILE),$(LAYER_00-base-b2f59b2d4223729e0cfca83f651ade1039b52e39_ARCHIVE_FILE)))

LAYER_01-ui-855160c42f310f22f923602dcdad2a99954567e3_ID             := 01-ui-855160c42f310f22f923602dcdad2a99954567e3
LAYER_01-ui-855160c42f310f22f923602dcdad2a99954567e3_TYPE           := ui
LAYER_01-ui-855160c42f310f22f923602dcdad2a99954567e3_BASE_LAYER     := 00-base-b2f59b2d4223729e0cfca83f651ade1039b52e39
LAYER_01-ui-855160c42f310f22f923602dcdad2a99954567e3_SOURCE_INCLUDE := internal/ui/VERSION
LAYER_01-ui-855160c42f310f22f923602dcdad2a99954567e3_SOURCE_EXCLUDE := 
LAYER_01-ui-855160c42f310f22f923602dcdad2a99954567e3_CACHE_KEY_FILE := .buildcache/cache-keys/ui-855160c42f310f22f923602dcdad2a99954567e3
LAYER_01-ui-855160c42f310f22f923602dcdad2a99954567e3_ARCHIVE_FILE   := .buildcache/archives/01-ui-855160c42f310f22f923602dcdad2a99954567e3.tar.gz
$(eval $(call LAYER,$(LAYER_01-ui-855160c42f310f22f923602dcdad2a99954567e3_ID),$(LAYER_01-ui-855160c42f310f22f923602dcdad2a99954567e3_TYPE),$(LAYER_01-ui-855160c42f310f22f923602dcdad2a99954567e3_BASE_LAYER),$(LAYER_01-ui-855160c42f310f22f923602dcdad2a99954567e3_SOURCE_INCLUDE),$(LAYER_01-ui-855160c42f310f22f923602dcdad2a99954567e3_SOURCE_EXCLUDE),$(LAYER_01-ui-855160c42f310f22f923602dcdad2a99954567e3_CACHE_KEY_FILE),$(LAYER_01-ui-855160c42f310f22f923602dcdad2a99954567e3_ARCHIVE_FILE)))

LAYER_02-go-modules-9bbdb533d1908af0a369ec790a3b318b7cd11e74_ID             := 02-go-modules-9bbdb533d1908af0a369ec790a3b318b7cd11e74
LAYER_02-go-modules-9bbdb533d1908af0a369ec790a3b318b7cd11e74_TYPE           := go-modules
LAYER_02-go-modules-9bbdb533d1908af0a369ec790a3b318b7cd11e74_BASE_LAYER     := 01-ui-855160c42f310f22f923602dcdad2a99954567e3
LAYER_02-go-modules-9bbdb533d1908af0a369ec790a3b318b7cd11e74_SOURCE_INCLUDE := go.mod go.sum */go.mod */go.sum
LAYER_02-go-modules-9bbdb533d1908af0a369ec790a3b318b7cd11e74_SOURCE_EXCLUDE := 
LAYER_02-go-modules-9bbdb533d1908af0a369ec790a3b318b7cd11e74_CACHE_KEY_FILE := .buildcache/cache-keys/go-modules-9bbdb533d1908af0a369ec790a3b318b7cd11e74
LAYER_02-go-modules-9bbdb533d1908af0a369ec790a3b318b7cd11e74_ARCHIVE_FILE   := .buildcache/archives/02-go-modules-9bbdb533d1908af0a369ec790a3b318b7cd11e74.tar.gz
$(eval $(call LAYER,$(LAYER_02-go-modules-9bbdb533d1908af0a369ec790a3b318b7cd11e74_ID),$(LAYER_02-go-modules-9bbdb533d1908af0a369ec790a3b318b7cd11e74_TYPE),$(LAYER_02-go-modules-9bbdb533d1908af0a369ec790a3b318b7cd11e74_BASE_LAYER),$(LAYER_02-go-modules-9bbdb533d1908af0a369ec790a3b318b7cd11e74_SOURCE_INCLUDE),$(LAYER_02-go-modules-9bbdb533d1908af0a369ec790a3b318b7cd11e74_SOURCE_EXCLUDE),$(LAYER_02-go-modules-9bbdb533d1908af0a369ec790a3b318b7cd11e74_CACHE_KEY_FILE),$(LAYER_02-go-modules-9bbdb533d1908af0a369ec790a3b318b7cd11e74_ARCHIVE_FILE)))

LAYER_03-copy-source-b846999949732b4909705805bc966271a781f9ad_ID             := 03-copy-source-b846999949732b4909705805bc966271a781f9ad
LAYER_03-copy-source-b846999949732b4909705805bc966271a781f9ad_TYPE           := copy-source
LAYER_03-copy-source-b846999949732b4909705805bc966271a781f9ad_BASE_LAYER     := 02-go-modules-9bbdb533d1908af0a369ec790a3b318b7cd11e74
LAYER_03-copy-source-b846999949732b4909705805bc966271a781f9ad_SOURCE_INCLUDE := *.go
LAYER_03-copy-source-b846999949732b4909705805bc966271a781f9ad_SOURCE_EXCLUDE := 
LAYER_03-copy-source-b846999949732b4909705805bc966271a781f9ad_CACHE_KEY_FILE := .buildcache/cache-keys/copy-source-b846999949732b4909705805bc966271a781f9ad
LAYER_03-copy-source-b846999949732b4909705805bc966271a781f9ad_ARCHIVE_FILE   := .buildcache/archives/03-copy-source-b846999949732b4909705805bc966271a781f9ad.tar.gz
$(eval $(call LAYER,$(LAYER_03-copy-source-b846999949732b4909705805bc966271a781f9ad_ID),$(LAYER_03-copy-source-b846999949732b4909705805bc966271a781f9ad_TYPE),$(LAYER_03-copy-source-b846999949732b4909705805bc966271a781f9ad_BASE_LAYER),$(LAYER_03-copy-source-b846999949732b4909705805bc966271a781f9ad_SOURCE_INCLUDE),$(LAYER_03-copy-source-b846999949732b4909705805bc966271a781f9ad_SOURCE_EXCLUDE),$(LAYER_03-copy-source-b846999949732b4909705805bc966271a781f9ad_CACHE_KEY_FILE),$(LAYER_03-copy-source-b846999949732b4909705805bc966271a781f9ad_ARCHIVE_FILE)))
