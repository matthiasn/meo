# OS detection adapted from: https://gist.github.com/sighingnow/deee806603ec9274fd47
OSFLAG 	:=
LEIN 	:=
SHADOW 	:=
YARN := $(shell command -v yarn 2> /dev/null)
JLINK := $(shell command -v jlink 2> /dev/null)

ifeq ($(OS),Windows_NT)
	LEIN := $(shell command -v lein.bat 2> /dev/null)
	SHADOW := $(shell command -v shadow-cljs.cmd 2> /dev/null)
	OSFLAG := -w
else
	LEIN := $(shell command -v lein 2> /dev/null)
	SHADOW := $(shell command -v shadow-cljs 2> /dev/null)
	UNAME_S := $(shell uname -s)
	ifeq ($(UNAME_S),Linux)
		OSFLAG := -l
	endif
	ifeq ($(UNAME_S),Darwin)
		OSFLAG := -m
	endif
	ifeq ($(UNAME_S),CYGWIN_NT-10.0)
		LEIN := $(shell command -v lein.bat 2> /dev/null)
		SHADOW := $(shell command -v shadow-cljs.cmd 2> /dev/null)
		OSFLAG := -w
	endif
endif

package: cljs jsbundle

all: clean deps package

clean: clean-npm clean-pods

clean-npm:
	@echo Cleaning up npm...
	@rm -rf ./node_modules

clean-pods:
	@echo Cleaning up pods...
	@rm -rf ./ios/Pods

deps: npm-deps pod-deps

npm-deps:
	@echo Fetching NPM dependencies...
	@yarn install

pod-deps:
	@echo Fetching Pods...
	@cd ios && pod install && cd ..

link-deps:
	@echo Linking dependencies...
	@react-native link

cljs:
	@echo Building ClojureScript for React Native app...
	@eval $(SHADOW) release app

cljs-shared-tests: npm-deps
	@echo Running ClojureScript tests...
	@eval $(SHADOW) compile shared-tests
	@node out/shared-tests.js

jsbundle:
	@echo Packaging jsbundle...
	@node --expose-gc --max_old_space_size=4096 ./node_modules/react-native/local-cli/cli.js bundle --entry-file app/index.js --platform ios --dev false --bundle-output ios/main.jsbundle --assets-dest ios

version:
	@echo Syncing version numbers...
	react-native-version

pod-install:
	@echo Building and publishing via Fastlane
	cd ios && pod install && cd ..

fastlane-beta:
	@echo Building and publishing Beta via Fastlane
	cd ios && fastlane beta && cd ..

fastlane-nightly:
	@echo Building and publishing Nightly via Fastlane
	cd ios && fastlane nightly && cd ..

fastlane-certificates:
	@echo Installing Certificates via Fastlane
	cd ios && fastlane certificates && cd ..

testflight-nightly: npm-deps pod-install package fastlane-nightly

testflight: npm-deps pod-install package fastlane-beta

jsbundle-android:
	@echo Packaging jsbundle for Android...
	@node --expose-gc --max_old_space_size=4096 ./node_modules/react-native/local-cli/cli.js bundle --platform android --dev false --entry-file app/index.js --bundle-output android/app/src/main/assets/index.android.bundle --assets-dest android/app/src/main/res/

fastlane-beta-android:
	@echo Building Android via Fastlane
	cd android && fastlane build && cd ..

metro:
	@echo Starting Metro Bundler...
	node --expose-gc --max_old_space_size=4096 ./node_modules/react-native/local-cli/cli.js start --reset-cache

android: npm-deps cljs fastlane-beta-android

playstore-upload:
	@echo Uploading to Playstore
	cd android && fastlane deploy && cd ..

playstore: npm-deps cljs fastlane-beta-android playstore-upload

android-install:
	adb install android/app/build/outputs/apk/release/app-release.apk
