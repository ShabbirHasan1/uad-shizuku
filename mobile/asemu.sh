#!/usr/bin/env bash

# WIP
# android studio emulator management build script for running android build in asemu guest.

# install sdkmanager if not exists
if [ ! -f /root/.android/Sdk/cmdline-tools/latest/bin/sdkmanager ]; then
  mkdir -p /root/.android/Sdk/cmdline-tools
  wget -O /root/.android/Sdk/cmdline-tools/commandlinetools.zip https://dl.google.com/android/repository/commandlinetools-linux-9477386_latest.zip
  unzip /root/.android/Sdk/cmdline-tools/commandlinetools.zip -d /root/.android/Sdk/cmdline-tools
  mv /root/.android/Sdk/cmdline-tools/cmdline-tools /root/.android/Sdk/cmdline-tools/latest
  rm /root/.android/Sdk/cmdline-tools/commandlinetools.zip
fi

# install avd manager if not exists
if [ ! -f /root/.android/Sdk/emulator/emulator ]; then
    /root/.android/Sdk/cmdline-tools/latest/bin/sdkmanager --sdk_root=/root/.android/Sdk "platform-tools" "emulator" "platforms;android-34" "system-images;android-34;google_apis_playstore;arm64-v8a"
fi

# create pixel 6 avd if not exists
if [ ! -f /root/.android/Sdk/.avd/MyEmulatorDevice.avd/config.ini ]; then
    /root/.android/Sdk/cmdline-tools/latest/bin/avdmanager create avd -n MyEmulatorDevice -k "system-images;android-34;google_apis_playstore;arm64-v8a" --device pixel_6
fi

# list android devices
/root/.android/Sdk/emulator/emulator -list-avds

# run the emulator
/root/.android/Sdk/emulator/emulator -avd MyEmulatorDevice -no-snapshot -no-audio -no-boot-anim -gpu swiftshader_indirect &

# wait for the emulator to boot
echo "Waiting for the emulator to boot..."
/root/.android/Sdk/platform-tools/adb wait-for-device
echo "Emulator booted."

