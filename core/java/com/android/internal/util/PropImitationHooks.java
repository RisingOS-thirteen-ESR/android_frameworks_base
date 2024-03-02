/*
 * Copyright (C) 2022 Paranoid Android
 *           (C) 2023 ArrowOS
 *           (C) 2023 The LibreMobileOS Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.internal.util;

import android.app.ActivityTaskManager;
import android.app.Application;
import android.app.TaskStackListener;
import android.content.ComponentName;
import android.content.Context;
import android.content.res.Resources;
import android.os.Build;
import android.os.Binder;
import android.os.Process;
import android.os.SystemProperties;
import android.text.TextUtils;
import android.util.Log;

import com.android.internal.R;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class PropImitationHooks {

    private static final String TAG = "PropImitationHooks";
    private static final boolean DEBUG = false;

    private static final String[] sCertifiedProps =
            Resources.getSystem().getStringArray(R.array.config_certifiedBuildProperties);

    private static final String sStockFp =
            Resources.getSystem().getString(R.string.config_stockFingerprint);

    private static final String PACKAGE_ARCORE = "com.google.ar.core";
    private static final String PACKAGE_FINSKY = "com.android.vending";
    private static final String PACKAGE_GMS = "com.google.android.gms";
    private static final String PROCESS_GMS_UNSTABLE = PACKAGE_GMS + ".unstable";


    private static final ComponentName GMS_ADD_ACCOUNT_ACTIVITY = ComponentName.unflattenFromString(
            "com.google.android.gms/.auth.uiflows.minutemaid.MinuteMaidActivity");

    private static final Map<String, Object> asusROG1Props = createGameProps("ASUS_Z01QD", "Asus");
    private static final Map<String, Object> asusROG3Props = createGameProps("ASUS_I003D", "Asus");
    private static final Map<String, Object> xperia5Props = createGameProps("SO-52A", "Sony");
    private static final Map<String, Object> op8ProProps = createGameProps("IN2020", "OnePlus");
    private static final Map<String, Object> op9RProps = createGameProps("LE2101", "OnePlus");
    private static final Map<String, Object> xmMi11TProps = createGameProps("21081111RG", "Xiaomi");
    private static final Map<String, Object> xmF4Props = createGameProps("22021211RG", "Xiaomi");

    private static Map<String, Object> createGameProps(String model, String manufacturer) {
        Map<String, Object> props = new HashMap<>();
        props.put("MODEL", model);
        props.put("MANUFACTURER", manufacturer);
        return props;
    }

    private static final Set<String> packagesToChangeROG1 = new HashSet<>(Arrays.asList(
            "com.madfingergames.legends"
    ));

    private static final Set<String> packagesToChangeROG3 = new HashSet<>(Arrays.asList(
            "com.pearlabyss.blackdesertm",
            "com.pearlabyss.blackdesertm.gl"
    ));

    private static final Set<String> packagesToChangeXP5 = new HashSet<>(Arrays.asList(
            "com.activision.callofduty.shooter",
            "com.garena.game.codm",
            "com.tencent.tmgp.kr.codm",
            "com.vng.codmvn"
    ));

    private static final Set<String> packagesToChangeOP8P = new HashSet<>(Arrays.asList(
            "com.netease.lztgglobal",
            "com.pubg.imobile",
            "com.pubg.krmobile",
            "com.rekoo.pubgm",
            "com.riotgames.league.wildrift",
            "com.riotgames.league.wildrifttw",
            "com.riotgames.league.wildriftvn",
            "com.tencent.ig",
            "com.tencent.tmgp.pubgmhd",
            "com.vng.pubgmobile"
    ));

    private static final Set<String> packagesToChangeOP9R = new HashSet<>(Arrays.asList(
            "com.epicgames.fortnite",
            "com.epicgames.portal"
    ));

    private static final Set<String> packagesToChange11T = new HashSet<>(Arrays.asList(
            "com.ea.gp.apexlegendsmobilefps",
            "com.levelinfinite.hotta.gp",
            "com.mobile.legends",
            "com.supercell.clashofclans",
            "com.tencent.tmgp.sgame",
            "com.vng.mlbbvn"
    ));

    private static final Set<String> packagesToChangeF4 = new HashSet<>(Arrays.asList(
            "com.dts.freefiremax",
            "com.dts.freefireth"
    ));

    private static volatile String sProcessName;
    private static volatile boolean sIsGms, sIsFinsky;

    public static void setProps(Context context) {
        final String packageName = context.getPackageName();
        final String processName = Application.getProcessName();

        if (TextUtils.isEmpty(packageName) || TextUtils.isEmpty(processName)) {
            Log.e(TAG, "Null package or process name");
            return;
        }

        sProcessName = processName;
        sIsGms = packageName.equals(PACKAGE_GMS) && processName.equals(PROCESS_GMS_UNSTABLE);
        sIsFinsky = packageName.equals(PACKAGE_FINSKY);

        /* Set certified properties for GMSCore
         * Set stock fingerprint for ARCore
         */
        if (sIsGms) {
            setCertifiedPropsForGms();
        } else if (packageName.equals(PACKAGE_GMS)) {
            dlog("Setting fresh build date for: " + packageName);
            setPropValue("TIME", System.currentTimeMillis());
        } else if (!sStockFp.isEmpty() && packageName.equals(PACKAGE_ARCORE)) {
            dlog("Setting stock fingerprint for: " + packageName);
            setPropValue("FINGERPRINT", sStockFp);
        } else {
            if (SystemProperties.getBoolean("persist.sys.pixelprops.games", false)) {
                Map<String, Object> gamePropsToSpoof = null;
                if (packagesToChangeROG1.contains(packageName)) {
                    dlog("Spoofing as Asus ROG 1 for: " + packageName);
                    gamePropsToSpoof = asusROG1Props;
                } else if (packagesToChangeROG3.contains(packageName)) {
                    dlog("Spoofing as Asus ROG 3 for: " + packageName);
                    gamePropsToSpoof = asusROG3Props;
                } else if (packagesToChangeXP5.contains(packageName)) {
                    dlog("Spoofing as Sony Xperia 5 for: " + packageName);
                    gamePropsToSpoof = xperia5Props;
                } else if (packagesToChangeOP8P.contains(packageName)) {
                    dlog("Spoofing as Oneplus 8 Pro for: " + packageName);
                    gamePropsToSpoof = op8ProProps;
                } else if (packagesToChangeOP9R.contains(packageName)) {
                    dlog("Spoofing as Oneplus 9R for: " + packageName);
                    gamePropsToSpoof = op9RProps;
                } else if (packagesToChange11T.contains(packageName)) {
                    dlog("Spoofing as Xiaomi Mi 11T for: " + packageName);
                    gamePropsToSpoof = xmMi11TProps;
                } else if (packagesToChangeF4.contains(packageName)) {
                    dlog("Spoofing as Xiaomi F4 for: " + packageName);
                    gamePropsToSpoof = xmF4Props;
                }
                if (gamePropsToSpoof != null) {
                    gamePropsToSpoof.forEach((k, v) -> setPropValue(k, v));
                }
            }
        }
    }

    private static void setPropValue(String key, Object value) {
        try {
            dlog("Setting prop " + key + " to " + value.toString());
            Field field = Build.class.getDeclaredField(key);
            field.setAccessible(true);
            field.set(null, value);
            field.setAccessible(false);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            Log.e(TAG, "Failed to set prop " + key, e);
        }
    }

    private static void setVersionFieldString(String key, String value) {
        try {
            dlog("Setting prop " + key + " to " + value.toString());
            Field field = Build.VERSION.class.getDeclaredField(key);
            field.setAccessible(true);
            field.set(null, value);
            field.setAccessible(false);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            Log.e(TAG, "Failed to spoof prop " + key, e);
        }
    }

    private static void setCertifiedPropsForGms() {
        if (sCertifiedProps.length != 8) {
            Log.e(TAG, "Insufficient array size for certified props: "
                    + sCertifiedProps.length + ", required 8");
            return;
        }
        final boolean was = isGmsAddAccountActivityOnTop();
        final TaskStackListener taskStackListener = new TaskStackListener() {
            @Override
            public void onTaskStackChanged() {
                final boolean is = isGmsAddAccountActivityOnTop();
                if (is ^ was) {
                    dlog("GmsAddAccountActivityOnTop is:" + is + " was:" + was +
                            ", killing myself!"); // process will restart automatically later
                    Process.killProcess(Process.myPid());
                }
            }
        };
        if (!was) {
            dlog("Spoofing build for GMS");
            setPropValue("DEVICE", sCertifiedProps[0]);
            setPropValue("PRODUCT", sCertifiedProps[1]);
            setPropValue("MODEL", sCertifiedProps[2]);
            setPropValue("FINGERPRINT", sCertifiedProps[3]);
            setPropValue("BRAND", sCertifiedProps[4]);
            setPropValue("MANUFACTURER", sCertifiedProps[5]);
            setVersionFieldString("SECURITY_PATCH", sCertifiedProps[6]);
            if (sCertifiedProps[7].isEmpty()) {
            	dlog("Skip spoofing first API level, because it is empty");
            } else {
                setPropValue("FIRST_API_LEVEL", sCertifiedProps[7]);
            }
        } else {
            dlog("Skip spoofing build for GMS, because GmsAddAccountActivityOnTop");
        }
        try {
            ActivityTaskManager.getService().registerTaskStackListener(taskStackListener);
        } catch (Exception e) {
            Log.e(TAG, "Failed to register task stack listener!", e);
        }
    }

    private static boolean isGmsAddAccountActivityOnTop() {
        try {
            final ActivityTaskManager.RootTaskInfo focusedTask =
                    ActivityTaskManager.getService().getFocusedRootTaskInfo();
            return focusedTask != null && focusedTask.topActivity != null
                    && focusedTask.topActivity.equals(GMS_ADD_ACCOUNT_ACTIVITY);
        } catch (Exception e) {
            Log.e(TAG, "Unable to get top activity!", e);
        }
        return false;
    }

    public static boolean shouldBypassTaskPermission(Context context) {
        // GMS doesn't have MANAGE_ACTIVITY_TASKS permission
        final int callingUid = Binder.getCallingUid();
        final int gmsUid;
        try {
            gmsUid = context.getPackageManager().getApplicationInfo(PACKAGE_GMS, 0).uid;
            dlog("shouldBypassTaskPermission: gmsUid:" + gmsUid + " callingUid:" + callingUid);
        } catch (Exception e) {
            Log.e(TAG, "shouldBypassTaskPermission: unable to get gms uid", e);
            return false;
        }
        return gmsUid == callingUid;
    }

    private static boolean isCallerSafetyNet() {
        return sIsGms && Arrays.stream(Thread.currentThread().getStackTrace())
                .anyMatch(elem -> elem.getClassName().contains("DroidGuard"));
    }

    public static void onEngineGetCertificateChain() {
        // Check stack for SafetyNet or Play Integrity
        if (isCallerSafetyNet() || sIsFinsky) {
            dlog("Blocked key attestation sIsGms=" + sIsGms + " sIsFinsky=" + sIsFinsky);
            throw new UnsupportedOperationException();
        }
    }

    private static void dlog(String msg) {
        if (DEBUG) Log.d(TAG, "[" + sProcessName + "] " + msg);
    }
}
