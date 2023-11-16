package io.github.tehcneko.disablehardwareattestation;

import android.annotation.SuppressLint;
import android.os.Build;
import android.util.Log;

import java.lang.reflect.Field;
import java.security.KeyStore;
import java.util.Arrays;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

@SuppressLint("DiscouragedPrivateApi")
@SuppressWarnings("ConstantConditions")
public class GMSHook implements IXposedHookLoadPackage {

    private static final String TAG = "GmsCompat/Attestation";
    private static final String PACKAGE_GMS = "com.google.android.gms";
    private static final String PACKAGE_FINSKY = "com.android.vending";
    private static final String PROCESS_UNSTABLE = "com.google.android.gms.unstable";
    private static final String PROVIDER_NAME = "AndroidKeyStore";
    private static volatile boolean sIsGms = false;
    private static volatile boolean sIsFinsky = false;

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam loadPackageParam) {
        if (PACKAGE_GMS.equals(loadPackageParam.packageName) &&
                PROCESS_UNSTABLE.equals(loadPackageParam.processName)) {
            sIsGms = true;
            spoofBuildGms();
        }
        
        if (PACKAGE_FINSKY.equals(loadPackageParam.packageName)) {
            sIsFinsky = true;
        }
        
        if (sIsGms || sIsFinsky) {
            try {
                KeyStore keyStore = KeyStore.getInstance(PROVIDER_NAME);
                Field keyStoreSpi = keyStore.getClass().getDeclaredField("keyStoreSpi");
                keyStoreSpi.setAccessible(true);
                XposedHelpers.findAndHookMethod(keyStoreSpi.get(keyStore).getClass(), "engineGetCertificateChain", String.class, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        // Check stack for SafetyNet or Play Integrity
                        if (isCallerSafetyNet() || sIsFinsky) {
                            Log.i(TAG, "Blocked key attestation sIsGms=" + sIsGms + " sIsFinsky=" + sIsFinsky);
                            param.setThrowable(new UnsupportedOperationException());
                        }
                    }
                });
                Log.d(TAG, "keystore hooked");
            } catch (Throwable t) {
                XposedBridge.log("keystore hook failed: " + Log.getStackTraceString(t));
            }
        }
    }

    private static void spoofBuildGms() {
        // Alter model name and fingerprint to Redmi Go to avoid hardware attestation enforcement
        // Alter build parameters to Nexus 6P for avoiding hardware attestation enforcement
        setPropValue("DEVICE", "bullhead");
        setPropValue("FINGERPRINT", "google/bullhead/bullhead:8.0.0/OPR6.170623.013/4283548:user/release-keys");
        setPropValue("MODEL", "Nexus 5X");
        setPropValue("PRODUCT", "bullhead");
        setVersionField("DEVICE_INITIAL_SDK_INT", Build.VERSION_CODES.N);
    }

    private static boolean isCallerSafetyNet() {
        return sIsGms && Arrays.stream(Thread.currentThread().getStackTrace())
                .anyMatch(elem -> elem.getClassName().contains("DroidGuard"));
    }

    private static void setPropValue(String key, Object value) {
        try {
            Field field = Build.class.getDeclaredField(key);
            field.setAccessible(true);
            field.set(null, value);
            field.setAccessible(false);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            Log.e(TAG, "Failed to set prop " + key, e);
        }
    }
    private static void setVersionField(String key, Object value) {
        try {
            Field field = Build.VERSION.class.getDeclaredField(key);
            field.setAccessible(true);
            field.set(null, value);
            field.setAccessible(false);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            Log.e(TAG, "Failed to set version field " + key, e);
        }
    }

    private static void setVersionFieldString(String key, String value) {
        try {
            Field field = Build.VERSION.class.getDeclaredField(key);
            field.setAccessible(true);
            field.set(null, value);
            field.setAccessible(false);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            Log.e(TAG, "Failed to set prop " + key, e);
        }
    }
}
