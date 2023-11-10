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
        // Alter build parameters to ASUS_X00HD for avoiding hardware attestation enforcement
        setPropValue("PRODUCT", "WW_Phone");
        setPropValue("PRODUCT_FOR_ATTESTATION", "WW_Phone");
        setPropValue("DEVICE", "ASUS_X00HD_4");
        setPropValue("DEVICE_FOR_ATTESTATION", "ASUS_X00HD_4");
        setPropValue("MANUFACTURER", "Asus");
        setPropValue("MANUFACTURER_FOR_ATTESTATION", "Asus");
        setPropValue("BRAND", "Asus");
        setPropValue("BRAND_FOR_ATTESTATION", "Asus");
        setPropValue("MODEL", "ASUS_X00HD");
        setPropValue("MODEL_FOR_ATTESTATION", "ASUS_X00HD");
        setPropValue("FINGERPRINT", "asus/WW_Phone/ASUS_X00HD_4:7.1.1/NMF26F/14.2016.1801.372-20180119:user/release-keys");
        setPropValue("ID", "NMF26F");
        setPropValue("TYPE", "user");
        setPropValue("TAGS", "release-keys");
        setVersionField("DEVICE_INITIAL_SDK_INT", Build.VERSION_CODES.N_MR1);
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