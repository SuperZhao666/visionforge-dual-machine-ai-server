package com.visionforge.inferencebenchmark;

import android.content.Context;
import android.content.SharedPreferences;

/** Durable operator output-route selection with safe fallback for invalid data. */
final class ControlOutputRouteStore {
    private static final String PREFERENCES = "visionforge_control_output";
    private static final String KEY_ROUTE = "selected_route_v1";

    private final SharedPreferences preferences;

    ControlOutputRouteStore(Context context) {
        if (context == null) throw new IllegalArgumentException("context");
        preferences = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE);
    }

    ControlOutputRoute load() {
        String token = preferences.getString(KEY_ROUTE, null);
        ControlOutputRoute route = ControlOutputRoute.fromStorageToken(token);
        if (route == ControlOutputRoute.NONE) route = ControlOutputRoute.MAKCU_USB;
        if (token != null && !route.storageToken.equals(token)) save(route);
        return route;
    }

    void save(ControlOutputRoute route) {
        ControlOutputRoute checked = route == null || route == ControlOutputRoute.NONE
                ? ControlOutputRoute.MAKCU_USB : route;
        preferences.edit().putString(KEY_ROUTE, checked.storageToken).apply();
    }
}
