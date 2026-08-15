package com.visionforge.inferencebenchmark.ui;

import android.view.View;

/** Small presentation contract implemented by every top-level destination. */
interface MobileScreen {
    View view();

    void render(MobileUiState state);
}
