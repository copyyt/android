package com.psami.copyyt.android.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.ExperimentalTextApi
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontVariation
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import com.psami.copyyt.R

/** The Copyyt palette, shared with the Chrome extension. */
object CopyytColors {
    val Blue = Color(0xFF2D9CDB)
    val BlueDark = Color(0xFF1E6892)
    val Navy = Color(0xFF0F3449)
    val Sky = Color(0xFFE3F3FB)
    val Mist = Color(0xFFF8FAFC)
    val Slate = Color(0xFF4B5563)
    val Line = Color(0xFFD1D5DB)
    val Red = Color(0xFFFF2635)
    val Green = Color(0xFF16A34A)
}

// Sora and Work Sans ship as variable fonts; each weight selects its axis value.
@OptIn(ExperimentalTextApi::class)
private fun variable(res: Int, weight: Int) = Font(
    res,
    FontWeight(weight),
    variationSettings = FontVariation.Settings(FontVariation.weight(weight)),
)

private val Sora = FontFamily(
    variable(R.font.sora, 400), variable(R.font.sora, 600), variable(R.font.sora, 700),
)
private val WorkSans = FontFamily(
    variable(R.font.work_sans, 400), variable(R.font.work_sans, 500), variable(R.font.work_sans, 600),
)

private val CopyytTypography = Typography(
    headlineMedium = TextStyle(fontFamily = Sora, fontWeight = FontWeight.Bold, fontSize = 26.sp, lineHeight = 32.sp),
    headlineSmall = TextStyle(fontFamily = Sora, fontWeight = FontWeight.Bold, fontSize = 22.sp, lineHeight = 28.sp),
    titleLarge = TextStyle(fontFamily = Sora, fontWeight = FontWeight.SemiBold, fontSize = 19.sp, lineHeight = 26.sp),
    titleMedium = TextStyle(fontFamily = Sora, fontWeight = FontWeight.SemiBold, fontSize = 16.sp, lineHeight = 22.sp),
    titleSmall = TextStyle(fontFamily = Sora, fontWeight = FontWeight.SemiBold, fontSize = 14.sp, lineHeight = 20.sp),
    bodyLarge = TextStyle(fontFamily = WorkSans, fontWeight = FontWeight.Normal, fontSize = 16.sp, lineHeight = 24.sp),
    bodyMedium = TextStyle(fontFamily = WorkSans, fontWeight = FontWeight.Normal, fontSize = 14.sp, lineHeight = 21.sp),
    bodySmall = TextStyle(fontFamily = WorkSans, fontWeight = FontWeight.Normal, fontSize = 12.sp, lineHeight = 18.sp),
    labelLarge = TextStyle(fontFamily = WorkSans, fontWeight = FontWeight.SemiBold, fontSize = 15.sp, lineHeight = 20.sp),
    labelMedium = TextStyle(fontFamily = WorkSans, fontWeight = FontWeight.Medium, fontSize = 12.sp, lineHeight = 16.sp),
)

private val Light = lightColorScheme(
    primary = CopyytColors.Blue,
    onPrimary = Color.White,
    primaryContainer = CopyytColors.Sky,
    onPrimaryContainer = CopyytColors.Navy,
    secondary = CopyytColors.BlueDark,
    onSecondary = Color.White,
    background = CopyytColors.Mist,
    onBackground = CopyytColors.Navy,
    surface = Color.White,
    onSurface = CopyytColors.Navy,
    surfaceVariant = Color(0xFFF1F5F9),
    onSurfaceVariant = CopyytColors.Slate,
    outline = CopyytColors.Line,
    error = CopyytColors.Red,
    onError = Color.White,
    errorContainer = Color(0xFFFFE4E6),
    onErrorContainer = Color(0xFF7F1D1D),
)

private val Dark = darkColorScheme(
    primary = Color(0xFF56B3E6),
    onPrimary = Color(0xFF002235),
    primaryContainer = Color(0xFF0F3449),
    onPrimaryContainer = CopyytColors.Sky,
    secondary = Color(0xFF8CCBEE),
    background = Color(0xFF08141C),
    onBackground = Color(0xFFE2EEF5),
    surface = Color(0xFF0F2230),
    onSurface = Color(0xFFE2EEF5),
    surfaceVariant = Color(0xFF16303F),
    onSurfaceVariant = Color(0xFFA9BCC8),
    outline = Color(0xFF2B4A5C),
    error = Color(0xFFFF6B75),
    errorContainer = Color(0xFF4A1016),
    onErrorContainer = Color(0xFFFFDADC),
)

@Composable
fun CopyytTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = if (isSystemInDarkTheme()) Dark else Light,
        typography = CopyytTypography,
        content = content,
    )
}
