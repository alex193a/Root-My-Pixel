package com.alex193a.rootmypixel.ui.theme

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawWithCache
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Outline
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

/**
 * Draws an animated (marching-ants) dashed border around the composable to act
 * as an indeterminate progress indicator — e.g. around a button while a long
 * background operation is running.
 *
 * When [active] is false the modifier is a no-op (pass-through).
 */
@Composable
fun Modifier.indeterminateBorder(
    active: Boolean,
    color: Color,
    width: Dp = 2.dp,
    shape: Shape = androidx.compose.material3.MaterialTheme.shapes.medium,
): Modifier {
    if (!active) return this

    val layoutDirection = LocalLayoutDirection.current
    val transition = rememberInfiniteTransition(label = "indeterminate-border")
    val phase by transition.animateFloat(
        initialValue = 0f,
        targetValue = 24f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 700, easing = LinearEasing),
        ),
        label = "indeterminate-border-phase",
    )

    return drawWithCache {
        val outline = shape.createOutline(size, layoutDirection, this)
        val path = when (outline) {
            is Outline.Rectangle -> Path().apply { addRect(outline.rect) }
            is Outline.Rounded -> Path().apply { addRoundRect(outline.roundRect) }
            is Outline.Generic -> outline.path
        }
        val pxWidth = width.toPx()
        onDrawBehind {
            drawPath(
                path = path,
                color = color,
                style = Stroke(
                    width = pxWidth,
                    pathEffect = PathEffect.dashPathEffect(
                        intervals = floatArrayOf(14f, 10f),
                        phase = phase,
                    ),
                ),
            )
        }
    }
}
