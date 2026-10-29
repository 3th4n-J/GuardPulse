package za.co.guardpulse.shield

import android.accessibilityservice.AccessibilityService
import android.content.Context
import android.graphics.PixelFormat
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Handler
import android.os.Looper
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView

/**
 * Full-screen "blocked" cover drawn as an accessibility overlay, which needs
 * no "display over other apps" permission. Built in code to keep the plugin
 * free of layout resources. Colours follow the app theme.
 */
class BlockOverlay(private val service: AccessibilityService) {

    private val wm = service.getSystemService(Context.WINDOW_SERVICE) as WindowManager
    private val main = Handler(Looper.getMainLooper())
    private val dp = service.resources.displayMetrics.density
    private var view: View? = null
    private var flashView: View? = null

    /** What the cover is for, e.g. "app:com.reddit.frontpage" or "site:reddit.com". */
    var key: String? = null
        private set

    val showing: Boolean get() = view != null

    fun show(key: String, title: String, message: String, button: String, onButton: () -> Unit) {
        if (this.key == key && view != null) return
        hide()
        val root = LinearLayout(service).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setBackgroundColor(0xF706122B.toInt())
            val pad = px(32)
            setPadding(pad, pad, pad, pad)
            isClickable = true // swallow touches meant for the app underneath
        }
        root.addView(ImageView(service).apply {
            setImageResource(service.applicationInfo.icon)
            layoutParams = LinearLayout.LayoutParams(px(96), px(96)).apply { bottomMargin = px(24) }
        })
        root.addView(text(title, 26f, 0xFFE6F1FF.toInt(), bold = true))
        root.addView(text(message, 15f, 0xFF8FA3C7.toInt()).apply {
            (layoutParams as LinearLayout.LayoutParams).topMargin = px(12)
        })
        root.addView(text(button, 16f, 0xFF06122B.toInt(), bold = true).apply {
            background = GradientDrawable().apply {
                cornerRadius = px(28).toFloat()
                colors = intArrayOf(0xFF1D50C5.toInt(), 0xFF23C6C0.toInt())
                orientation = GradientDrawable.Orientation.LEFT_RIGHT
            }
            setTextColor(0xFFFFFFFF.toInt())
            setPadding(px(32), px(14), px(32), px(14))
            (layoutParams as LinearLayout.LayoutParams).topMargin = px(32)
            isClickable = true
            setOnClickListener { onButton() }
        })
        val lp = WindowManager.LayoutParams(
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.TYPE_ACCESSIBILITY_OVERLAY,
            WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
            PixelFormat.TRANSLUCENT,
        )
        try {
            wm.addView(root, lp)
            view = root
            this.key = key
        } catch (e: Exception) {
            // window token gone (service unbinding) - nothing to cover
        }
    }

    /** Small pill at the bottom for ~1.5 s, e.g. after bouncing out of Shorts. Doesn't take touches. */
    fun flash(message: String) {
        flashView?.let { safeRemove(it) }
        val pill = text(message, 14f, 0xFFFFFFFF.toInt(), bold = true).apply {
            background = GradientDrawable().apply {
                cornerRadius = px(24).toFloat()
                setColor(0xF013295A.toInt())
            }
            setPadding(px(20), px(12), px(20), px(12))
        }
        val lp = WindowManager.LayoutParams(
            WindowManager.LayoutParams.WRAP_CONTENT,
            WindowManager.LayoutParams.WRAP_CONTENT,
            WindowManager.LayoutParams.TYPE_ACCESSIBILITY_OVERLAY,
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or WindowManager.LayoutParams.FLAG_NOT_TOUCHABLE,
            PixelFormat.TRANSLUCENT,
        ).apply {
            gravity = Gravity.BOTTOM or Gravity.CENTER_HORIZONTAL
            y = px(96)
        }
        try {
            wm.addView(pill, lp)
            flashView = pill
            main.postDelayed({ if (flashView === pill) { safeRemove(pill); flashView = null } }, 1500)
        } catch (e: Exception) {
        }
    }

    fun hide() {
        view?.let { safeRemove(it) }
        view = null
        key = null
    }

    fun hideAll() {
        hide()
        flashView?.let { safeRemove(it) }
        flashView = null
    }

    private fun safeRemove(v: View) {
        try {
            wm.removeView(v)
        } catch (e: Exception) {
        }
    }

    private fun text(value: String, sp: Float, color: Int, bold: Boolean = false) = TextView(service).apply {
        text = value
        setTextSize(TypedValue.COMPLEX_UNIT_SP, sp)
        setTextColor(color)
        gravity = Gravity.CENTER
        if (bold) typeface = Typeface.DEFAULT_BOLD
        layoutParams = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.WRAP_CONTENT,
            LinearLayout.LayoutParams.WRAP_CONTENT,
        )
    }

    private fun px(value: Int) = (value * dp).toInt()
}
