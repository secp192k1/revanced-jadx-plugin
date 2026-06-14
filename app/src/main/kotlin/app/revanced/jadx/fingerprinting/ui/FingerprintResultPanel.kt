package app.revanced.jadx.fingerprinting.ui

import app.revanced.patcher.patch.BytecodePatchContext
import com.android.tools.smali.dexlib2.analysis.reflection.util.ReflectionUtils
import com.android.tools.smali.dexlib2.iface.Method
import app.revanced.jadx.fingerprinting.ReVancedJadxPlugin
import app.revanced.jadx.fingerprinting.core.SCRIPT_PRELUDE_LINE_COUNT
import app.revanced.jadx.fingerprinting.core.ScriptEvaluation
import app.revanced.jadx.fingerprinting.core.getShortId
import io.github.oshai.kotlinlogging.KotlinLogging
import jadx.api.plugins.JadxPluginContext
import jadx.api.plugins.gui.JadxGuiContext
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.swing.Swing
import kotlinx.coroutines.withContext
import java.awt.*
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.util.regex.Pattern
import javax.swing.*
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener
import javax.swing.table.DefaultTableModel
import javax.swing.table.TableRowSorter
import kotlin.properties.ReadOnlyProperty
import kotlin.script.experimental.api.EvaluationResult
import kotlin.script.experimental.api.ResultValue
import kotlin.script.experimental.api.ResultWithDiagnostics
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.measureTime

internal const val FINGERPRINT_PANEL_HEADER_HEIGHT = 36

class FingerprintResultPanel(
    private val context: JadxPluginContext,
    private val guiContext: JadxGuiContext,
    private val scriptProvider: () -> String,
    private val clearAction: () -> Unit = {},
) : JPanel(BorderLayout()) {
    private val log = KotlinLogging.logger("${ReVancedJadxPlugin.ID}/result-panel")
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val copyIcon = ReVancedJadxPluginUi.inlineSvgIcon(Icons.copy(16))

    private val runButton = iconButton(
        "Run the script",
        ReVancedJadxPluginUi.inlineSvgIcon(Icons.playArrow),
    )
    private val clearButton = iconButton(
        "Clear editor",
        ReVancedJadxPluginUi.inlineSvgIcon(Icons.clear),
    )
    private val resultLabel = JLabel("Fingerprint result").apply {
        border = BorderFactory.createEmptyBorder(0, 10, 0, 0)
    }

    private val resultContentBox = Box.createVerticalBox()
    private val resultScrollPane: JScrollPane

    init {
        val upPanel = JPanel(FlowLayout(FlowLayout.LEFT, 4, 2)).apply {
            border = BorderFactory.createEmptyBorder(0, 10, 0, 0)
            preferredSize = Dimension(0, FINGERPRINT_PANEL_HEADER_HEIGHT)
            add(runButton)
            add(clearButton)
            add(resultLabel)
        }
        add(upPanel, BorderLayout.NORTH)

        val resultContentPanel = JPanel(BorderLayout()).apply {
            add(resultContentBox, BorderLayout.PAGE_START)
        }
        resultScrollPane = JScrollPane(resultContentPanel)
        add(resultScrollPane, BorderLayout.CENTER)

        runButton.addActionListener { fetchAndRender() }
        clearButton.addActionListener { clearAction() }
    }

    override fun removeNotify() {
        super.removeNotify()
        scope.cancel()
    }

    private fun fetchAndRender() {
        setControlsEnabled(false)
        showStatusText("Evaluating…")

        val script = scriptProvider()
        scope.launch {
            var results: List<Method> = emptyList()
            val executionTime = measureTime {
                val evalResult = try {
                    ScriptEvaluation.rawEvaluate(script)
                } catch (t: Throwable) {
                    log.error(t) { "Exception during script evaluation" }
                    withContext(Dispatchers.Swing) {
                        showStatusText("Evaluation failed: ${t.message}")
                        setControlsEnabled(true)
                    }
                    return@launch
                }

                val matcher = extractMatcher(evalResult) { msg ->
                    withContext(Dispatchers.Swing) {
                        showStatusText(msg)
                        setControlsEnabled(true)
                    }
                } ?: return@launch

                results = ReVancedJadxPluginUi.resolver.searchAllFingerprintMatches(matcher)
            }

            withContext(Dispatchers.Swing) {
                resultLabel.text = "Executed in ${executionTime.inWholeMilliseconds.milliseconds}"
                renderResults(results)
            }
        }
    }

    private fun renderResults(methods: List<Method>) {
        resultContentBox.removeAll()
        if (methods.isEmpty()) {
            resultContentBox.add(ReVancedJadxPluginUi.createWrappedTextArea("Fingerprint not found in the APK.").apply {
                alignmentX = LEFT_ALIGNMENT
            })
        } else {
            resultContentBox.add(resultCard(methods.first()))

            val others = methods.drop(1)
            if (others.isNotEmpty()) {
                resultContentBox.add(Box.createVerticalStrut(10))
                resultContentBox.add(JSeparator(SwingConstants.HORIZONTAL).apply {
                    alignmentX = LEFT_ALIGNMENT
                    maximumSize = Dimension(Int.MAX_VALUE, 2)
                })
                resultContentBox.add(JLabel("Other possible matches (${others.size}):").apply {
                    alignmentX = LEFT_ALIGNMENT
                    border = BorderFactory.createEmptyBorder(6, 4, 6, 0)
                })
                others.forEach { method ->
                    resultContentBox.add(resultCard(method))
                    resultContentBox.add(Box.createVerticalStrut(10))
                }
            }
        }
        setControlsEnabled(true)
        resultContentBox.revalidate()
        resultContentBox.repaint()
        resultScrollPane.verticalScrollBar.value = resultScrollPane.verticalScrollBar.minimum
    }

    private fun resultCard(method: Method): JComponent {
        val dexClass = method.definingClass
        val javaName = ReflectionUtils.dexToJavaName(dexClass).replace("$", ".")
        val shortId = method.getShortId()
        val accentColor: Color = UIManager.getColor("Component.accentColor") ?: Color(0x4d9fec)

        val grid = JPanel(GridBagLayout()).apply {
            alignmentX = LEFT_ALIGNMENT
            border = BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 3, 0, 0, accentColor),
                BorderFactory.createEmptyBorder(6, 8, 6, 4),
            )
        }

        val labelGbc = GridBagConstraints().apply {
            gridx = 0
            anchor = GridBagConstraints.EAST
            insets = Insets(1, 0, 1, 8)
        }
        val valueGbc = GridBagConstraints().apply {
            gridx = 1
            weightx = 1.0
            fill = GridBagConstraints.HORIZONTAL
            anchor = GridBagConstraints.WEST
            insets = Insets(1, 0, 1, 2)
        }
        val copyGbc = GridBagConstraints().apply {
            gridx = 2
            anchor = GridBagConstraints.CENTER
            insets = Insets(1, 0, 1, 0)
        }

        var row = 0
        fun addRow(label: String, value: String) {
            grid.add(JLabel("$label:"), labelGbc.atRow(row))
            grid.add(JTextField(value).apply {
                isEditable = false
                border = null
                isOpaque = false
            }, valueGbc.atRow(row))
            grid.add(copyButton(value), copyGbc.atRow(row))
            row++
        }

        addRow("Class (Java)", javaName)
        addRow("Class (DEX)", dexClass)
        addRow("Short ID", shortId)

        val javaKlass = context.decompiler.searchJavaClassByOrigFullName(javaName)
        val fgMethod = javaKlass?.searchMethodByShortId(shortId)
        val actionRow = JPanel(FlowLayout(FlowLayout.LEFT, 6, 0)).apply { isOpaque = false }
        fgMethod?.let { sourceMethod ->
            addRow("Method", sourceMethod.fullName)
            actionRow.add(JButton("Jump to method").apply {
                addActionListener {
                    if (!guiContext.open(sourceMethod.codeNodeRef))
                        log.error { "Failed to jump to method: ${sourceMethod.fullName}" }
                }
            })
        }
        actionRow.add(JButton("Find usages").apply {
            toolTipText = "Scan APK for methods that call this method"
            addActionListener { showUsagesDialog(method) }
        })
        grid.add(actionRow, GridBagConstraints().apply {
            gridx = 1; gridwidth = 2; gridy = row
            anchor = GridBagConstraints.WEST
            insets = Insets(4, 0, 0, 0)
        })

        return JPanel(BorderLayout()).apply {
            isOpaque = false
            alignmentX = LEFT_ALIGNMENT
            add(grid, BorderLayout.CENTER)
        }
    }

    private fun showUsagesDialog(target: Method) {
        val dialog = JDialog(guiContext.mainFrame, "Find usages - ${target.name}", false)
        dialog.defaultCloseOperation = JDialog.DISPOSE_ON_CLOSE
        dialog.setSize(900, 520)
        dialog.setLocationRelativeTo(guiContext.mainFrame)

        val targetJavaName = ReflectionUtils.dexToJavaName(target.definingClass).replace("$", ".")
        val targetSig = "${target.name}(${target.parameterTypes.joinToString(", ")})${target.returnType}"
        val headerLabel = JLabel(
            "<html><b>$targetSig</b><br><small>in <tt>$targetJavaName</tt></small></html>"
        ).apply { border = BorderFactory.createEmptyBorder(0, 0, 8, 0) }

        val statusLabel = JLabel("Scanning APK…")
        val filterField = JTextField(20).apply { toolTipText = "Substring filter (case-insensitive); matches class or method" }
        val filterRow = JPanel(BorderLayout(8, 0)).apply {
            add(statusLabel, BorderLayout.WEST)
            add(JPanel(FlowLayout(FlowLayout.RIGHT, 6, 0)).apply {
                add(JLabel("Filter:"))
                add(filterField)
            }, BorderLayout.EAST)
        }
        val callerHolder = mutableListOf<Method>()
        val model = object : DefaultTableModel(arrayOf("Class", "Method"), 0) {
            override fun isCellEditable(row: Int, col: Int) = false
            override fun getColumnClass(columnIndex: Int): Class<*> = String::class.java
        }
        val sorter = TableRowSorter(model)
        val table = JTable(model).apply {
            rowSorter = sorter
            setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
            autoResizeMode = JTable.AUTO_RESIZE_LAST_COLUMN
            setShowGrid(false)
            rowHeight = 22
            intercellSpacing = Dimension(0, 0)
        }
        table.columnModel.getColumn(0).preferredWidth = 480
        table.columnModel.getColumn(1).preferredWidth = 360

        fun jumpToSelected() {
            val viewRow = table.selectedRow.takeIf { it >= 0 } ?: return
            val modelRow = table.convertRowIndexToModel(viewRow)
            val caller = callerHolder.getOrNull(modelRow) ?: return
            val javaName = ReflectionUtils.dexToJavaName(caller.definingClass).replace("$", ".")
            val shortId = caller.getShortId()
            val sourceMethod = context.decompiler.searchJavaClassByOrigFullName(javaName)
                ?.searchMethodByShortId(shortId)
            if (sourceMethod != null) {
                if (!guiContext.open(sourceMethod.codeNodeRef))
                    log.error { "Failed to jump to caller: ${sourceMethod.fullName}" }
            } else {
                log.warn { "No JADX source for caller: $javaName.$shortId" }
            }
        }

        table.addMouseListener(object : MouseAdapter() {
            override fun mouseClicked(e: MouseEvent) {
                if (e.clickCount == 2 && table.selectedRow >= 0) jumpToSelected()
            }
        })

        filterField.document.addDocumentListener(object : DocumentListener {
            private fun applyFilter() {
                val text = filterField.text
                sorter.rowFilter = if (text.isBlank()) null
                else RowFilter.regexFilter("(?i)" + Pattern.quote(text))
            }
            override fun insertUpdate(e: DocumentEvent) = applyFilter()
            override fun removeUpdate(e: DocumentEvent) = applyFilter()
            override fun changedUpdate(e: DocumentEvent) = applyFilter()
        })

        val openBtn = JButton("Open Selected").apply {
            isEnabled = false
            addActionListener { jumpToSelected() }
        }
        table.selectionModel.addListSelectionListener { openBtn.isEnabled = table.selectedRow >= 0 }
        val closeBtn = JButton("Close").apply { addActionListener { dialog.dispose() } }
        val southPanel = JPanel(FlowLayout(FlowLayout.RIGHT, 6, 0)).apply {
            add(openBtn); add(closeBtn)
        }

        val northPanel = JPanel(BorderLayout()).apply {
            add(headerLabel, BorderLayout.NORTH)
            add(filterRow, BorderLayout.CENTER)
            border = BorderFactory.createEmptyBorder(0, 0, 8, 0)
        }
        dialog.contentPane.add(JPanel(BorderLayout(8, 8)).apply {
            border = BorderFactory.createEmptyBorder(10, 10, 10, 10)
            add(northPanel, BorderLayout.NORTH)
            add(JScrollPane(table), BorderLayout.CENTER)
            add(southPanel, BorderLayout.SOUTH)
        })
        dialog.isVisible = true

        scope.launch {
            val callers: List<Method>
            val scanTime = measureTime {
                callers = runCatching { ReVancedJadxPluginUi.resolver.findCallers(target) }
                    .onFailure { log.error(it) { "findCallers failed" } }
                    .getOrDefault(emptyList())
            }
            val sortedCallers = callers.sortedWith(compareBy({ it.definingClass }, { it.name }))
            withContext(Dispatchers.Swing) {
                statusLabel.text = "Found ${callers.size} usage(s) in ${scanTime.inWholeMilliseconds.milliseconds}"
                callerHolder.clear()
                callerHolder.addAll(sortedCallers)
                sortedCallers.forEach { caller ->
                    val javaName = ReflectionUtils.dexToJavaName(caller.definingClass).replace("$", ".")
                    model.addRow(arrayOf(javaName, caller.getShortId()))
                }
            }
        }
    }

    private fun iconButton(tooltipText: String, icon: Icon): JButton =
        JButton(null, icon).apply {
            toolTipText = tooltipText
            margin = Insets(3, 3, 3, 3)
            preferredSize = Dimension(icon.iconWidth, icon.iconHeight)
            maximumSize = preferredSize
            border = BorderFactory.createEmptyBorder(3, 3, 3, 3)
        }

    private fun copyButton(valueToCopy: String): JButton =
        JButton(null, copyIcon).apply {
            toolTipText = "Copy to Clipboard"
            border = BorderFactory.createEmptyBorder(2, 2, 2, 2)
            isContentAreaFilled = false
            setFixedSize(20)
            addActionListener { guiContext.copyToClipboard(valueToCopy) }
        }

    private fun showStatusText(text: String) {
        resultContentBox.removeAll()
        resultContentBox.add(ReVancedJadxPluginUi.createWrappedTextArea(text).apply {
            alignmentX = LEFT_ALIGNMENT
        })
        resultContentBox.revalidate()
        resultContentBox.repaint()
    }

    private fun setControlsEnabled(enabled: Boolean) {
        runButton.isEnabled = enabled
        clearButton.isEnabled = enabled
    }

    @Suppress("UNCHECKED_CAST")
    private suspend fun extractMatcher(
        evalResult: ResultWithDiagnostics<EvaluationResult>,
        onError: suspend (String) -> Unit,
    ): ReadOnlyProperty<BytecodePatchContext, *>? = when (evalResult) {
        is ResultWithDiagnostics.Failure -> {
            val msgs = buildString {
                appendLine("Script evaluation failed:")
                evalResult.reports.forEach { report ->
                    val userLine = report.location?.start?.line
                        ?.minus(SCRIPT_PRELUDE_LINE_COUNT)
                        ?.takeIf { it >= 1 }
                    val locPart = userLine?.let { " (line $it)" } ?: ""
                    appendLine("  ${report.severity}: ${report.message}$locPart")
                    log.error { "  ${report.severity}: ${report.message}$locPart" }
                }
            }
            onError(msgs.trim())
            null
        }
        is ResultWithDiagnostics.Success -> when (val rv = evalResult.value.returnValue) {
            ResultValue.NotEvaluated -> { onError("Script was not evaluated."); null }
            is ResultValue.Error -> {
                log.error(rv.error) { "Script execution error" }
                onError("Script execution error: ${rv.error.message}")
                null
            }
            is ResultValue.Unit -> { onError("Script did not produce a value."); null }
            is ResultValue.Value -> when (val v = rv.value) {
                null -> { onError("Script returned null."); null }
                !is ReadOnlyProperty<*, *> -> {
                    onError("Script must return a matcher (e.g. gettingFirstMethodDeclaratively { … }); got: ${rv.type}")
                    null
                }
                else -> v as ReadOnlyProperty<BytecodePatchContext, *>
            }
        }
    }
}
