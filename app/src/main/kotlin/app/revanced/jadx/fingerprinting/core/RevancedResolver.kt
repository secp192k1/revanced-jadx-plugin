package app.revanced.jadx.fingerprinting.core

import app.revanced.jadx.fingerprinting.ReVancedJadxPlugin
import app.revanced.patcher.patch.bytecodePatch
import com.android.tools.smali.dexlib2.iface.Method
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction
import com.android.tools.smali.dexlib2.iface.reference.MethodReference
import com.android.tools.smali.dexlib2.util.MethodUtil
import io.github.oshai.kotlinlogging.KotlinLogging
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import java.io.File
import java.util.UUID
import kotlin.properties.ReadOnlyProperty
import app.revanced.patcher.patch.BytecodePatchContext
import app.revanced.patcher.patcher

private val matcherProbe = Unit

class ReVancedResolver : AutoCloseable {
    private val log = KotlinLogging.logger("${ReVancedJadxPlugin.ID}/resolver")
    private lateinit var sourceApk: File
    private lateinit var patcherTemporaryFilesPath: File

    private var cachedContext: BytecodePatchContext? = null

    @OptIn(DelicateCoroutinesApi::class)
    fun createPatcher(
        sourceApk: File,
        patcherTemporaryFilesPath: File,
        onError: (Throwable) -> Unit = {},
        onMethodsLoaded: (List<Method>) -> Unit = {},
    ) {
        this.sourceApk = sourceApk
        this.patcherTemporaryFilesPath = File(patcherTemporaryFilesPath, UUID.randomUUID().toString())
        log.info { "Called createPatcher with $sourceApk and ${this.patcherTemporaryFilesPath}" }
        GlobalScope.launch(Dispatchers.IO) {
            ScriptEvaluation.preload()
            try {
                log.info { "Eagerly initializing bytecode context for $sourceApk" }
                val context = loadContext()
                val methods = context.classDefs.flatMap { it.methods }
                log.info { "Extracted ${methods.size} methods from bytecode context" }
                onMethodsLoaded(methods)
            } catch (e: Exception) {
                log.error(e) { "Failed to eagerly initialize bytecode context or extract methods" }
                onError(e)
            }
        }
    }

    /**
     * Loads the apk into a [BytecodePatchContext] once and caches it. The only public entry point to
     * a context is from within a running patch, so a no-op patch captures and hands it back out.
     */
    private fun loadContext(): BytecodePatchContext = synchronized(this) {
        cachedContext ?: run {
            var captured: BytecodePatchContext? = null
            val capturePatch = bytecodePatch(name = "Capture bytecode context") {
                apply { captured = this }
            }
            patcher(
                apkFile = sourceApk,
                temporaryFilesPath = patcherTemporaryFilesPath,
                aaptBinaryPath = null,
                frameworkFileDirectory = patcherTemporaryFilesPath.absolutePath,
            ) { _, _ -> setOf(capturePatch) }.invoke { result ->
                result.exception?.let { log.error(it) { "\"${result.patch}\" failed" } }
            }
            (captured ?: error("Patcher did not provide a BytecodePatchContext")).also { cachedContext = it }
        }
    }

    fun listClassTypes(): List<String> {
        if (!ensureInitialized()) return emptyList()
        return loadContext().classDefs.map { it.type }.sorted()
    }

    fun findCallers(target: Method): List<Method> {
        if (!ensureInitialized()) return emptyList()
        return loadContext().classDefs.asSequence()
            .flatMap { it.methods.asSequence() }
            .filter { it.referencesMethod(target) }
            .toList()
    }

    fun searchFingerprint(matcher: ReadOnlyProperty<BytecodePatchContext, *>): Method? {
        if (!ensureInitialized()) return null
        val result = runCatching {
            matcher.getValue(loadContext(), ::matcherProbe)
        }.getOrElse {
            log.info { "Matcher produced no result: ${it.message}" }
            null
        }

        if (result != null && result.javaClass.name.contains(".dexlib2.mutable.")) invalidateContext()
        log.info { "Search result: $result" }
        return result as? Method
    }

    private fun invalidateContext() = synchronized(this) { cachedContext = null }

    private fun ensureInitialized(): Boolean {
        if (!::sourceApk.isInitialized || !::patcherTemporaryFilesPath.isInitialized) {
            log.error { "Resolver not initialized" }
            return false
        }
        return true
    }

    private fun Method.referencesMethod(target: Method): Boolean {
        val instructions = implementation?.instructions ?: return false
        return instructions.any { ins ->
            val ref = (ins as? ReferenceInstruction)?.reference as? MethodReference ?: return@any false
            MethodUtil.methodSignaturesMatch(ref, target)
        }
    }

    override fun close() {
        synchronized(this) {
            cachedContext = null
        }
    }
}
