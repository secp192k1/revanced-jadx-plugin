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
import com.android.tools.smali.dexlib2.iface.ClassDef

private val matcherProbe = Unit
private const val MAX_FINGERPRINT_MATCHES = 50

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

    fun searchAllFingerprintMatches(matcher: ReadOnlyProperty<BytecodePatchContext, *>): List<Method> {
        if (!ensureInitialized()) return emptyList()
        val context = loadContext()
        val cacheField = runCatching {
            matcher.javaClass.getDeclaredField("cache").apply { isAccessible = true }
        }.getOrNull()

        fun clearMatcherCache() = (cacheField?.get(matcher) as? MutableMap<*, *>)?.clear()
        fun evalOnce(): Method? = runCatching {
            clearMatcherCache()
            matcher.getValue(context, ::matcherProbe)
        }.getOrElse {
            log.info { "Matcher produced no result: ${it.message}" }
            null
        } as? Method

        val matches = mutableListOf<Method>()
        val removed = mutableListOf<ClassDef>()
        try {
            var budget = MAX_FINGERPRINT_MATCHES
            while (budget-- > 0) {
                val method = evalOnce() ?: break
                matches += method
                if (cacheField == null) break // cannot iterate without a clearable result cache
                val classDef = context.classDefs[method.definingClass] ?: break
                context.classDefs.remove(classDef)
                removed += classDef
            }
        } finally {
            removed.forEach { context.classDefs.add(it) }
            clearMatcherCache()
        }
        log.info { "Found ${matches.size} match(es)" }
        return matches.sortedWith(
            compareBy({ it.definingClass }, { it.name }, { it.parameterTypes.joinToString(",") }),
        )
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
