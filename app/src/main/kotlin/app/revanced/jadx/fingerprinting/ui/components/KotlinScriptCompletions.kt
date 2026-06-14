package app.revanced.jadx.fingerprinting.ui.components

import org.fife.ui.autocomplete.CompletionProvider
import org.fife.ui.autocomplete.DefaultCompletionProvider
import org.fife.ui.autocomplete.TemplateCompletion

/**
 * Builds the autocomplete provider for the fingerprint script editor
 *
 * Entries mirror the surface of `script-prelude.kts` plus the low-level
 * `FingerprintBuilder` DSL. Each `getting*` family registers two templates:
 * the no-arg lambda form and the string-anchored form, so RSTA shows both
 * shapes when the user types the function name
 *
 * Kept separate from [CodePanel] so the completion list can grow without
 * bloating the panel class
 */
internal object KotlinScriptCompletions {
    private val METHOD_FUNCTIONS = listOf(
        "gettingFirstMethodDeclaratively",
        "gettingFirstMethodDeclarativelyOrNull",
        "gettingFirstImmutableMethodDeclaratively",
        "gettingFirstImmutableMethodDeclarativelyOrNull",
        "gettingFirstMethod",
        "gettingFirstMethodOrNull",
        "gettingFirstImmutableMethod",
        "gettingFirstImmutableMethodOrNull",
        "composingFirstMethod",
    )

    private val CLASS_DEF_FUNCTIONS = listOf(
        "gettingFirstClassDef",
        "gettingFirstClassDefOrNull",
        "gettingFirstImmutableClassDef",
        "gettingFirstImmutableClassDefOrNull",
        "gettingFirstClassDefDeclaratively",
        "gettingFirstClassDefDeclarativelyOrNull",
        "gettingFirstImmutableClassDefDeclaratively",
        "gettingFirstImmutableClassDefDeclarativelyOrNull",
    )

    fun create(): CompletionProvider = DefaultCompletionProvider().apply {
        // Method lookups
        METHOD_FUNCTIONS.forEach { fn ->
            tpl(fn, "$fn { … }", "$fn {\n\t\${cursor}\n}")
            tpl(fn, "$fn(\"…\") { … }", "$fn(\"\${str}\") {\n\t\${cursor}\n}")
        }

        // ClassDef lookups
        CLASS_DEF_FUNCTIONS.forEach { fn ->
            tpl(fn, "$fn(\"L…;\")", "$fn(\"\${cursor}\")")
            tpl(fn, "$fn(\"L…;\") { … }", "$fn(\"\${descriptor}\") {\n\t\${cursor}\n}")
        }

        // _MethodSpec DSL
        tpl("definingClass", "definingClass(\"L…;\")", "definingClass(\"\${cursor}\")")
        tpl("name", "name(\"…\")", "name(\"\${cursor}\")")
        tpl("returnType", "returnType(\"…\")", "returnType(\"\${cursor}\")")
        tpl("parameterTypes", "parameterTypes(\"…\", …)", "parameterTypes(\"\${cursor}\")")
        tpl("accessFlags", "accessFlags(AccessFlags.…)", "accessFlags(AccessFlags.\${cursor})")
        tpl("opcodes", "opcodes(Opcode.…)", "opcodes(Opcode.\${cursor})")
        tpl("strings", "strings(\"…\")", "strings(\"\${cursor}\")")
        tpl("custom", "custom { method, classDef -> … }", "custom { method, classDef ->\n\t\${cursor}\n}")
    }

    private fun DefaultCompletionProvider.tpl(
        input: String,
        shortDesc: String,
        template: String,
    ) = addCompletion(TemplateCompletion(this, input, shortDesc, template))
}
