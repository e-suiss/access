// OP-116 m.6
// The vectors.py cases through the uniffi Kotlin binding. Argument: conformance/vectors/core/1.

import java.io.File
import java.security.MessageDigest
import java.util.Base64
import kotlin.system.exitProcess
import uniffi.access_kernel_uniffi.*

typealias Obj = Map<String, Any?>

class Json(private val s: String) {
    private var i = 0

    fun parse(): Any? {
        val v = value()
        ws()
        require(i == s.length) { "trailing JSON at $i" }
        return v
    }

    private fun ws() {
        while (i < s.length && s[i].isWhitespace()) i++
    }

    private fun value(): Any? {
        ws()
        return when (s[i]) {
            '{' -> obj()
            '[' -> arr()
            '"' -> str()
            't' -> lit("true", true)
            'f' -> lit("false", false)
            'n' -> lit("null", null)
            else -> num()
        }
    }

    private fun lit(word: String, v: Any?): Any? {
        require(s.startsWith(word, i)) { "bad literal at $i" }
        i += word.length
        return v
    }

    private fun obj(): Obj {
        val m = LinkedHashMap<String, Any?>()
        i++
        ws()
        if (s[i] == '}') return m.also { i++ }
        while (true) {
            ws()
            val k = str()
            ws()
            require(s[i++] == ':') { "expected : at $i" }
            m[k] = value()
            ws()
            when (s[i++]) {
                ',' -> continue
                '}' -> return m
                else -> error("expected , or } at $i")
            }
        }
    }

    private fun arr(): List<Any?> {
        val a = ArrayList<Any?>()
        i++
        ws()
        if (s[i] == ']') return a.also { i++ }
        while (true) {
            a.add(value())
            ws()
            when (s[i++]) {
                ',' -> continue
                ']' -> return a
                else -> error("expected , or ] at $i")
            }
        }
    }

    private fun str(): String {
        require(s[i++] == '"') { "expected string at $i" }
        val b = StringBuilder()
        while (true) {
            val c = s[i++]
            when (c) {
                '"' -> return b.toString()
                '\\' -> when (val e = s[i++]) {
                    'n' -> b.append('\n')
                    't' -> b.append('\t')
                    'r' -> b.append('\r')
                    'b' -> b.append('\b')
                    'f' -> b.append('\u000c')
                    'u' -> b.append(s.substring(i, i + 4).toInt(16).toChar()).also { i += 4 }
                    else -> b.append(e)
                }
                else -> b.append(c)
            }
        }
    }

    private fun num(): Any {
        val start = i
        if (s[i] == '-') i++
        while (i < s.length && (s[i].isDigit() || s[i] in ".eE+-")) i++
        val text = s.substring(start, i)
        return text.toLongOrNull() ?: text.toULongOrNull() ?: text.toDouble()
    }
}

val vectors = mutableListOf<Pair<String, Int>>()
val failures = mutableListOf<String>()
lateinit var dir: File

@Suppress("UNCHECKED_CAST")
fun load(name: String): Obj = Json(File(dir, name).readText()).parse() as Obj

@Suppress("UNCHECKED_CAST")
fun Obj.cases(key: String = "cases"): List<Obj> = this[key] as List<Obj>

fun Obj.str(key: String): String = this[key] as String

fun Obj.u64(key: String): ULong = when (val n = this[key]) {
    is ULong -> n
    else -> (n as Long).toULong()
}

@Suppress("UNCHECKED_CAST")
fun Obj.ints(key: String): List<Int> = (this[key] as List<Long>).map { it.toInt() }

fun count(name: String, n: Int) {
    vectors.add(name to n)
}

fun expect(got: Any?, want: Any?, id: Any?) {
    if (got != want) failures.add("$id: got $got, want $want")
}

fun hex(s: String): ByteArray = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }

fun hex(b: ByteArray): String = b.joinToString("") { "%02x".format(it.toInt() and 0xff) }

fun head(major: Int, n: Int): ByteArray = when {
    n < 24 -> byteArrayOf((major shl 5 or n).toByte())
    n < 0x100 -> byteArrayOf((major shl 5 or 24).toByte(), n.toByte())
    n < 0x10000 -> byteArrayOf((major shl 5 or 25).toByte(), (n shr 8).toByte(), n.toByte())
    else -> error("length out of range for this test encoder")
}

fun bstr(b: ByteArray): ByteArray = head(2, b.size) + b

fun tstr(s: String): ByteArray = s.toByteArray().let { head(3, it.size) + it }

val bytewise = Comparator<ByteArray> { a, b ->
    val n = minOf(a.size, b.size)
    (0 until n).map { (a[it].toInt() and 0xff) - (b[it].toInt() and 0xff) }.firstOrNull { it != 0 }
        ?: (a.size - b.size)
}

fun cborMap(entries: List<Pair<ByteArray, ByteArray>>): ByteArray =
    entries.sortedWith { x, y -> bytewise.compare(x.first, y.first) }
        .fold(head(5, entries.size)) { acc, (k, v) -> acc + k + v }

fun keySet(keys: List<Pair<ByteArray, ByteArray>>, allowed: List<Int>): ByteArray {
    val algs = allowed.map { head(1, -1 - it) }.sortedWith(bytewise)
    return cborMap(listOf(
        tstr("keys") to cborMap(keys.map { (kid, key) -> bstr(kid) to key }),
        tstr("allowed") to algs.fold(head(4, algs.size)) { acc, a -> acc + a },
    ))
}

fun render(v: Any?): String = when (v) {
    null -> "null"
    is String -> "\"" + v.flatMap {
        when {
            it == '"' -> listOf('\\', '"')
            it == '\\' -> listOf('\\', '\\')
            it < ' ' -> "\\u%04x".format(it.code).toList()
            else -> listOf(it)
        }
    }.joinToString("") + "\""
    is Map<*, *> -> v.entries.sortedBy { it.key as String }
        .joinToString(",", "{", "}") { render(it.key) + ":" + render(it.value) }
    is List<*> -> v.joinToString(",", "[", "]") { render(it) }
    else -> v.toString()
}

fun joseKeys(v: Obj): List<Pair<ByteArray, ByteArray>> {
    @Suppress("UNCHECKED_CAST")
    val keys = v["keys"] as Map<String, String>
    return keys.map { (kid, key) ->
        val raw = b64url(key)
        b64url(kid) to cborMap(listOf(tstr(if (raw.size == 32) "ed25519" else "p256") to bstr(raw)))
    }
}

fun verdict(got: Outcome): String = when (got) {
    is Outcome.Ok -> "accept"
    is Outcome.Err -> "reject: " + got.name
}

fun b64url(s: String): ByteArray = Base64.getUrlDecoder().decode(s)

sealed class Outcome {
    data class Ok(val v: String) : Outcome()
    data class Err(val name: String) : Outcome()
}

fun outcome(f: () -> String): Outcome = try {
    Outcome.Ok(f())
} catch (e: KernelException) {
    Outcome.Err(e.message ?: "")
}

fun testDecision() {
    val v = load("decision.json")
    for (c in v.cases()) {
        val got = outcome { hex(evaluate(hex(c.str("input")), v.u64("fuel"))) }
        val want = if ("decision" in c) Outcome.Ok(c.str("decision")) else Outcome.Err(c.str("rejection"))
        expect(got, want, c["id"])
    }
    count("decision.json", v.cases().size)
}

fun testCveRegressions() {
    val v = load("cve-regressions.json")
    for (c in v.cases()) {
        if (c["operation"] == "combinator.evaluate") {
            val got = outcome { hex(evaluate(hex(c.str("input")), v.u64("fuel"))) }
            expect(got, Outcome.Ok(c.str("decision")), c["id"])
        } else {
            val got = outcome {
                childWithinParent(hex(c.str("child")), hex(c.str("parent")), hex(c.str("holder")), hex("a0"))
                    .toString()
            }
            expect(got, Outcome.Ok(c["within"].toString()), c["id"])
        }
    }
    count("cve-regressions.json", v.cases().size)
}

@Suppress("UNCHECKED_CAST")
fun testCose() {
    val v = load("cose.json")
    val keys = keySet((v["keys"] as Map<String, String>).map { (kid, key) -> hex(kid) to hex(key) }, v.ints("allowed"))
    for (c in v.cases()) {
        val got = outcome { hex(verifyCoseSign1(hex(c.str("sign1")), keys, v.str("content_type"))) }
        val want = if ("error" in c) {
            Outcome.Err(c.str("error"))
        } else {
            Outcome.Ok(hex(cborMap(listOf(
                tstr("kid") to bstr(hex(c.str("kid"))),
                tstr("payload") to bstr(hex(c.str("payload"))),
            ))))
        }
        expect(got, want, c["id"])
    }
    count("cose.json", v.cases().size)
}

fun testKeyScope() {
    val v = load("key-scope.json")
    for (c in v.cases()) {
        val got = outcome {
            hex(operationalKey(
                hex(c.str("metadata")), hex(c.str("domain")), hex(c.str("excerpt")), c.str("usage"), c.u64("iat"),
            ))
        }
        val want = if ("error" in c) Outcome.Err(c.str("error")) else Outcome.Ok(c.str("key"))
        expect(got, want, c["id"])
    }
    count("key-scope.json", v.cases().size)
}

@Suppress("UNCHECKED_CAST")
fun testJoseAttackClasses() {
    val v = load("jose-attack-classes.json")
    val keys = joseKeys(v)
    for (c in v.cases()) {
        val ks = keySet(keys, if ("allowed" in c) c.ints("allowed") else v.ints("allowed"))
        val got = outcome {
            verifyJwsCompact(
                c.str("token"), ks, v.str("typ"), "https://access.example", "pep:shop", 1_500_000UL, 60_000UL,
            )
        }
        expect(verdict(got), c.str("expect"), c["id"])
    }
    count("jose-attack-classes.json", v.cases().size)
}

@Suppress("UNCHECKED_CAST")
fun testJwtClaims() {
    val v = load("jwt-claims.json")
    val ks = keySet(joseKeys(v), v.ints("allowed"))
    for (c in v.cases()) {
        val ctx = (c["claims"] ?: v["claims"]) as Obj
        val got = outcome {
            verifyJwsCompact(
                c.str("token"), ks, v.str("typ"), ctx.str("issuer"), ctx.str("audience"), ctx.u64("now"),
                ctx.u64("skew_ms"),
            )
        }
        expect(verdict(got), c.str("expect"), c["id"])
    }
    count("jwt-claims.json", v.cases().size)
}

@Suppress("UNCHECKED_CAST")
fun testSdJwt() {
    val v = load("sd-jwt.json")
    val ks = keySet(joseKeys(v), v.ints("allowed"))
    val ctx = v["context"] as Obj
    for (c in v.cases()) {
        val got = outcome {
            val text = verifySdJwt(
                c.str("presentation"), ks, ctx.str("typ"), ctx.str("audience"), ctx.str("nonce"), ctx.u64("now"),
                ctx.u64("skew_ms"),
            )
            render(Json(text).parse())
        }
        val want = if ("claims" in c) Outcome.Ok(render(c["claims"])) else Outcome.Err(c.str("error"))
        expect(got, want, c["id"])
    }
    count("sd-jwt.json", v.cases().size)
}

fun testValidity() {
    val v = load("validity.json")
    for (c in v.cases()) {
        val got = outcome {
            checkValidity(
                hex((c["contract"] ?: v["contract"]) as String), c.u64("now"), v.str("audience"), emptyList(),
                (c["last_refresh"] as Long?)?.toULong(), (c["online"] ?: v["online"]) as Boolean, v.u64("skew_ms"),
                c.u64("iat"), c.u64("horizon_cap_ms"),
            )
            ""
        }
        val want = if ("error" in c) Outcome.Err(c.str("error")) else Outcome.Ok("")
        expect(got, want, c["id"])
    }
    count("validity.json", v.cases().size)
}

@Suppress("UNCHECKED_CAST")
fun testMerkle() {
    val v = load("merkle.json")
    val roots = v.cases("roots").associate { it["size"] as Long to hex(it.str("root")) }
    val leaves = v["leaves"] as List<String>
    fun path(c: Obj) = (c["path"] as List<String>).fold(ByteArray(0)) { acc, p -> acc + hex(p) }
    for (c in v.cases("inclusion")) {
        val index = c["index"] as Long
        val size = c["size"] as Long
        val leaf = MessageDigest.getInstance("SHA-256").digest(byteArrayOf(0) + hex(leaves[index.toInt()]))
        val got = outcome {
            verifyInclusion(index.toULong(), size.toULong(), leaf, path(c), roots.getValue(size)).toString()
        }
        expect(got, Outcome.Ok("true"), index to size)
    }
    for (c in v.cases("consistency")) {
        val first = c["first"] as Long
        val second = c["second"] as Long
        val got = outcome {
            verifyConsistency(
                first.toULong(), second.toULong(), roots.getValue(first), roots.getValue(second), path(c),
            ).toString()
        }
        expect(got, Outcome.Ok("true"), first to second)
    }
    val short = outcome { verifyInclusion(0UL, 1UL, ByteArray(31), ByteArray(0), roots.getValue(1L)).toString() }
    expect(short, Outcome.Err("input"), "short leaf")
    count("merkle.json", v.cases("inclusion").size + v.cases("consistency").size)
}

fun testErrorsCrossAsStableNames() {
    val first = hex(load("decision.json").cases()[0].str("input"))
    expect(outcome { hex(evaluate(first, 1_000_001UL)) }, Outcome.Err("input"), "fuel cap")
    expect(outcome { hex(evaluate(first, 0UL)) }, Outcome.Err("fuel"), "no fuel")
    try {
        evaluate(first, 0UL)
        failures.add("no fuel: no error")
    } catch (e: KernelException) {
        if (e !is KernelException.Fuel) failures.add("no fuel: $e is not KernelException.Fuel")
    }
    val empty = hex("a0")
    expect(outcome { hex(intentDigest(empty)) }, Outcome.Err("input"), "intent digest")
    expect(outcome { hex(verifyMetadata(empty, empty)) }, Outcome.Err("input"), "metadata")
    val validity = outcome {
        checkValidity(empty, 0UL, "pep:shop", emptyList(), null, true, 60_000UL, 0UL, 0UL)
        ""
    }
    expect(validity, Outcome.Err("input"), "validity")
    val ed = cborMap(listOf(tstr("ed25519") to bstr(b64url("6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw"))))
    val keys = keySet(listOf(ByteArray(32) { 1 } to ed), listOf(-19))
    val sd = outcome { verifySdJwt("x", keys, "t", "a", "n", 0UL, 0UL) }
    expect(sd, Outcome.Err("not an SD-JWT presentation"), "sd-jwt")
    expect(apiVersion(), "0.0", "api version")
}

fun main(args: Array<String>) {
    dir = File(args[0])
    testDecision()
    testCveRegressions()
    testCose()
    testKeyScope()
    testJoseAttackClasses()
    testJwtClaims()
    testSdJwt()
    testValidity()
    testMerkle()
    testErrorsCrossAsStableNames()
    val total = vectors.sumOf { it.second }
    println("vector cases: " + vectors.joinToString(" ") { "${it.first}=${it.second}" } + " total $total")
    failures.forEach { println("FAILED $it") }
    exitProcess(if (failures.isEmpty()) 0 else 1)
}
