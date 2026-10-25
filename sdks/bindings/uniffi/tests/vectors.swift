// OP-116 m.6
// The vectors.py cases through the uniffi Swift binding. Argument: conformance/vectors/core/1.

import CryptoKit
import Foundation

let vectors = URL(fileURLWithPath: CommandLine.arguments[1])
var counts: [(String, Int)] = []
var failures: [String] = []

func load(_ name: String) -> [String: Any] {
    let data = try! Data(contentsOf: vectors.appendingPathComponent(name))
    return try! JSONSerialization.jsonObject(with: data) as! [String: Any]
}

func count(_ name: String, _ n: Int) {
    counts.append((name, n))
}

func expect<T: Equatable>(_ got: T, _ want: T, _ id: Any) {
    if got != want {
        failures.append("\(id): got \(got), want \(want)")
    }
}

func hex(_ s: String) -> Data {
    var out = Data(capacity: s.utf8.count / 2)
    var i = s.startIndex
    while i < s.endIndex {
        let j = s.index(i, offsetBy: 2)
        out.append(UInt8(s[i..<j], radix: 16)!)
        i = j
    }
    return out
}

func hex(_ d: Data) -> String {
    d.map { String(format: "%02x", $0) }.joined()
}

func head(_ major: UInt8, _ n: Int) -> Data {
    switch n {
    case 0..<24: return Data([major << 5 | UInt8(n)])
    case 24..<0x100: return Data([major << 5 | 24, UInt8(n)])
    case 0x100..<0x10000: return Data([major << 5 | 25, UInt8(n >> 8), UInt8(n & 0xff)])
    default: fatalError("length out of range for this test encoder")
    }
}

func bstr(_ b: Data) -> Data { head(2, b.count) + b }

func tstr(_ s: String) -> Data { head(3, s.utf8.count) + Data(s.utf8) }

func cborMap(_ entries: [(Data, Data)]) -> Data {
    let sorted = entries.sorted { $0.0.lexicographicallyPrecedes($1.0) }
    return sorted.reduce(head(5, sorted.count)) { $0 + $1.0 + $1.1 }
}

func keySet(_ keys: [(Data, Data)], _ allowed: [Int]) -> Data {
    let algs = allowed.map { head(1, -1 - $0) }.sorted { $0.lexicographicallyPrecedes($1) }
    return cborMap([
        (tstr("keys"), cborMap(keys.map { (bstr($0.0), $0.1) })),
        (tstr("allowed"), algs.reduce(head(4, algs.count), +)),
    ])
}

func b64url(_ s: String) -> Data {
    var t = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    t += String(repeating: "=", count: (4 - t.count % 4) % 4)
    return Data(base64Encoded: t)!
}

func message(_ e: KernelError) -> String {
    let payload = Mirror(reflecting: e).children.first!.value
    if let s = payload as? String { return s }
    return Mirror(reflecting: payload).children.first!.value as! String
}

enum Outcome: Equatable, CustomStringConvertible {
    case ok(String)
    case error(String)

    var description: String {
        switch self {
        case .ok(let v): return "ok(\(v))"
        case .error(let v): return "error(\(v))"
        }
    }
}

func outcome(_ f: () throws -> String) -> Outcome {
    do {
        return .ok(try f())
    } catch let e as KernelError {
        return .error(message(e))
    } catch {
        return .error("unexpected \(error)")
    }
}

func cases(_ v: [String: Any], _ key: String = "cases") -> [[String: Any]] {
    v[key] as! [[String: Any]]
}

func u64(_ v: Any?) -> UInt64 { (v as! NSNumber).uint64Value }

func testDecision() {
    let v = load("decision.json")
    for c in cases(v) {
        let fuel = u64(c["fuel"] ?? v["fuel"])
        let got = outcome { hex(try evaluate(input: hex(c["input"] as! String), fuel: fuel)) }
        let want: Outcome = c["decision"] != nil
            ? .ok(c["decision"] as! String) : .error(c["rejection"] as! String)
        expect(got, want, c["id"]!)
    }
    count("decision.json", cases(v).count)
}

func testCveRegressions() {
    let v = load("cve-regressions.json")
    for c in cases(v) {
        if c["operation"] as! String == "combinator.evaluate" {
            let got = outcome { hex(try evaluate(input: hex(c["input"] as! String), fuel: u64(v["fuel"]))) }
            expect(got, .ok(c["decision"] as! String), c["id"]!)
        } else {
            let got = outcome {
                String(try childWithinParent(
                    child: hex(c["child"] as! String),
                    parent: hex(c["parent"] as! String),
                    holder: hex(c["holder"] as! String),
                    catalog: Data([0xa0])))
            }
            expect(got, .ok(String(c["within"] as! Bool)), c["id"]!)
        }
    }
    count("cve-regressions.json", cases(v).count)
}

func testCose() {
    let v = load("cose.json")
    let keys = keySet(
        (v["keys"] as! [String: String]).map { (hex($0.key), hex($0.value)) },
        v["allowed"] as! [Int])
    for c in cases(v) {
        let got = outcome {
            hex(try verifyCoseSign1(
                sign1: hex(c["sign1"] as! String), keySet: keys, contentType: v["content_type"] as! String))
        }
        let want: Outcome
        if let error = c["error"] as? String {
            want = .error(error)
        } else {
            want = .ok(hex(cborMap([
                (tstr("kid"), bstr(hex(c["kid"] as! String))),
                (tstr("payload"), bstr(hex(c["payload"] as! String))),
            ])))
        }
        expect(got, want, c["id"]!)
    }
    count("cose.json", cases(v).count)
}

func testKeyScope() {
    let v = load("key-scope.json")
    for c in cases(v) {
        let got = outcome {
            hex(try operationalKey(
                metadata: hex(c["metadata"] as! String),
                domain: hex(c["domain"] as! String),
                excerpt: hex(c["excerpt"] as! String),
                usage: c["usage"] as! String,
                iat: u64(c["iat"])))
        }
        let want: Outcome = c["error"] != nil ? .error(c["error"] as! String) : .ok(c["key"] as! String)
        expect(got, want, c["id"]!)
    }
    count("key-scope.json", cases(v).count)
}

func joseKeys(_ v: [String: Any]) -> [(Data, Data)] {
    (v["keys"] as! [String: String]).map { kid, key -> (Data, Data) in
        let raw = b64url(key)
        return (b64url(kid), cborMap([(tstr(raw.count == 32 ? "ed25519" : "p256"), bstr(raw))]))
    }
}

func verdict(_ got: Outcome) -> String {
    switch got {
    case .ok: return "accept"
    case .error(let name): return "reject: " + name
    }
}

func canonical(_ json: Any) -> String {
    let data = try! JSONSerialization.data(withJSONObject: json, options: [.sortedKeys, .fragmentsAllowed])
    return String(decoding: data, as: UTF8.self)
}

func testJoseAttackClasses() {
    let v = load("jose-attack-classes.json")
    let keys = joseKeys(v)
    for c in cases(v) {
        let ks = keySet(keys, (c["allowed"] ?? v["allowed"]) as! [Int])
        let got = outcome {
            try verifyJwsCompact(
                token: c["token"] as! String, keySet: ks, typ: v["typ"] as! String,
                issuer: "https://access.example", audience: "pep:shop", now: 1_500_000, skewMs: 60_000)
        }
        expect(verdict(got), c["expect"] as! String, c["id"]!)
    }
    count("jose-attack-classes.json", cases(v).count)
}

func testJwtClaims() {
    let v = load("jwt-claims.json")
    let ks = keySet(joseKeys(v), v["allowed"] as! [Int])
    for c in cases(v) {
        let ctx = (c["claims"] ?? v["claims"]) as! [String: Any]
        let got = outcome {
            try verifyJwsCompact(
                token: c["token"] as! String, keySet: ks, typ: v["typ"] as! String,
                issuer: ctx["issuer"] as! String, audience: ctx["audience"] as! String,
                now: u64(ctx["now"]), skewMs: u64(ctx["skew_ms"]))
        }
        expect(verdict(got), c["expect"] as! String, c["id"]!)
    }
    count("jwt-claims.json", cases(v).count)
}

func testSdJwt() {
    let v = load("sd-jwt.json")
    let ks = keySet(joseKeys(v), v["allowed"] as! [Int])
    let ctx = v["context"] as! [String: Any]
    for c in cases(v) {
        let got = outcome {
            let text = try verifySdJwt(
                presentation: c["presentation"] as! String, keySet: ks, typ: ctx["typ"] as! String,
                audience: ctx["audience"] as! String, nonce: ctx["nonce"] as! String,
                now: u64(ctx["now"]), skewMs: u64(ctx["skew_ms"]))
            return canonical(try JSONSerialization.jsonObject(with: Data(text.utf8), options: .fragmentsAllowed))
        }
        let want: Outcome = c["claims"] != nil ? .ok(canonical(c["claims"]!)) : .error(c["error"] as! String)
        expect(got, want, c["id"]!)
    }
    count("sd-jwt.json", cases(v).count)
}

func testValidity() {
    let v = load("validity.json")
    for c in cases(v) {
        let got = outcome {
            try checkValidity(
                contract: hex((c["contract"] ?? v["contract"]) as! String), now: u64(c["now"]),
                audience: v["audience"] as! String, understood: [],
                lastRefresh: c["last_refresh"].map { u64($0) }, online: (c["online"] ?? v["online"]) as! Bool,
                skewMs: u64(v["skew_ms"]), iat: u64(c["iat"]), horizonCapMs: u64(c["horizon_cap_ms"]))
            return ""
        }
        let want: Outcome = c["error"] != nil ? .error(c["error"] as! String) : .ok("")
        expect(got, want, c["id"]!)
    }
    count("validity.json", cases(v).count)
}

func testMerkle() {
    let v = load("merkle.json")
    var roots: [UInt64: Data] = [:]
    for r in cases(v, "roots") {
        roots[u64(r["size"])] = hex(r["root"] as! String)
    }
    let leaves = v["leaves"] as! [String]
    func path(_ c: [String: Any]) -> Data {
        (c["path"] as! [String]).reduce(Data()) { $0 + hex($1) }
    }
    for c in cases(v, "inclusion") {
        let (index, size) = (u64(c["index"]), u64(c["size"]))
        let leaf = Data(SHA256.hash(data: Data([0]) + hex(leaves[Int(index)])))
        let got = outcome {
            String(try verifyInclusion(index: index, size: size, leafHash: leaf, path: path(c), root: roots[size]!))
        }
        expect(got, .ok("true"), (index, size))
    }
    for c in cases(v, "consistency") {
        let (first, second) = (u64(c["first"]), u64(c["second"]))
        let got = outcome {
            String(try verifyConsistency(
                first: first, second: second, firstRoot: roots[first]!, secondRoot: roots[second]!, path: path(c)))
        }
        expect(got, .ok("true"), (first, second))
    }
    let short = outcome {
        String(try verifyInclusion(index: 0, size: 1, leafHash: Data(count: 31), path: Data(), root: roots[1]!))
    }
    expect(short, .error("input"), "short leaf")
    count("merkle.json", cases(v, "inclusion").count + cases(v, "consistency").count)
}

func testErrorsCrossAsStableNames() {
    let first = hex(cases(load("decision.json"))[0]["input"] as! String)
    expect(outcome { hex(try evaluate(input: first, fuel: 1_000_001)) }, .error("input"), "fuel cap")
    expect(outcome { hex(try evaluate(input: first, fuel: 0)) }, .error("fuel"), "no fuel")
    do {
        _ = try evaluate(input: first, fuel: 0)
        failures.append("no fuel: no error")
    } catch KernelError.Fuel {
    } catch {
        failures.append("no fuel: \(error) is not KernelError.Fuel")
    }
    let empty = Data([0xa0])
    expect(outcome { hex(try intentDigest(envelope: empty)) }, .error("input"), "intent digest")
    expect(outcome { hex(try verifyMetadata(metadata: empty, trusted: empty)) }, .error("input"), "metadata")
    let validity = outcome {
        try checkValidity(
            contract: empty, now: 0, audience: "pep:shop", understood: [], lastRefresh: nil, online: true,
            skewMs: 60_000, iat: 0, horizonCapMs: 0)
        return ""
    }
    expect(validity, .error("input"), "validity")
    let ed = cborMap([(tstr("ed25519"), bstr(b64url("6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw")))])
    let keys = keySet([(Data(repeating: 1, count: 32), ed)], [-19])
    let sd = outcome {
        try verifySdJwt(presentation: "x", keySet: keys, typ: "t", audience: "a", nonce: "n", now: 0, skewMs: 0)
    }
    expect(sd, .error("not an SD-JWT presentation"), "sd-jwt")
    expect(apiVersion(), "0.0", "api version")
}

@main
enum Vectors {
    static func main() {
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

        let total = counts.reduce(0) { $0 + $1.1 }
        print("vector cases:", counts.map { "\($0.0)=\($0.1)" }.joined(separator: " "), "total", total)
        for f in failures {
            print("FAILED", f)
        }
        exit(failures.isEmpty ? 0 : 1)
    }
}
