//! Configuration-output tests of the signers' deployment (OP-158 m.3 (y)): the k8s manifests,
//! the admission policy and the hosting profiles say what the spec asks. The cluster, the
//! admission controller and the reserved hardware are the operator's; these tests check what
//! Access ships.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::string_slice,
    reason = "test code"
)]

use std::path::PathBuf;

fn read(path: &str) -> String {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../deploy/k8s");
    std::fs::read_to_string(root.join(path)).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// The lines of the block that starts at the line `head` and runs while lines are indented
/// deeper than it.
fn block<'a>(text: &'a str, head: &str) -> Vec<&'a str> {
    let mut lines = text.lines().skip_while(|l| l.trim_end() != head);
    let Some(first) = lines.next() else {
        panic!("no `{head}`");
    };
    let indent = first.len() - first.trim_start().len();
    lines
        .take_while(|l| l.trim().is_empty() || l.len() - l.trim_start().len() > indent)
        .collect()
}

/// The container named `name` in the statefulset.
fn container(name: &str) -> Vec<&'static str> {
    let text: &'static str = Box::leak(read("statefulset.yaml").into_boxed_str());
    block(text, &format!("        - name: {name}"))
}

// U49, §14.5, OP-158
#[test]
fn the_admission_policy_refuses_images_ci_did_not_sign() {
    let policy = read("admission/cluster-image-policy.yaml");
    assert!(policy.contains("kind: ClusterImagePolicy"));
    assert!(policy.contains("mode: enforce"));
    assert!(policy.contains(r#"- glob: "ghcr.io/e-suiss/access**""#));
    assert!(policy.contains("issuer: https://token.actions.githubusercontent.com"));
    let subject = policy
        .lines()
        .find_map(|l| l.trim().strip_prefix("subjectRegExp: "))
        .unwrap();
    for signed in [
        "https://github.com/e-suiss/access/.github/workflows/image.yml@refs/heads/main",
        "https://github.com/e-suiss/access/.github/workflows/release.yml@refs/tags/v0.6.0",
    ] {
        assert!(matches(subject, signed), "{signed}");
    }
    for unsigned in [
        "",
        "https://github.com/e-suiss/access/.github/workflows/image.yml@refs/heads/feature",
        "https://github.com/e-suiss/access/.github/workflows/ci.yml@refs/heads/main",
        "https://github.com/someone/access/.github/workflows/image.yml@refs/heads/main",
        "https://github.com/e-suiss/access/.github/workflows/release.yml@refs/tags/v0.6.0-x",
    ] {
        assert!(!matches(subject, unsigned), "{unsigned}");
    }
    assert!(
        !policy.contains("static:"),
        "no image passes without a signature"
    );
    let namespace = read("namespace.yaml");
    assert!(namespace.contains(r#"policy.sigstore.dev/include: "true""#));
    for f in ["statefulset.yaml", "migrate-job.yaml"] {
        for image in read(f)
            .lines()
            .filter_map(|l| l.trim().strip_prefix("image: "))
        {
            assert!(
                image.starts_with("ghcr.io/e-suiss/access@sha256:"),
                "{f}: {image}"
            );
        }
    }
}

/// A matcher for the one regular expression shape the policy uses: anchors, literal text,
/// escaped dots, one `(a|b)` group per alternative set and `[0-9]+`.
fn matches(pattern: &str, text: &str) -> bool {
    let p = pattern
        .strip_prefix('^')
        .unwrap()
        .strip_suffix('$')
        .unwrap();
    expand(p).iter().any(|alt| literal_match(alt, text))
}

fn expand(p: &str) -> Vec<String> {
    let Some(open) = p.find('(') else {
        return vec![p.to_owned()];
    };
    let close = p[open..].find(')').unwrap() + open;
    let (head, alts, tail) = (&p[..open], &p[open + 1..close], &p[close + 1..]);
    alts.split('|')
        .flat_map(|a| expand(&format!("{head}{a}{tail}")))
        .collect()
}

fn literal_match(p: &str, text: &str) -> bool {
    let (mut p, mut t) = (p, text);
    loop {
        if p.is_empty() {
            return t.is_empty();
        }
        if let Some(rest) = p.strip_prefix("[0-9]+") {
            let digits = t.len() - t.trim_start_matches(|c: char| c.is_ascii_digit()).len();
            if digits == 0 {
                return false;
            }
            (p, t) = (rest, &t[digits..]);
        } else if let Some(rest) = p.strip_prefix('\\') {
            let c = rest.chars().next().unwrap();
            if !t.starts_with(c) {
                return false;
            }
            (p, t) = (&rest[c.len_utf8()..], &t[c.len_utf8()..]);
        } else {
            let c = p.chars().next().unwrap();
            if !t.starts_with(c) {
                return false;
            }
            (p, t) = (&p[c.len_utf8()..], &t[c.len_utf8()..]);
        }
    }
}

// U54, MD-17, SA-25, OP-158
#[test]
fn the_dedicated_profile_carries_nosmt_and_a_reserved_node_selector() {
    let k = read("profiles/dedicated/kustomization.yaml");
    assert!(k.contains("kind: Component"));
    let patch = read("profiles/dedicated/statefulset.yaml");
    assert!(patch.contains("access.suiss.dev/compute: dedicated"));
    assert!(patch.contains("key: access.suiss.dev/dedicated"));
    assert!(patch.contains("effect: NoSchedule"));
    assert!(patch.contains("requiredDuringSchedulingIgnoredDuringExecution"));
    assert!(patch.contains("key: access.suiss.dev/kernel-mitigations"));
    assert!(patch.contains(r#"values: ["auto-nosmt"]"#));
    let grub = read("profiles/dedicated/node.grub.cfg");
    let cmdline = grub
        .lines()
        .find(|l| l.starts_with("GRUB_CMDLINE_LINUX_DEFAULT="))
        .unwrap();
    assert!(cmdline.contains("mitigations=auto,nosmt"), "{cmdline}");
    assert!(!read("statefulset.yaml").contains("access.suiss.dev/compute"));
}

// CR-40, SAI-45, OP-158
#[test]
fn the_signer_isolation_profile_gives_signers_whole_cores() {
    let patch = read("profiles/signer-isolated/statefulset.yaml");
    for name in ["authority-signer", "identity-signer", "access-server"] {
        let c = block(&patch, &format!("        - name: {name}"));
        let req = c.iter().find(|l| l.contains("requests:")).unwrap();
        let lim = c.iter().find(|l| l.contains("limits:")).unwrap();
        assert_eq!(
            req.trim().trim_start_matches("requests:"),
            lim.trim().trim_start_matches("limits:"),
            "{name}: requests equal limits"
        );
        assert!(
            req.contains(r#"cpu: "1""#) || req.contains(r#"cpu: "2""#),
            "{name}"
        );
    }
    let kubelet = read("profiles/signer-isolated/kubelet.yaml");
    assert!(kubelet.contains("cpuManagerPolicy: static"));
    assert!(kubelet.contains(r#"full-pcpus-only: "true""#));
}

// SAI-45, CMP-22a, CMP-22b, OP-94, OP-158
#[test]
fn the_signers_are_separate_native_sidecars_with_their_own_keys() {
    let set = read("statefulset.yaml");
    let init = set.find("      initContainers:").unwrap();
    let main = set.find("      containers:").unwrap();
    assert!(init < main);
    for (name, binary, config) in [
        ("authority-signer", "access-signer", "signer.toml"),
        (
            "identity-signer",
            "access-identity-signer",
            "identity-signer.toml",
        ),
    ] {
        let c = container(name);
        let text = c.join("\n");
        let at = set.find(&format!("        - name: {name}")).unwrap();
        assert!(init < at && at < main, "{name} is a native sidecar");
        assert!(text.contains("restartPolicy: Always"), "{name}");
        assert!(text.contains(&format!(r#"command: ["/usr/local/bin/{binary}"]"#)));
        assert!(text.contains(&format!("value: /etc/access/{config}")));
        assert!(
            text.contains("mountPath: /run/access"),
            "{name}: the socket directory"
        );
        assert!(!text.contains("containerPort"), "{name}: no network port");
        assert!(text.contains("drop: [ALL]"), "{name}");
        assert!(text.contains("readOnlyRootFilesystem: true"), "{name}");
    }
    let server = container("access-server").join("\n");
    assert!(
        !server.contains("signer-vault"),
        "the server never mounts a signer's keys"
    );
    assert!(!server.contains("hsm-signer-pin"));
    let config = read("configmap.yaml");
    for toml in ["signer.toml: |", "identity-signer.toml: |"] {
        let body = block(&config, &format!("  {toml}")).join("\n");
        assert!(body.contains(r#"hardening = "paranoid""#), "{toml}");
        assert!(body.contains(r#"secret_memory = "memfd_secret""#), "{toml}");
    }
}

// CR-35, OP-129, OP-148, OP-158
#[test]
fn every_secret_file_comes_from_the_csi_provider_and_none_from_env_or_secret_objects() {
    let provided = read("secretproviderclass.yaml");
    let objects: Vec<&str> = provided
        .lines()
        .filter_map(|l| l.trim().strip_prefix("- objectName: "))
        .collect();
    for required in ["db-router", "db-archive", "db-outbox-reader"] {
        assert!(objects.contains(&required), "{required}");
    }
    let config = read("configmap.yaml");
    let referenced: Vec<&str> = config
        .split("/run/secrets/")
        .skip(1)
        .filter_map(|s| s.split('"').next())
        .collect();
    assert_ne!(referenced.len(), 0);
    for file in &referenced {
        assert!(
            objects.contains(file),
            "/run/secrets/{file} has no CSI object"
        );
    }
    assert!(provided.contains("vaultAuthMountPath: spiffe"));
    for f in [
        "statefulset.yaml",
        "migrate-job.yaml",
        "configmap.yaml",
        "secretproviderclass.yaml",
    ] {
        let text = read(f);
        assert!(!text.contains("secretKeyRef"), "{f}");
        assert!(!text.contains("kind: Secret\n"), "{f}");
        assert!(!text.contains("secret:\n"), "{f}: no Secret volume");
    }
    let set = read("statefulset.yaml");
    assert!(set.contains("driver: secrets-store.csi.k8s.io"));
    assert!(set.contains("secretProviderClass: access-server"));
    assert!(read("migrate-job.yaml").contains("secretProviderClass: access-migrate"));
    assert!(read("kustomization.yaml").contains("- secretproviderclass.yaml"));
}

// OP-146 m.12 (f), OP-148
#[test]
fn the_image_carries_the_hosted_login_and_the_configuration_points_at_it() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../deploy/docker/Dockerfile");
    let dockerfile = std::fs::read_to_string(root).unwrap();
    let runtime = dockerfile.split("AS runtime").nth(1).unwrap();
    assert!(runtime.contains("COPY --from=web /src/web/login/dist /usr/share/access/login"));
    assert!(read("configmap.yaml").contains(r#"dist_dir = "/usr/share/access/login""#));
}
