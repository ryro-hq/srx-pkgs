//! Qualification metadata is bound to the actual guest, runtime and report bytes.
use super::{Result, root};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::{Read as _, Write as _},
    path::Path,
};
const SCOPE: &str = "Two pinned Linux userspaces on the shared Linux 6.12.109 VM kernel; not distribution kernels or universal Linux support.";
fn hex(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn read(path: &Path) -> Result<Value> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.len() > 64 * 1024 * 1024 {
        return Err("expected bounded regular JSON file".into());
    }
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}
fn write(path: &Path, value: &Value) -> Result {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(&serde_json::to_vec_pretty(value)?)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}
fn digest(path: &Path) -> Result<String> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.len() > 32 * 1024 * 1024 * 1024 {
        return Err("expected bounded regular qualification input".into());
    }
    let mut file = fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    let mut size = 0;
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        size += n as u64;
        if size > meta.len() {
            return Err("qualification input changed".into());
        }
        hash.update(&buffer[..n]);
    }
    if size != meta.len() {
        return Err("qualification input changed".into());
    }
    Ok(format!("{:x}", hash.finalize()))
}
fn hosts(document: &Value) -> Result<&Vec<Value>> {
    let rows = document["include"]
        .as_array()
        .ok_or("missing host matrix")?;
    let mut seen = BTreeSet::new();
    for row in rows {
        let fields = row.as_object().ok_or("invalid host row")?;
        if fields.len() != 3
            || !["host", "base_image", "canonical"]
                .iter()
                .all(|name| fields.contains_key(*name))
        {
            return Err("unexpected host matrix fields".into());
        }
        let host = row["host"].as_str().ok_or("invalid host name")?;
        if !host.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
            || !host
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".-".contains(&b))
            || !seen.insert(host)
        {
            return Err("host names must be unique safe artifact names".into());
        }
        let image = row["base_image"].as_str().ok_or("invalid guest image")?;
        let (name, pin) = image
            .split_once("@sha256:")
            .ok_or("guest base image must be digest-pinned")?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"/.-".contains(&b))
            || !hex(pin)
            || !row["canonical"].is_boolean()
        {
            return Err("invalid host declaration".into());
        }
    }
    if rows.len() < 2 || rows.iter().filter(|row| row["canonical"] == true).count() != 1 {
        return Err("require multiple userspaces and one canonical release host".into());
    }
    Ok(rows)
}
fn matrix(packages: &Value, rows: &[Value]) -> Result<Value> {
    let entries = packages["include"]
        .as_array()
        .ok_or("missing package matrix")?;
    let mut seen = BTreeSet::new();
    let mut result = Vec::new();
    for entry in entries {
        let fields = entry.as_object().ok_or("invalid package matrix row")?;
        let id = entry["identity"]
            .as_str()
            .ok_or("missing package identity")?;
        if !hex(id)
            || !seen.insert(id)
            || ["host", "base_image", "canonical"]
                .iter()
                .any(|name| fields.contains_key(*name))
        {
            return Err("duplicate, invalid or host-overriding package identity".into());
        }
        for row in rows {
            let mut combined = fields.clone();
            combined.extend(row.as_object().ok_or("invalid host row")?.clone());
            result.push(Value::Object(combined));
        }
    }
    if result.is_empty() {
        return Err("empty package matrix".into());
    }
    Ok(json!({"include":result}))
}
fn record(row: &Value, directory: &Path) -> Result {
    let provenance = read(&directory.join("provenance.json"))?;
    if provenance["kernel"] != "6.12.109" || provenance["sdk"] != "0.7.3" {
        return Err("unexpected VM kernel or SDK".into());
    }
    let firmware = digest(&directory.join("libkrunfw.so.5.6.1"))?;
    if provenance["firmware_sha256"] != firmware {
        return Err("firmware differs from its provenance".into());
    }
    let image_id = fs::read_to_string(directory.join("image.id"))?;
    let image_id = image_id.trim();
    if !image_id.strip_prefix("sha256:").is_some_and(hex) {
        return Err("invalid built guest image ID".into());
    }
    let mut metadata = row.as_object().ok_or("invalid host row")?.clone();
    metadata.extend(json!({"schema":1,"scope":SCOPE,"kernel":provenance["kernel"],"sdk":provenance["sdk"],"image_id":image_id,
        "image_archive_sha256":digest(&directory.join("image.tar"))?,"runtime_sha256":digest(&directory.join("msb"))?,"firmware_sha256":firmware, "sbom_sha256":digest(&directory.join("host.spdx.json"))?, "musl_copyright_sha256":digest(&directory.join("musl-copyright"))?}).as_object().ok_or("invalid metadata")?.clone());
    write(
        &directory.join(format!(
            "host-{}.json",
            row["host"].as_str().ok_or("invalid host name")?
        )),
        &Value::Object(metadata),
    )
}
fn verified(row: &Value, directory: &Path) -> Result<Value> {
    let host = row["host"].as_str().ok_or("invalid host name")?;
    let metadata = read(&directory.join(format!("host-{host}.json")))?;
    if !row
        .as_object()
        .ok_or("invalid host row")?
        .iter()
        .all(|(key, value)| &metadata[key] == value)
        || metadata["schema"] != 1
        || metadata["kernel"] != "6.12.109"
        || metadata["sdk"] != "0.7.3"
    {
        return Err("guest metadata differs from configured host".into());
    }
    for key in ["image_archive_sha256", "runtime_sha256", "firmware_sha256"] {
        if !metadata[key].as_str().is_some_and(hex) {
            return Err(format!("invalid environment {key}").into());
        }
    }
    let sbom = directory.join(format!("host-{host}.spdx.json"));
    if metadata["sbom_sha256"] != digest(&sbom)? {
        return Err("qualification host SBOM changed".into());
    }
    if metadata["musl_copyright_sha256"]
        != digest(&directory.join(format!("musl-{host}.copyright")))?
    {
        return Err("qualification host copyright changed".into());
    }
    let manifest_path = directory.join(format!("manifest-{host}.json"));
    let manifest = read(&manifest_path)?;
    let mut reports = Vec::new();
    let mut seen = BTreeSet::new();
    for package in manifest["packages"]
        .as_array()
        .ok_or("missing manifest packages")?
    {
        let id = package["identity"]
            .as_str()
            .ok_or("missing package identity")?;
        if !hex(id) || !seen.insert(id) {
            return Err("invalid or duplicate manifest package identity".into());
        }
        let filename = format!("{id}.{host}.vm.json");
        let path = directory.join(&filename);
        let report = read(&path)?;
        if report["schema"] != 1
            || report["identity"] != id
            || report["status"] != "passed"
            || report["vm_cleanup"] != "destroyed"
        {
            return Err("combination lacks successful VM execution and cleanup".into());
        }
        let environment = &report["environment"];
        for key in [
            "image_archive_sha256",
            "runtime_sha256",
            "firmware_sha256",
            "sdk",
        ] {
            if environment[key] != metadata[key] {
                return Err(format!("combination used another host environment: {key}").into());
            }
        }
        if environment["firmware_provenance"]["kernel"] != metadata["kernel"]
            || environment["firmware_provenance"]["sdk"] != metadata["sdk"]
        {
            return Err("combination used another kernel".into());
        }
        reports.push(json!({"identity":id,"report":filename,"sha256":digest(&path)?}));
    }
    if reports.is_empty() {
        return Err("empty qualified identities".into());
    }
    Ok(
        json!({"schema":1,"scope":SCOPE,"host":metadata,"manifest":manifest_path.file_name().ok_or("invalid manifest path")?,"manifest_sha256":digest(&manifest_path)?,"vm_reports":reports}),
    )
}
pub(super) fn execute(command: &str, args: &[&str]) -> Result {
    let config = read(&root().join(".github/qualification-hosts.json"))?;
    let rows = hosts(&config)?;
    match (command, args) {
        ("matrix", [packages]) => {
            println!("hosts={}", json!({"include":rows}));
            println!("matrix={}", matrix(&read(Path::new(packages))?, rows)?);
            Ok(())
        }
        (command @ ("record" | "verify"), [host, directory]) => {
            let row = rows
                .iter()
                .find(|row| row["host"] == *host)
                .ok_or("host absent from qualification matrix")?;
            let directory = Path::new(directory);
            if command == "record" {
                record(row, directory)
            } else {
                write(
                    &directory.join(format!("qualification-{host}.json")),
                    &verified(row, directory)?,
                )
            }
        }
        _ => Err(
            "qualification matrix PACKAGES | record HOST DIRECTORY | verify HOST DIRECTORY".into(),
        ),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> Value {
        json!({"include":[{"host":"debian","base_image":format!("debian@sha256:{}", "a".repeat(64)),"canonical":true},{"host":"ubuntu","base_image":format!("ubuntu@sha256:{}", "b".repeat(64)),"canonical":false}]})
    }
    #[test]
    fn matrix_refuses_collisions_mutable_images_and_ambiguous_publication() {
        let mut value = config();
        hosts(&value).unwrap();
        let packages = json!({"include":[{"identity":"c".repeat(64)}]});
        assert_eq!(
            matrix(&packages, hosts(&value).unwrap()).unwrap()["include"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        let overridden = json!({"include":[{"identity":"c".repeat(64), "host":"injected"}]});
        assert!(matrix(&overridden, hosts(&value).unwrap()).is_err());
        value["include"][1]["canonical"] = json!(true);
        assert!(hosts(&value).is_err());
        value = config();
        value["include"][0]["base_image"] = json!("debian:latest");
        assert!(hosts(&value).is_err());
        value = config();
        value["include"][1]["host"] = json!("debian");
        assert!(hosts(&value).is_err());
    }
    #[test]
    fn reports_bind_manifest_bytes_guest_and_cleanup() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path();
        let row = &config()["include"][0];
        let id = "c".repeat(64);
        fs::write(dir.join("host-debian.spdx.json"), b"{\"packages\":[]}").unwrap();
        fs::write(dir.join("musl-debian.copyright"), b"upstream notices").unwrap();
        let metadata = json!({"sbom_sha256":digest(&dir.join("host-debian.spdx.json")).unwrap(),"host":"debian","base_image":row["base_image"],"canonical":true,"schema":1,"kernel":"6.12.109","sdk":"0.7.3","image_archive_sha256":"a".repeat(64),"runtime_sha256":"b".repeat(64),"firmware_sha256":"d".repeat(64)});
        let mut metadata = metadata;
        metadata["musl_copyright_sha256"] =
            json!(digest(&dir.join("musl-debian.copyright")).unwrap());
        write(&dir.join("host-debian.json"), &metadata).unwrap();
        write(
            &dir.join("manifest-debian.json"),
            &json!({"packages":[{"identity":id}]}),
        )
        .unwrap();
        let mut report = json!({"schema":1,"identity":id,"status":"passed","vm_cleanup":"destroyed","environment":{"image_archive_sha256":metadata["image_archive_sha256"],"runtime_sha256":metadata["runtime_sha256"],"firmware_sha256":metadata["firmware_sha256"],"sdk":"0.7.3","firmware_provenance":{"kernel":"6.12.109","sdk":"0.7.3"}}});
        let report_path = dir.join(format!("{id}.debian.vm.json"));
        write(&report_path, &report).unwrap();
        assert_eq!(
            verified(row, dir).unwrap()["vm_reports"][0]["sha256"],
            digest(&report_path).unwrap()
        );
        fs::write(dir.join("musl-debian.copyright"), b"changed notices").unwrap();
        assert!(verified(row, dir).is_err());
        fs::write(dir.join("musl-debian.copyright"), b"upstream notices").unwrap();
        for (pointer, value) in [
            ("/vm_cleanup", "unknown"),
            ("/status", "failed"),
            ("/environment/runtime_sha256", "e"),
            ("/environment/firmware_provenance/kernel", "wrong"),
        ] {
            let old = report.pointer(pointer).unwrap().clone();
            *report.pointer_mut(pointer).unwrap() = json!(value);
            fs::write(&report_path, serde_json::to_vec(&report).unwrap()).unwrap();
            assert!(verified(row, dir).is_err());
            *report.pointer_mut(pointer).unwrap() = old;
        }
        for name in ["image.tar", "msb", "libkrunfw.so.5.6.1"] {
            fs::write(dir.join(name), name).unwrap();
        }
        fs::write(dir.join("image.id"), format!("sha256:{}", "a".repeat(64))).unwrap();
        write(
            &dir.join("provenance.json"),
            &json!({"kernel":"6.12.109","sdk":"0.7.3","firmware_sha256":"wrong"}),
        )
        .unwrap();
        assert!(record(&config()["include"][1], dir).is_err());
    }
}
