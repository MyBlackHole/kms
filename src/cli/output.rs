use crate::cli::config::OutputFormat;
use std::fmt::Write;

pub fn print_result(value: &serde_json::Value, format: &OutputFormat) {
    match format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(value).unwrap_or_default()
            );
        }
        OutputFormat::Table => {
            if let Some(obj) = value.as_object() {
                print_table(obj);
            } else if let Some(arr) = value.as_array() {
                if let Some(first) = arr.first().and_then(|v| v.as_object()) {
                    print_array_table(arr, first);
                } else {
                    for item in arr {
                        println!("{}", item);
                    }
                }
            } else if let Some(s) = value.as_str() {
                println!("{}", s);
            } else {
                println!("{}", value);
            }
        }
    }
}

fn print_table(obj: &serde_json::Map<String, serde_json::Value>) {
    let mut out = String::new();
    for (key, val) in obj {
        let val_str = match val {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Null => "<null>".to_string(),
            other => other.to_string(),
        };
        let _ = writeln!(out, "  {}: {}", key, val_str);
    }
    print!("{}", out);
}

fn print_array_table(
    arr: &[serde_json::Value],
    first: &serde_json::Map<String, serde_json::Value>,
) {
    let keys: Vec<&str> = first.keys().map(|k| k.as_str()).collect();
    let widths: Vec<usize> = keys
        .iter()
        .map(|k| {
            arr.iter()
                .map(|row| row.get(k).map(cell_width).unwrap_or(0))
                .chain(std::iter::once(k.len()))
                .max()
                .unwrap_or(0)
        })
        .collect();

    let header: String = keys
        .iter()
        .zip(&widths)
        .map(|(k, w)| format!("{:width$}", k, width = w))
        .collect::<Vec<_>>()
        .join("  ");
    println!("{}", header);
    println!("{}", header.chars().map(|_| '-').collect::<String>());

    for row in arr {
        let line: String = keys
            .iter()
            .zip(&widths)
            .map(|(k, w)| {
                let val = row
                    .get(k)
                    .map(|v| match v {
                        serde_json::Value::Null => "-".to_string(),
                        serde_json::Value::String(s) => s.clone(),
                        other => other.to_string(),
                    })
                    .unwrap_or_default();
                format!("{:width$}", val, width = w)
            })
            .collect::<Vec<_>>()
            .join("  ");
        println!("{}", line);
    }
}

fn cell_width(v: &serde_json::Value) -> usize {
    match v {
        serde_json::Value::String(s) => s.len(),
        serde_json::Value::Null => 1,
        other => other.to_string().len(),
    }
}

pub fn print_success(msg: &str) {
    println!("✓ {}", msg);
}

pub fn print_error(msg: &str) {
    eprintln!("✗ {}", msg);
}
