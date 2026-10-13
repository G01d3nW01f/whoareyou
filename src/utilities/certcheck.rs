use anyhow::Result;

use ring::digest::{digest, SHA256};

use x509_parser::{
    extensions::{GeneralName, ParsedExtension},
    parse_x509_certificate,
    prelude::*,
};

use crate::utilities::client::get_certificate;

fn get_attr(name: &X509Name, oid: &str) -> String {
    name.iter_attributes()
        .find(|attr| attr.attr_type().to_id_string() == oid)
        .and_then(|attr| attr.as_str().ok())
        .unwrap_or("")
        .to_string()
}

fn hex_string(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<String>>()
        .join(":")
}

pub fn print_certificate_info(url: &str) -> Result<()> {
    let cert_bytes = get_certificate(url)?;

    let (_, cert) = parse_x509_certificate(&cert_bytes)?;

    let subject = cert.subject();
    let issuer = cert.issuer();

    let subject_cn = get_attr(subject, "2.5.4.3");
    let subject_o = get_attr(subject, "2.5.4.10");
    let subject_ou = get_attr(subject, "2.5.4.11");

    let issuer_cn = get_attr(issuer, "2.5.4.3");
    let issuer_o = get_attr(issuer, "2.5.4.10");
    let issuer_ou = get_attr(issuer, "2.5.4.11");

    // SAN取得
    let mut san_list = Vec::<String>::new();

    for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for name in &san.general_names {
                match name {
                    GeneralName::DNSName(dns) => {
                        san_list.push(format!("DNS: {}", dns));
                    }

                    GeneralName::IPAddress(ip) => {
                        let ip_str = match ip.len() {
                            4 => {
                                format!(
                                    "{}.{}.{}.{}",
                                    ip[0], ip[1], ip[2], ip[3]
                                )
                            }

                            16 => {
                                ip.chunks(2)
                                    .map(|chunk| {
                                        if chunk.len() == 2 {
                                            format!(
                                                "{:02x}{:02x}",
                                                chunk[0],
                                                chunk[1]
                                            )
                                        } else {
                                            format!("{:02x}", chunk[0])
                                        }
                                    })
                                    .collect::<Vec<_>>()
                                    .join(":")
                            }

                            _ => format!("{:?}", ip),
                        };

                        san_list.push(format!("IP: {}", ip_str));
                    }

                    _ => {}
                }
            }
        }
    }

    // 証明書フィンガープリント
    let cert_fp = digest(&SHA256, &cert_bytes);

    // 公開鍵フィンガープリント
    let pubkey = cert.public_key();

    let pubkey_fp = digest(
        &SHA256,
        pubkey.raw,
    );

    println!("================================================");

    println!("発行先:");
    println!("  一般名 (CN) : {}", subject_cn);
    println!("  組織 (O)    : {}", subject_o);
    println!("  組織単位(OU): {}", subject_ou);

    println!();

    println!("発行元:");
    println!("  一般名 (CN) : {}", issuer_cn);
    println!("  組織 (O)    : {}", issuer_o);
    println!("  組織単位(OU): {}", issuer_ou);

    println!();

    println!("有効期間:");
    println!("  発行日     : {}", cert.validity().not_before);
    println!("  有効期限   : {}", cert.validity().not_after);

    println!();

    println!("Subject Alternative Name:");

    if san_list.is_empty() {
        println!("  なし");
    } else {
        for san in &san_list {
            println!("  {}", san);
        }
    }

    println!();

    println!("SHA-256フィンガープリント:");
    println!(
        "  証明書     : {}",
        hex_string(cert_fp.as_ref())
    );
    println!(
        "  公開鍵     : {}",
        hex_string(pubkey_fp.as_ref())
    );

    println!("================================================");

    Ok(())
}
