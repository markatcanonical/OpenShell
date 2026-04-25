// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use miette::{miette, IntoDiagnostic, Result, WrapErr};
use std::env;
use std::path::PathBuf;
use owo_colors::OwoColorize;
use tokio::process::Command;

use openshell_driver_podman::client::PodmanClient;

/// Initialize Podman to serve as a compute driver for OpenShell.
pub async fn init() -> Result<()> {
    println!("{}", "Initializing Podman for OpenShell...".bold());

    // 1. Check socket path
    let socket_path = env::var("OPENSHELL_PODMAN_SOCKET").unwrap_or_else(|_| {
        "/var/snap/openshell/common/podman.sock".to_string()
    });

    let socket_path_buf = PathBuf::from(&socket_path);
    if !socket_path_buf.exists() {
        println!("\n{}", "Podman socket not found!".red().bold());
        println!("Expected socket at: {}", socket_path);
        println!("\nIf you are running OpenShell as a snap, you must bind-mount your rootless podman socket:");
        println!("  sudo mount --bind /run/user/$(id -u)/podman/podman.sock /var/snap/openshell/common/podman.sock");
        println!("\nAlternatively, set OPENSHELL_PODMAN_SOCKET to your socket path if running natively.");
        return Err(miette!("Podman socket not found at {}", socket_path));
    }

    println!("✓ Found Podman socket at: {}", socket_path);

    // 2. Verify connectivity
    let client = PodmanClient::new(socket_path_buf.clone());
    client.ping().await.into_diagnostic().wrap_err("Failed to connect to Podman daemon")?;
    println!("✓ Successfully connected to Podman daemon");

    // 3. Load the OCI archive rock using skopeo
    // The rock is located at $SNAP/images/openshell-core.rock
    let snap_dir = env::var("SNAP").unwrap_or_else(|_| ".".to_string());
    let rock_path = PathBuf::from(snap_dir).join("images").join("openshell-core.rock");

    if !rock_path.exists() {
        println!("{}", "Warning: openshell-core.rock not found locally. Skipping image load.".yellow());
    } else {
        println!("Loading sandbox images from {}...", rock_path.display());
        
        let skopeo_bin = "skopeo";
        // Skopeo can push an OCI archive to the podman daemon.
        // We load it as openshell/supervisor:latest because that's the default supervisor image.
        // We will also load it as openshell/base:latest for the default sandbox image.
        let target_supervisor = "docker-daemon:openshell/supervisor:latest";
        let target_base = "docker-daemon:openshell/base:latest";

        for target in &[target_supervisor, target_base] {
            let mut cmd = Command::new(skopeo_bin);
            cmd.arg("copy")
               .arg("--insecure-policy")
               .arg(format!("oci-archive:{}", rock_path.display()))
               .arg(target)
               .env("DOCKER_HOST", format!("unix://{}", socket_path));

            let status = cmd.status().await.into_diagnostic().wrap_err("Failed to execute skopeo")?;
            
            if !status.success() {
                return Err(miette!("Failed to load OCI archive into Podman. skopeo exited with {}", status));
            }
        }
        println!("✓ Sandbox images loaded into Podman");
    }

    // 4. Print configuration instructions
    println!("\n{}", "Podman initialization complete!".green().bold());
    println!("To configure OpenShell to use the Podman compute driver, run:");
    println!("  openshell settings set --global --key compute_drivers --value podman");
    println!("  openshell settings set --global --key podman_socket_path --value {}", socket_path);

    Ok(())
}
