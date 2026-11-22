// В release-сборке встраиваем манифест с requireAdministrator: WinDivert,
// службы и hosts требуют прав администратора. В debug (tauri dev) права не
// запрашиваются, чтобы dev-сервер мог запустить exe; приложение само
// показывает баннер «нет прав» и работает в режиме только чтения.
fn main() {
    let release = std::env::var("PROFILE").map(|p| p == "release").unwrap_or(false);
    let level = if release { "requireAdministrator" } else { "asInvoker" };
    let manifest = format!(
        r#"<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0"
        processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*" />
    </dependentAssembly>
  </dependency>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="{level}" uiAccess="false" />
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>"#
    );
    let attrs = tauri_build::Attributes::new()
        .windows_attributes(tauri_build::WindowsAttributes::new().app_manifest(manifest));
    tauri_build::try_build(attrs).expect("tauri build failed");
    println!("cargo:rerun-if-env-changed=PROFILE");
    // Иконка вшивается в exe здесь: при её замене скрипт должен перезапуститься.
    println!("cargo:rerun-if-changed=icons/icon.ico");
}
