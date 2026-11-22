//! Автозапуск GUI с Windows. Приложению нужны права администратора, а ключ Run
//! их не даёт, поэтому используется задача планировщика с наивысшими правами.
//! XML нужен, чтобы снять ограничения по питанию от батареи и лимит времени.

const TASK: &str = "digital-bypass";

fn schtasks() -> String {
    crate::util::system32("schtasks.exe")
}

pub fn is_enabled() -> bool {
    crate::util::run_hidden(&schtasks(), &["/query", "/tn", TASK]).map(|o| o.status.success()).unwrap_or(false)
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

pub fn set(enabled: bool) -> Result<(), String> {
    if !enabled {
        let _ = crate::util::run_hidden(&schtasks(), &["/delete", "/tn", TASK, "/f"]);
        return Ok(());
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let user = match (std::env::var("USERDOMAIN"), std::env::var("USERNAME")) {
        (Ok(d), Ok(u)) => format!("{d}\\{u}"),
        (_, Ok(u)) => u,
        _ => return Err(crate::tr!("не удалось определить пользователя", "could not determine the current user")),
    };
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled><UserId>{user}</UserId><Delay>PT5S</Delay></LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author"><UserId>{user}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec><Command>{exe}</Command><Arguments>--tray</Arguments></Exec>
  </Actions>
</Task>"#,
        user = xml_escape(&user),
        exe = xml_escape(&exe.to_string_lossy()),
    );
    // schtasks читает XML в UTF-16 LE с BOM.
    let mut bytes = vec![0xFF, 0xFE];
    for u in xml.encode_utf16() {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    let path = std::env::temp_dir().join("digital-bypass-task.xml");
    std::fs::write(&path, bytes).map_err(|e| e.to_string())?;
    let out = crate::util::run_hidden(&schtasks(), &["/create", "/tn", TASK, "/xml", &path.to_string_lossy(), "/f"])
        .map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(&path);
    if out.status.success() {
        Ok(())
    } else {
        Err(format!("schtasks: {}", String::from_utf8_lossy(&out.stderr).trim()))
    }
}
