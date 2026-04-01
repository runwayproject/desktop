use std::process;
use std::sync::Mutex;

mod client;

use client::{ClientSnapshot, ClientState};

struct AppState {
    client: Mutex<ClientState>,
}

#[tauri::command]
fn get_snapshot(state: tauri::State<'_, AppState>) -> Result<ClientSnapshot, String> {
    let client = state
        .client
        .lock()
        .map_err(|_| "client state lock poisoned".to_string())?;
    Ok(client.snapshot())
}

#[tauri::command]
fn fetch_messages(
    state: tauri::State<'_, AppState>,
    quiet_empty: bool,
) -> Result<ClientSnapshot, String> {
    let mut client = state
        .client
        .lock()
        .map_err(|_| "client state lock poisoned".to_string())?;
    client
        .fetch_messages(quiet_empty)
        .map_err(|err| err.to_string())?;
    Ok(client.snapshot())
}

#[tauri::command]
fn send_message(
    state: tauri::State<'_, AppState>,
    message: String,
) -> Result<ClientSnapshot, String> {
    let mut client = state
        .client
        .lock()
        .map_err(|_| "client state lock poisoned".to_string())?;
    client
        .send_message(message)
        .map_err(|err| err.to_string())?;
    Ok(client.snapshot())
}

#[tauri::command]
fn add_peer(
    state: tauri::State<'_, AppState>,
    target_rid: String,
) -> Result<ClientSnapshot, String> {
    let mut client = state
        .client
        .lock()
        .map_err(|_| "client state lock poisoned".to_string())?;
    client.add_peer(target_rid).map_err(|err| err.to_string())?;
    Ok(client.snapshot())
}

#[tauri::command]
fn create_group(state: tauri::State<'_, AppState>) -> Result<ClientSnapshot, String> {
    let mut client = state
        .client
        .lock()
        .map_err(|_| "client state lock poisoned".to_string())?;
    client.create_group().map_err(|err| err.to_string())?;
    Ok(client.snapshot())
}

#[tauri::command]
fn add_member(
    state: tauri::State<'_, AppState>,
    member_rid: String,
) -> Result<ClientSnapshot, String> {
    let mut client = state
        .client
        .lock()
        .map_err(|_| "client state lock poisoned".to_string())?;
    client
        .add_member(member_rid)
        .map_err(|err| err.to_string())?;
    Ok(client.snapshot())
}

#[tauri::command]
fn select_group(
    state: tauri::State<'_, AppState>,
    group_id: String,
) -> Result<ClientSnapshot, String> {
    let mut client = state
        .client
        .lock()
        .map_err(|_| "client state lock poisoned".to_string())?;
    client
        .select_group(group_id)
        .map_err(|err| err.to_string())?;
    Ok(client.snapshot())
}

#[tauri::command]
fn leave_group(state: tauri::State<'_, AppState>) -> Result<ClientSnapshot, String> {
    let mut client = state
        .client
        .lock()
        .map_err(|_| "client state lock poisoned".to_string())?;
    client.leave_group().map_err(|err| err.to_string())?;
    Ok(client.snapshot())
}

#[tauri::command]
fn accept_pending_offer(state: tauri::State<'_, AppState>) -> Result<ClientSnapshot, String> {
    let mut client = state
        .client
        .lock()
        .map_err(|_| "client state lock poisoned".to_string())?;
    client
        .accept_pending_offer()
        .map_err(|err| err.to_string())?;
    Ok(client.snapshot())
}

#[tauri::command]
fn reject_pending_offer(state: tauri::State<'_, AppState>) -> Result<ClientSnapshot, String> {
    let mut client = state
        .client
        .lock()
        .map_err(|_| "client state lock poisoned".to_string())?;
    client
        .reject_pending_offer()
        .map_err(|err| err.to_string())?;
    Ok(client.snapshot())
}

#[tauri::command]
fn clear_activity(state: tauri::State<'_, AppState>) -> Result<ClientSnapshot, String> {
    let mut client = state
        .client
        .lock()
        .map_err(|_| "client state lock poisoned".to_string())?;
    client.clear_activity();
    Ok(client.snapshot())
}

#[tauri::command]
fn rotate_rid(state: tauri::State<'_, AppState>) -> Result<ClientSnapshot, String> {
    let mut client = state
        .client
        .lock()
        .map_err(|_| "client state lock poisoned".to_string())?;
    client.rotate_rid().map_err(|err| err.to_string())?;
    Ok(client.snapshot())
}
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let server_addr = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "127.0.0.1:32767".to_string());

    let client = match ClientState::connect(server_addr) {
        Ok(client) => client,
        Err(err) => {
            eprintln!("client bootstrap failed: {err:#}");
            process::exit(1);
        }
    };

    tauri::Builder::default()
        .manage(AppState {
            client: Mutex::new(client),
        })
        .invoke_handler(tauri::generate_handler![
            get_snapshot,
            fetch_messages,
            send_message,
            add_peer,
            create_group,
            add_member,
            select_group,
            leave_group,
            accept_pending_offer,
            reject_pending_offer,
            clear_activity,
            rotate_rid,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
