use std::collections::HashMap;

use serde_json::Value;

use super::cdp::client::CdpClient;
use super::cdp::types::*;
use super::element::{
    resolve_element_center, resolve_element_object_id, session_viewport_offset, RefMap,
};

/// Outcome of a click. `dialog_opened` is true if a JavaScript dialog opened
/// mid-sequence (the page is then blocked until `dialog accept`/`dismiss`).
/// `pending_release` is set only when the dialog opened after mousePressed but
/// before mouseReleased: the button is logically held until the caller
/// dispatches the release (done once the dialog is resolved), otherwise the
/// next click would register as a drag or double-click.
#[derive(Default)]
pub struct ClickResult {
    /// Final pointer position in the top-level page viewport, including dialogs.
    pub position: (f64, f64),
    pub dialog_opened: bool,
    pub pending_release: Option<PendingRelease>,
    pub x: f64,
    pub y: f64,
    pub button_pressed: bool,
}

pub struct PendingRelease {
    pub session_id: String,
    pub x: f64,
    pub y: f64,
    pub button: String,
    pub modifiers: i32,
}

pub async fn click(
    client: &CdpClient,
    session_id: &str,
    ref_map: &RefMap,
    selector_or_ref: &str,
    button: &str,
    click_count: i32,
    iframe_sessions: &HashMap<String, String>,
) -> Result<ClickResult, String> {
    click_with_modifiers(
        client,
        session_id,
        ref_map,
        selector_or_ref,
        button,
        click_count,
        0,
        iframe_sessions,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn click_with_modifiers(
    client: &CdpClient,
    session_id: &str,
    ref_map: &RefMap,
    selector_or_ref: &str,
    button: &str,
    click_count: i32,
    modifiers: i32,
    iframe_sessions: &HashMap<String, String>,
) -> Result<ClickResult, String> {
    let (mut x, mut y, effective_session_id) = resolve_element_center(
        client,
        session_id,
        ref_map,
        selector_or_ref,
        iframe_sessions,
    )
    .await?;
    // A click-triggered dialog can fire on the frame's own session (OOPIF) or
    // on the top-level page session; both count as "ours". A dialog on any
    // other session belongs to a background tab and must not abort this click.
    let offset =
        session_viewport_offset(client, session_id, &effective_session_id, iframe_sessions).await?;
    if click_count == 2 {
        let mut first = dispatch_click(
            client,
            &effective_session_id,
            &[effective_session_id.as_str(), session_id],
            x,
            y,
            button,
            1,
            modifiers,
        )
        .await?;
        if first.dialog_opened {
            first.position = (x + offset.0, y + offset.1);
            (first.x, first.y) = first.position;
            return Ok(first);
        }
        let (next_x, next_y, next_session) = resolve_element_center(
            client,
            session_id,
            ref_map,
            selector_or_ref,
            iframe_sessions,
        )
        .await
        .map_err(|_| {
            "Double click target unavailable after input may have committed".to_string()
        })?;
        if next_session != effective_session_id {
            return Err("Double click frame changed after input may have committed".into());
        }
        x = next_x;
        y = next_y;
    }
    let mut result = dispatch_click(
        client,
        &effective_session_id,
        &[effective_session_id.as_str(), session_id],
        x,
        y,
        button,
        click_count,
        modifiers,
    )
    .await
    .map_err(|error| {
        if click_count == 2 {
            "Double click incomplete after input may have committed".to_string()
        } else {
            error
        }
    })?;
    // Compute before dispatch: a click may navigate or open a blocking dialog.
    result.position = (x + offset.0, y + offset.1);
    (result.x, result.y) = result.position;
    Ok(result)
}

pub async fn dblclick(
    client: &CdpClient,
    session_id: &str,
    ref_map: &RefMap,
    selector_or_ref: &str,
    iframe_sessions: &HashMap<String, String>,
) -> Result<ClickResult, String> {
    click(
        client,
        session_id,
        ref_map,
        selector_or_ref,
        "left",
        2,
        iframe_sessions,
    )
    .await
}

pub async fn hover(
    client: &CdpClient,
    session_id: &str,
    ref_map: &RefMap,
    selector_or_ref: &str,
    iframe_sessions: &HashMap<String, String>,
) -> Result<(f64, f64), String> {
    let (x, y, effective_session_id) = resolve_element_center(
        client,
        session_id,
        ref_map,
        selector_or_ref,
        iframe_sessions,
    )
    .await?;
    let offset =
        session_viewport_offset(client, session_id, &effective_session_id, iframe_sessions).await?;
    client
        .send_command_typed::<_, Value>(
            "Input.dispatchMouseEvent",
            &DispatchMouseEventParams {
                event_type: "mouseMoved".to_string(),
                x,
                y,
                button: None,
                buttons: None,
                click_count: None,
                delta_x: None,
                delta_y: None,
                modifiers: None,
            },
            Some(&effective_session_id),
        )
        .await?;
    Ok((x + offset.0, y + offset.1))
}

// One fill implementation: normal controls retain the upstream browser text
// insertion path. Only controls without a reliable text insertion path use the
// narrow native-value extension, after validating on a detached same-type input.
const PREPARE_FILL_JS: &str = r#"function(value) {
    const tag = this.localName;
    const native = tag === 'input' || tag === 'textarea';
    const textTypes = ['text', 'email', 'password', 'search', 'tel', 'url', 'number'];
    const valueTypes = ['date', 'datetime-local', 'month', 'time', 'week'];
    const usesValue = tag === 'input' && valueTypes.includes(this.type);
    const editable = tag === 'textarea' || (tag === 'input' && (textTypes.includes(this.type) || usesValue)) || (!native && this.isContentEditable);
    const blocked = () => !this.isConnected || this.matches(':disabled') || this.readOnly || this.getAttribute('aria-disabled') === 'true' || this.getAttribute('aria-readonly') === 'true';
    if (!editable || blocked() || this.getClientRects().length === 0) return { beforeInput: true };

    let valueSetter;
    if (usesValue) {
        const view = this.ownerDocument.defaultView;
        valueSetter = Object.getOwnPropertyDescriptor(view.HTMLInputElement.prototype, 'value').set;
        const probe = this.ownerDocument.createElement('input');
        probe.type = this.type;
        valueSetter.call(probe, value);
        if (probe.value !== value) return { beforeInput: true };
    }

    this.focus();
    const focused = () => {
        let active = this.ownerDocument.activeElement;
        while (active && active.shadowRoot?.activeElement) active = active.shadowRoot.activeElement;
        return active === this || this.getRootNode().activeElement === this;
    };
    if (blocked() || !focused()) return false;

    if (usesValue) {
        valueSetter.call(this, value);
        if (this.value !== value) return false;
        this.dispatchEvent(new Event('input', { bubbles: true, composed: true }));
        this.dispatchEvent(new Event('change', { bubbles: true }));
        return { nativeValue: true };
    }
    if (native) {
        this.select && this.select();
        if (blocked() || !focused()) return false;
        this.value = '';
        this.dispatchEvent(new Event('input', { bubbles: true }));
    } else {
        // Let Input.insertText replace the selection using browser editing
        // semantics. Never flatten a rich editor with textContent assignment.
        const range = this.ownerDocument.createRange();
        range.selectNodeContents(this);
        const selection = this.ownerDocument.getSelection();
        if (!selection) return false;
        selection.removeAllRanges();
        selection.addRange(range);
    }
    if (blocked() || !focused()) return false;
    return !native && value === '' ? { deleteSelection: true } : { insertText: true };
}"#;

pub async fn fill(
    client: &CdpClient,
    session_id: &str,
    ref_map: &RefMap,
    selector_or_ref: &str,
    value: &str,
    iframe_sessions: &HashMap<String, String>,
) -> Result<(), String> {
    let (object_id, effective_session_id) = resolve_element_object_id(
        client,
        session_id,
        ref_map,
        selector_or_ref,
        iframe_sessions,
    )
    .await?;

    let result: EvaluateResult = client
        .send_command_typed(
            "Runtime.callFunctionOn",
            &CallFunctionOnParams {
                function_declaration: PREPARE_FILL_JS.to_string(),
                object_id: Some(object_id),
                arguments: Some(vec![CallArgument {
                    value: Some(serde_json::json!(value)),
                    object_id: None,
                }]),
                return_by_value: Some(true),
                await_promise: Some(false),
            },
            Some(&effective_session_id),
        )
        .await?;
    if result.exception_details.is_some() {
        return Err("Fill did not complete after page effects may have committed".into());
    }
    let result = result.result.value.unwrap_or(Value::Null);
    if result["beforeInput"].as_bool() == Some(true) {
        return Err("e2e_not_actionable".into());
    }
    if result["nativeValue"].as_bool() == Some(true) {
        return Ok(());
    }
    if result["deleteSelection"].as_bool() == Some(true) {
        // A complete browser editing key sequence reliably deletes the selected
        // rich-editor contents even when empty insertText is a no-op.
        return press_key(client, session_id, "Backspace")
            .await
            .map_err(|_| "Fill incomplete after input may have committed".to_string());
    }
    if result["insertText"].as_bool() != Some(true) {
        return Err("Fill did not complete after page effects may have committed".into());
    }

    // Like upstream, keyboard insertion uses the top-level page session after
    // focusing the element in its frame. CDP cannot make focus and insertion
    // atomic; never retry on an uncertain response from this command.
    client
        .send_command_typed::<_, Value>(
            "Input.insertText",
            &InsertTextParams {
                text: value.to_string(),
            },
            Some(session_id),
        )
        .await
        .map_err(|_| "Fill incomplete after input may have committed".to_string())?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn type_text(
    client: &CdpClient,
    session_id: &str,
    ref_map: &RefMap,
    selector_or_ref: &str,
    text: &str,
    clear: bool,
    delay_ms: Option<u64>,
    iframe_sessions: &HashMap<String, String>,
) -> Result<(), String> {
    let (object_id, effective_session_id) = resolve_element_object_id(
        client,
        session_id,
        ref_map,
        selector_or_ref,
        iframe_sessions,
    )
    .await?;

    // Focus
    client
        .send_command_typed::<_, Value>(
            "Runtime.callFunctionOn",
            &CallFunctionOnParams {
                function_declaration: "function() { this.focus(); }".to_string(),
                object_id: Some(object_id.clone()),
                arguments: None,
                return_by_value: Some(true),
                await_promise: Some(false),
            },
            Some(&effective_session_id),
        )
        .await?;

    if clear {
        client
            .send_command_typed::<_, Value>(
                "Runtime.callFunctionOn",
                &CallFunctionOnParams {
                    function_declaration: r#"function() {
                        this.select && this.select();
                        this.value = '';
                        this.dispatchEvent(new Event('input', { bubbles: true }));
                    }"#
                    .to_string(),
                    object_id: Some(object_id),
                    arguments: None,
                    return_by_value: Some(true),
                    await_promise: Some(false),
                },
                Some(&effective_session_id),
            )
            .await?;
    }

    type_text_into_active_context(client, session_id, text, delay_ms).await
}

pub async fn type_text_into_active_context(
    client: &CdpClient,
    session_id: &str,
    text: &str,
    delay_ms: Option<u64>,
) -> Result<(), String> {
    type_text_into_context(client, session_id, text, delay_ms, false).await
}

/// Explicit keyboard typing emits real key events for printable US-layout keys.
/// Unmapped Unicode still uses the browser's trusted text insertion command.
pub async fn type_keys_into_active_context(
    client: &CdpClient,
    session_id: &str,
    text: &str,
    delay_ms: Option<u64>,
) -> Result<(), String> {
    type_text_into_context(client, session_id, text, delay_ms, true).await
}

fn typing_key_info(ch: char) -> (String, String, i32) {
    // Complete the shifted digit mapping for explicit physical-key dispatch.
    if let Some(digit) = ")!@#$%^&*(".chars().position(|candidate| candidate == ch) {
        return (ch.to_string(), format!("Digit{}", digit), 48 + digit as i32);
    }
    char_to_key_info(ch)
}

async fn type_text_into_context(
    client: &CdpClient,
    session_id: &str,
    text: &str,
    delay_ms: Option<u64>,
    keyboard_events: bool,
) -> Result<(), String> {
    let delay = delay_ms.unwrap_or(0);

    for ch in text.chars() {
        let (key, code, key_code) = typing_key_info(ch);
        if matches!(ch, '\n' | '\r' | '\t') || (keyboard_events && key_code != 0) {
            let text_str = key_text(&key);
            client
                .send_command_typed::<_, Value>(
                    "Input.dispatchKeyEvent",
                    &DispatchKeyEventParams {
                        event_type: "keyDown".to_string(),
                        key: Some(key.clone()),
                        code: Some(code.clone()),
                        text: text_str.clone(),
                        unmodified_text: text_str,
                        windows_virtual_key_code: Some(key_code),
                        native_virtual_key_code: Some(key_code),
                        modifiers: None,
                    },
                    Some(session_id),
                )
                .await?;

            client
                .send_command_typed::<_, Value>(
                    "Input.dispatchKeyEvent",
                    &DispatchKeyEventParams {
                        event_type: "keyUp".to_string(),
                        key: Some(key),
                        code: Some(code),
                        text: None,
                        unmodified_text: None,
                        windows_virtual_key_code: Some(key_code),
                        native_virtual_key_code: Some(key_code),
                        modifiers: None,
                    },
                    Some(session_id),
                )
                .await?;
        } else {
            // Element text typing retains upstream direct printable insertion.
            // Explicit keyboard typing uses this only for unmapped characters;
            // never synthesize a physical keyboard code for Unicode text.
            client
                .send_command_typed::<_, Value>(
                    "Input.insertText",
                    &InsertTextParams {
                        text: ch.to_string(),
                    },
                    Some(session_id),
                )
                .await?;
        }

        if delay > 0 {
            tokio::time::sleep(tokio::time::Duration::from_millis(delay)).await;
        }
    }

    Ok(())
}

pub async fn press_key(client: &CdpClient, session_id: &str, key: &str) -> Result<(), String> {
    press_key_with_modifiers(client, session_id, key, None).await
}

/// Dispatch a keyDown+keyUp sequence for `key` with an optional CDP modifier bitmask.
///
/// Modifier values follow the CDP `Input.dispatchKeyEvent` spec:
/// 1 = Alt, 2 = Control, 4 = Meta (Cmd), 8 = Shift.
///
/// Callers that need a platform-appropriate modifier (e.g. Cmd on macOS,
/// Ctrl elsewhere) must choose the value themselves -- see `cfg!(target_os)`.
pub async fn press_key_with_modifiers(
    client: &CdpClient,
    session_id: &str,
    key: &str,
    modifiers: Option<i32>,
) -> Result<(), String> {
    let (key_name, code, key_code) = named_key_info(key);

    // Suppress text insertion when Control (2) or Meta (4) modifiers are active,
    // since these are command chords (e.g. Ctrl+A = select-all), not text input.
    let has_command_modifier = modifiers.is_some_and(|m| m & (2 | 4) != 0);
    let text = if has_command_modifier {
        None
    } else {
        key_text(&key_name)
    };

    client
        .send_command_typed::<_, Value>(
            "Input.dispatchKeyEvent",
            &DispatchKeyEventParams {
                event_type: "keyDown".to_string(),
                key: Some(key_name.clone()),
                code: Some(code.clone()),
                text: text.clone(),
                unmodified_text: text.clone(),
                windows_virtual_key_code: Some(key_code),
                native_virtual_key_code: Some(key_code),
                modifiers,
            },
            Some(session_id),
        )
        .await?;

    client
        .send_command_typed::<_, Value>(
            "Input.dispatchKeyEvent",
            &DispatchKeyEventParams {
                event_type: "keyUp".to_string(),
                key: Some(key_name),
                code: Some(code),
                text: None,
                unmodified_text: None,
                windows_virtual_key_code: Some(key_code),
                native_virtual_key_code: Some(key_code),
                modifiers,
            },
            Some(session_id),
        )
        .await?;

    Ok(())
}

pub async fn scroll(
    client: &CdpClient,
    session_id: &str,
    ref_map: &RefMap,
    selector_or_ref: Option<&str>,
    delta_x: f64,
    delta_y: f64,
    iframe_sessions: &HashMap<String, String>,
) -> Result<(), String> {
    if let Some(sel) = selector_or_ref {
        let (object_id, effective_session_id) =
            resolve_element_object_id(client, session_id, ref_map, sel, iframe_sessions).await?;
        let js = "function(dx, dy) { this.scrollBy(dx, dy); }".to_string();
        client
            .send_command_typed::<_, Value>(
                "Runtime.callFunctionOn",
                &CallFunctionOnParams {
                    function_declaration: js,
                    object_id: Some(object_id),
                    arguments: Some(vec![
                        CallArgument {
                            value: Some(serde_json::json!(delta_x)),
                            object_id: None,
                        },
                        CallArgument {
                            value: Some(serde_json::json!(delta_y)),
                            object_id: None,
                        },
                    ]),
                    return_by_value: Some(true),
                    await_promise: Some(false),
                },
                Some(&effective_session_id),
            )
            .await?;
    } else {
        let js = format!("window.scrollBy({}, {})", delta_x, delta_y);
        client
            .send_command_typed::<_, Value>(
                "Runtime.evaluate",
                &EvaluateParams {
                    expression: js,
                    return_by_value: Some(true),
                    await_promise: Some(false),
                },
                Some(session_id),
            )
            .await?;
    }
    Ok(())
}

// Auto matching keeps upstream value/trimmed label/text matching and its
// whitespace-normalized fallback. Explicit match kinds are exact selectors;
// they must identify one enabled option before the shared mutation starts.
const SELECT_OPTION_JS: &str = r#"function(vals, mode) {
    const exact = mode !== 'auto';
    if (!this.isConnected || this.localName !== 'select' || this.matches(':disabled')) return { error: 'e2e_not_actionable', beforeInput: true };
    if (exact && !this.multiple && vals.length !== 1) return { error: 'e2e_unsupported_capability', beforeInput: true };
    const normalize = (value) => String(value ?? '').replace(/[\u200B\u200C\u200D\u2060\uFEFF]/g, '').replace(/\s+/g, ' ').trim();
    const options = Array.from(this.options);
    const wanted = new Set();
    for (const value of vals) {
        let matches = options.filter((option, index) =>
            mode === 'index' ? String(index) === value :
            mode === 'value' ? option.value === value :
            mode === 'label' ? option.label === value :
            value === option.value || value === option.label.trim() || value === option.textContent.trim()
        );
        if (!exact && matches.length === 0) {
            const normalizedValue = normalize(value);
            matches = options.filter((option) => normalize(option.label) === normalizedValue);
            if (matches.length > 1) return { error: 'Multiple options matched ' + JSON.stringify(value) + ' after whitespace normalization', beforeInput: true };
        }
        if (exact && matches.length !== 1) return { error: 'e2e_not_actionable', beforeInput: true };
        if (matches.length === 0) {
            const available = options.map(option => option.value + ' ("' + normalize(option.label) + '")').join(', ');
            return { error: 'No option matched ' + JSON.stringify(vals) + '. Available options: ' + available, beforeInput: true };
        }
        for (const option of matches) {
            if (exact && (option.disabled || option.parentElement?.matches('optgroup:disabled'))) return { error: 'e2e_not_actionable', beforeInput: true };
            wanted.add(option);
        }
    }
    if (wanted.size === 0) return { error: 'No option matched ' + JSON.stringify(vals), beforeInput: true };
    for (const option of options) option.selected = wanted.has(option);
    if (exact) this.dispatchEvent(new Event('input', { bubbles: true }));
    this.dispatchEvent(new Event('change', { bubbles: true }));
    return { matched: wanted.size };
}"#;

pub async fn select_option(
    client: &CdpClient,
    session_id: &str,
    ref_map: &RefMap,
    selector_or_ref: &str,
    values: &[String],
    mode: &str,
    iframe_sessions: &HashMap<String, String>,
) -> Result<(), String> {
    let (object_id, effective_session_id) = resolve_element_object_id(
        client,
        session_id,
        ref_map,
        selector_or_ref,
        iframe_sessions,
    )
    .await?;

    if !["auto", "value", "label", "index"].contains(&mode) {
        return Err("e2e_unsupported_capability".into());
    }
    let js = SELECT_OPTION_JS.to_string();

    let result = client
        .send_command_typed::<_, Value>(
            "Runtime.callFunctionOn",
            &CallFunctionOnParams {
                function_declaration: js,
                object_id: Some(object_id),
                arguments: Some(vec![
                    CallArgument {
                        value: Some(serde_json::json!(values)),
                        object_id: None,
                    },
                    CallArgument {
                        value: Some(serde_json::json!(mode)),
                        object_id: None,
                    },
                ]),
                return_by_value: Some(true),
                await_promise: Some(false),
            },
            Some(&effective_session_id),
        )
        .await?;

    if result.get("exceptionDetails").is_some() {
        return Err("Select option did not complete".into());
    }
    if let Some(error) = result
        .get("result")
        .and_then(|r| r.get("value"))
        .and_then(|v| v.get("error"))
        .and_then(|e| e.as_str())
    {
        if result["result"]["value"]["beforeInput"].as_bool() == Some(true) {
            return Err(error.to_string());
        }
        return Err("Select did not complete".into());
    }

    if result["result"]["value"]["matched"]
        .as_u64()
        .is_none_or(|count| count == 0)
    {
        return Err("Select did not complete after input may have committed".into());
    }
    Ok(())
}

pub async fn check(
    client: &CdpClient,
    session_id: &str,
    ref_map: &RefMap,
    selector_or_ref: &str,
    iframe_sessions: &HashMap<String, String>,
) -> Result<Option<(f64, f64)>, String> {
    let mut position = None;
    let is_checked = read_checkable_state(
        client,
        session_id,
        ref_map,
        selector_or_ref,
        false,
        iframe_sessions,
    )
    .await?;
    if !is_checked {
        let result = click(
            client,
            session_id,
            ref_map,
            selector_or_ref,
            "left",
            1,
            iframe_sessions,
        )
        .await?;
        position = Some(result.position);

        wait_for_checkbox_after_input(
            client,
            session_id,
            ref_map,
            selector_or_ref,
            true,
            iframe_sessions,
        )
        .await?;
    }
    Ok(position)
}

pub async fn uncheck(
    client: &CdpClient,
    session_id: &str,
    ref_map: &RefMap,
    selector_or_ref: &str,
    iframe_sessions: &HashMap<String, String>,
) -> Result<Option<(f64, f64)>, String> {
    let mut position = None;
    let is_checked = read_checkable_state(
        client,
        session_id,
        ref_map,
        selector_or_ref,
        true,
        iframe_sessions,
    )
    .await?;
    if is_checked {
        let result = click(
            client,
            session_id,
            ref_map,
            selector_or_ref,
            "left",
            1,
            iframe_sessions,
        )
        .await?;
        position = Some(result.position);

        wait_for_checkbox_after_input(
            client,
            session_id,
            ref_map,
            selector_or_ref,
            false,
            iframe_sessions,
        )
        .await?;
    }
    Ok(position)
}

/// Reject unrelated controls and radio unchecking before dispatching any input.
async fn read_checkable_state(
    client: &CdpClient,
    session_id: &str,
    ref_map: &RefMap,
    selector_or_ref: &str,
    uncheck: bool,
    iframe_sessions: &HashMap<String, String>,
) -> Result<bool, String> {
    let (object_id, effective_session_id) = resolve_element_object_id(
        client,
        session_id,
        ref_map,
        selector_or_ref,
        iframe_sessions,
    )
    .await?;
    let result: EvaluateResult=client.send_command_typed("Runtime.callFunctionOn", &CallFunctionOnParams {
        function_declaration:r#"function(uncheck){
            let el=this;if(el.localName==='label')el=el.control;
            if(!el||!el.isConnected||el.matches(':disabled')||el.getAttribute('aria-disabled')==='true')return null;
            const native=el.localName==='input'&&['checkbox','radio'].includes(el.type);
            const role=el.getAttribute('role');const radio=native?el.type==='radio':['radio','menuitemradio'].includes(role);
            if(uncheck&&radio)return 'unsupported';
            if(native)return el.checked;
            if(!['checkbox','radio','switch','menuitemcheckbox','menuitemradio'].includes(role))return null;
            const checked=el.getAttribute('aria-checked');return checked==='true'?true:checked==='false'?false:null;
        }"#.to_string(),object_id:Some(object_id),arguments:Some(vec![CallArgument{value:Some(serde_json::json!(uncheck)),object_id:None}]),return_by_value:Some(true),await_promise:Some(false),
    },Some(&effective_session_id)).await?;
    if result.exception_details.is_some() {
        return Err("Checkable target is unavailable".into());
    }
    if result.result.value.as_ref().and_then(Value::as_str) == Some("unsupported") {
        return Err("e2e_unsupported_capability".into());
    }
    result
        .result
        .value
        .as_ref()
        .and_then(Value::as_bool)
        .ok_or_else(|| "e2e_not_actionable".to_string())
}

/// After dispatch, only observe. A second click can undo a delayed controlled
/// update. Any read failure after input is uncertain, never a retryable stale.
async fn wait_for_checkbox_after_input(
    client: &CdpClient,
    session_id: &str,
    ref_map: &RefMap,
    selector_or_ref: &str,
    wanted: bool,
    iframe_sessions: &HashMap<String, String>,
) -> Result<(), String> {
    let started = std::time::Instant::now();
    loop {
        let checked = super::element::is_element_checked(
            client,
            session_id,
            ref_map,
            selector_or_ref,
            iframe_sessions,
        )
        .await
        .map_err(|_| "Checkbox state unavailable after input may have committed".to_string())?;
        if checked == wanted {
            return Ok(());
        }
        if started.elapsed() >= std::time::Duration::from_millis(1500) {
            return Err("Checkbox state did not settle after input may have committed".to_string());
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
}

pub async fn focus(
    client: &CdpClient,
    session_id: &str,
    ref_map: &RefMap,
    selector_or_ref: &str,
    iframe_sessions: &HashMap<String, String>,
) -> Result<(), String> {
    let (object_id, effective_session_id) = resolve_element_object_id(
        client,
        session_id,
        ref_map,
        selector_or_ref,
        iframe_sessions,
    )
    .await?;

    client
        .send_command_typed::<_, Value>(
            "Runtime.callFunctionOn",
            &CallFunctionOnParams {
                function_declaration: "function() { this.focus(); }".to_string(),
                object_id: Some(object_id),
                arguments: None,
                return_by_value: Some(true),
                await_promise: Some(false),
            },
            Some(&effective_session_id),
        )
        .await?;

    Ok(())
}

pub async fn clear(
    client: &CdpClient,
    session_id: &str,
    ref_map: &RefMap,
    selector_or_ref: &str,
    iframe_sessions: &HashMap<String, String>,
) -> Result<(), String> {
    fill(
        client,
        session_id,
        ref_map,
        selector_or_ref,
        "",
        iframe_sessions,
    )
    .await
}

pub async fn select_all(
    client: &CdpClient,
    session_id: &str,
    ref_map: &RefMap,
    selector_or_ref: &str,
    iframe_sessions: &HashMap<String, String>,
) -> Result<(), String> {
    let (object_id, effective_session_id) = resolve_element_object_id(
        client,
        session_id,
        ref_map,
        selector_or_ref,
        iframe_sessions,
    )
    .await?;

    client
        .send_command_typed::<_, Value>(
            "Runtime.callFunctionOn",
            &CallFunctionOnParams {
                function_declaration: r#"function() {
                    this.focus();
                    if (typeof this.select === 'function') {
                        this.select();
                    } else {
                        const range = document.createRange();
                        range.selectNodeContents(this);
                        const sel = window.getSelection();
                        sel.removeAllRanges();
                        sel.addRange(range);
                    }
                }"#
                .to_string(),
                object_id: Some(object_id),
                arguments: None,
                return_by_value: Some(true),
                await_promise: Some(false),
            },
            Some(&effective_session_id),
        )
        .await?;

    Ok(())
}

pub async fn scroll_into_view(
    client: &CdpClient,
    session_id: &str,
    ref_map: &RefMap,
    selector_or_ref: &str,
    iframe_sessions: &HashMap<String, String>,
) -> Result<(), String> {
    let (object_id, effective_session_id) = resolve_element_object_id(
        client,
        session_id,
        ref_map,
        selector_or_ref,
        iframe_sessions,
    )
    .await?;

    client
        .send_command_typed::<_, Value>(
            "Runtime.callFunctionOn",
            &CallFunctionOnParams {
                function_declaration:
                    "function() { this.scrollIntoView({ block: 'center', inline: 'center' }); }"
                        .to_string(),
                object_id: Some(object_id),
                arguments: None,
                return_by_value: Some(true),
                await_promise: Some(false),
            },
            Some(&effective_session_id),
        )
        .await?;

    Ok(())
}

pub async fn dispatch_event(
    client: &CdpClient,
    session_id: &str,
    ref_map: &RefMap,
    selector_or_ref: &str,
    event_type: &str,
    event_init: Option<&Value>,
    iframe_sessions: &HashMap<String, String>,
) -> Result<(), String> {
    let (object_id, effective_session_id) = resolve_element_object_id(
        client,
        session_id,
        ref_map,
        selector_or_ref,
        iframe_sessions,
    )
    .await?;

    let init_json = event_init
        .map(|v| serde_json::to_string(v).unwrap_or("{}".to_string()))
        .unwrap_or_else(|| "{ bubbles: true }".to_string());

    let js = format!(
        "function() {{ this.dispatchEvent(new Event({}, {})); }}",
        serde_json::to_string(event_type).unwrap_or_default(),
        init_json
    );

    client
        .send_command_typed::<_, Value>(
            "Runtime.callFunctionOn",
            &CallFunctionOnParams {
                function_declaration: js,
                object_id: Some(object_id),
                arguments: None,
                return_by_value: Some(true),
                await_promise: Some(false),
            },
            Some(&effective_session_id),
        )
        .await?;

    Ok(())
}

pub async fn highlight(
    client: &CdpClient,
    session_id: &str,
    ref_map: &RefMap,
    selector_or_ref: &str,
    iframe_sessions: &HashMap<String, String>,
) -> Result<(), String> {
    let (object_id, effective_session_id) = resolve_element_object_id(
        client,
        session_id,
        ref_map,
        selector_or_ref,
        iframe_sessions,
    )
    .await?;

    client
        .send_command_typed::<_, Value>(
            "Runtime.callFunctionOn",
            &CallFunctionOnParams {
                function_declaration: r#"function() {
                    this.style.outline = '2px solid red';
                    this.style.outlineOffset = '2px';
                    const el = this;
                    setTimeout(() => {
                        el.style.outline = '';
                        el.style.outlineOffset = '';
                    }, 3000);
                }"#
                .to_string(),
                object_id: Some(object_id),
                arguments: None,
                return_by_value: Some(true),
                await_promise: Some(false),
            },
            Some(&effective_session_id),
        )
        .await?;

    Ok(())
}

pub async fn tap_touch(
    client: &CdpClient,
    session_id: &str,
    ref_map: &RefMap,
    selector_or_ref: &str,
    iframe_sessions: &HashMap<String, String>,
) -> Result<(), String> {
    let (x, y, effective_session_id) = resolve_element_center(
        client,
        session_id,
        ref_map,
        selector_or_ref,
        iframe_sessions,
    )
    .await?;

    client
        .send_command(
            "Input.dispatchTouchEvent",
            Some(serde_json::json!({
                "type": "touchStart",
                "touchPoints": [{ "x": x, "y": y }],
            })),
            Some(&effective_session_id),
        )
        .await?;

    client
        .send_command(
            "Input.dispatchTouchEvent",
            Some(serde_json::json!({
                "type": "touchEnd",
                "touchPoints": [],
            })),
            Some(&effective_session_id),
        )
        .await?;

    Ok(())
}

/// Dispatches one mouse event and waits for the browser to ack it, but
/// returns Ok(true) if a JavaScript dialog opens first. A synchronous dialog
/// (confirm/prompt/alert in the event handler) blocks the renderer's main
/// thread, so the input ack cannot arrive until the dialog is resolved;
/// without this the command hangs until the client read timeout and the agent
/// never sees the pending-dialog warning.
async fn dispatch_mouse_or_dialog(
    client: &CdpClient,
    session_id: &str,
    accept_sessions: &[&str],
    params: &DispatchMouseEventParams,
) -> Result<bool, String> {
    use tokio::sync::broadcast::error::RecvError;

    // Subscribe before sending so the dialog event cannot slip past us.
    let mut events = client.subscribe();
    let send =
        client.send_command_typed::<_, Value>("Input.dispatchMouseEvent", params, Some(session_id));
    tokio::pin!(send);
    loop {
        tokio::select! {
            res = &mut send => {
                res?;
                return Ok(false);
            }
            event = events.recv() => {
                match event {
                    Ok(e) if e.method == "Page.javascriptDialogOpening" => {
                        // Only a dialog on this click's frame/page session
                        // aborts it; a background-tab dialog must not. A
                        // session-less event has no flat session and is
                        // treated as the top-level page (i.e. ours).
                        let ours = match e.session_id.as_deref() {
                            Some(sid) => accept_sessions.contains(&sid),
                            None => true,
                        };
                        if ours {
                            return Ok(true);
                        }
                        continue;
                    }
                    Ok(_) => continue,
                    Err(RecvError::Lagged(_)) => continue,
                    Err(RecvError::Closed) => {
                        (&mut send).await?;
                        return Ok(false);
                    }
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_click(
    client: &CdpClient,
    session_id: &str,
    accept_sessions: &[&str],
    x: f64,
    y: f64,
    button: &str,
    click_count: i32,
    modifiers: i32,
) -> Result<ClickResult, String> {
    // Move
    if dispatch_mouse_or_dialog(
        client,
        session_id,
        accept_sessions,
        &DispatchMouseEventParams {
            event_type: "mouseMoved".to_string(),
            x,
            y,
            button: None,
            buttons: None,
            click_count: None,
            delta_x: None,
            delta_y: None,
            modifiers: Some(modifiers),
        },
    )
    .await?
    {
        // No button was pressed yet, nothing to release.
        return Ok(ClickResult {
            position: (x, y),
            dialog_opened: true,
            pending_release: None,
            x,
            y,
            button_pressed: false,
        });
    }

    let button_value = match button {
        "right" => 2,
        "middle" => 4,
        _ => 1,
    };

    // Press
    if dispatch_mouse_or_dialog(
        client,
        session_id,
        accept_sessions,
        &DispatchMouseEventParams {
            event_type: "mousePressed".to_string(),
            x,
            y,
            button: Some(button.to_string()),
            buttons: Some(button_value),
            click_count: Some(click_count),
            delta_x: None,
            delta_y: None,
            modifiers: Some(modifiers),
        },
    )
    .await?
    {
        // Dialog opened from the mousedown handler: the button is held and the
        // release will never arrive on its own. Hand the caller what it needs
        // to release once the dialog is resolved.
        return Ok(ClickResult {
            position: (x, y),
            dialog_opened: true,
            pending_release: Some(PendingRelease {
                session_id: session_id.to_string(),
                x,
                y,
                button: button.to_string(),
                modifiers,
            }),
            x,
            y,
            button_pressed: true,
        });
    }

    // Release. A dialog here fired from the click/mouseup handler, which runs
    // after the button is already up, so there is nothing left to release.
    let dialog_opened = dispatch_mouse_or_dialog(
        client,
        session_id,
        accept_sessions,
        &DispatchMouseEventParams {
            event_type: "mouseReleased".to_string(),
            x,
            y,
            button: Some(button.to_string()),
            buttons: Some(0),
            click_count: Some(click_count),
            delta_x: None,
            delta_y: None,
            modifiers: Some(modifiers),
        },
    )
    .await?;
    Ok(ClickResult {
        position: (x, y),
        dialog_opened,
        pending_release: None,
        x,
        y,
        button_pressed: true,
    })
}

/// Best-effort mouseReleased to clear a button left logically down when a
/// dialog opened mid-click. Called after the dialog is resolved.
pub async fn dispatch_pending_release(
    client: &CdpClient,
    release: &PendingRelease,
) -> Result<(), String> {
    client
        .send_command_typed::<_, Value>(
            "Input.dispatchMouseEvent",
            &DispatchMouseEventParams {
                event_type: "mouseReleased".to_string(),
                x: release.x,
                y: release.y,
                button: Some(release.button.clone()),
                buttons: Some(0),
                click_count: Some(1),
                delta_x: None,
                delta_y: None,
                modifiers: Some(release.modifiers),
            },
            Some(&release.session_id),
        )
        .await?;
    Ok(())
}

fn char_to_key_info(ch: char) -> (String, String, i32) {
    match ch {
        '\n' | '\r' => ("Enter".to_string(), "Enter".to_string(), 13),
        '\t' => ("Tab".to_string(), "Tab".to_string(), 9),
        ' ' => (" ".to_string(), "Space".to_string(), 32),
        _ => {
            let key = ch.to_string();
            if ch.is_ascii_alphabetic() {
                // For letters the Windows VK code equals the uppercase ASCII value.
                let upper = ch.to_ascii_uppercase();
                let code = format!("Key{}", upper);
                let key_code = upper as i32;
                (key, code, key_code)
            } else if ch.is_ascii_digit() {
                let code = format!("Digit{}", ch);
                let key_code = ch as i32;
                (key, code, key_code)
            } else {
                let (code, key_code) = punctuation_key_info(ch);
                (key, code.to_string(), key_code)
            }
        }
    }
}

/// Return the DOM `KeyboardEvent.code` value and Windows virtual-key code for
/// a punctuation / symbol character assuming a US keyboard layout.
///
/// The Windows virtual-key codes (VK_OEM_*) differ from ASCII values for
/// punctuation.  Using the raw ASCII code would misidentify characters – e.g.
/// '.' (ASCII 46) collides with VK_DELETE (0x2E = 46), causing the period to
/// be swallowed.
fn punctuation_key_info(ch: char) -> (&'static str, i32) {
    match ch {
        // VK_OEM_1 (0xBA = 186) — ";:" key on US layout
        ';' | ':' => ("Semicolon", 186),
        // VK_OEM_PLUS (0xBB = 187) — "=+" key
        '=' | '+' => ("Equal", 187),
        // VK_OEM_COMMA (0xBC = 188) — ",<" key
        ',' | '<' => ("Comma", 188),
        // VK_OEM_MINUS (0xBD = 189) — "-_" key
        '-' | '_' => ("Minus", 189),
        // VK_OEM_PERIOD (0xBE = 190) — ".>" key
        '.' | '>' => ("Period", 190),
        // VK_OEM_2 (0xBF = 191) — "/?" key
        '/' | '?' => ("Slash", 191),
        // VK_OEM_3 (0xC0 = 192) — "`~" key
        '`' | '~' => ("Backquote", 192),
        // VK_OEM_4 (0xDB = 219) — "[{" key
        '[' | '{' => ("BracketLeft", 219),
        // VK_OEM_5 (0xDC = 220) — "\\|" key
        '\\' | '|' => ("Backslash", 220),
        // VK_OEM_6 (0xDD = 221) — "]}" key
        ']' | '}' => ("BracketRight", 221),
        // VK_OEM_7 (0xDE = 222) — "'\""" key
        '\'' | '"' => ("Quote", 222),
        _ => ("", 0),
    }
}

/// Return the `text` value that CDP `Input.dispatchKeyEvent` needs on the
/// `keyDown` event so that Chrome performs the default action for the key.
/// For example Enter needs `"\r"` to actually submit a form, and Tab needs
/// `"\t"` to move focus.  Non-printable / navigation keys return `None`.
fn key_text(key_name: &str) -> Option<String> {
    match key_name {
        "Enter" => Some("\r".to_string()),
        "Tab" => Some("\t".to_string()),
        " " => Some(" ".to_string()),
        _ => {
            // Single printable characters carry themselves as text.
            if key_name.len() == 1 {
                Some(key_name.to_string())
            } else {
                None
            }
        }
    }
}

fn named_key_info(key: &str) -> (String, String, i32) {
    match key.to_lowercase().as_str() {
        "enter" | "return" => ("Enter".to_string(), "Enter".to_string(), 13),
        "tab" => ("Tab".to_string(), "Tab".to_string(), 9),
        "escape" | "esc" => ("Escape".to_string(), "Escape".to_string(), 27),
        "backspace" => ("Backspace".to_string(), "Backspace".to_string(), 8),
        "delete" => ("Delete".to_string(), "Delete".to_string(), 46),
        "arrowup" | "up" => ("ArrowUp".to_string(), "ArrowUp".to_string(), 38),
        "arrowdown" | "down" => ("ArrowDown".to_string(), "ArrowDown".to_string(), 40),
        "arrowleft" | "left" => ("ArrowLeft".to_string(), "ArrowLeft".to_string(), 37),
        "arrowright" | "right" => ("ArrowRight".to_string(), "ArrowRight".to_string(), 39),
        "home" => ("Home".to_string(), "Home".to_string(), 36),
        "end" => ("End".to_string(), "End".to_string(), 35),
        "pageup" => ("PageUp".to_string(), "PageUp".to_string(), 33),
        "pagedown" => ("PageDown".to_string(), "PageDown".to_string(), 34),
        "space" | " " => (" ".to_string(), "Space".to_string(), 32),
        _ => {
            if key.len() == 1 {
                let ch = key.chars().next().unwrap();
                char_to_key_info(ch)
            } else {
                (key.to_string(), key.to_string(), 0)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn fill_uses_one_browser_insertion_and_never_retries_uncertain_input() {
        use futures_util::{SinkExt, StreamExt};
        use serde_json::json;
        use tokio_tungstenite::tungstenite::Message;
        for (exact, fail_insert, native_value) in [
            (false, false, false),
            (true, false, false),
            (true, true, false),
            (true, false, true),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("ws://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                let mut ws = tokio_tungstenite::accept_async(socket).await.unwrap();
                let mut insertions = 0;
                while let Ok(Some(Ok(Message::Text(text)))) =
                    tokio::time::timeout(std::time::Duration::from_millis(100), ws.next()).await
                {
                    let request: Value = serde_json::from_str(&text).unwrap();
                    let mut response = json!({"id":request["id"],"result":{}});
                    match request["method"].as_str().unwrap() {
                        "DOM.resolveNode" => {
                            response["result"] =
                                json!({"object":{"type":"object","objectId":"field"}})
                        }
                        "Runtime.callFunctionOn" => {
                            let source = request["params"]["functionDeclaration"].as_str().unwrap();
                            if source == PREPARE_FILL_JS {
                                response["result"] = json!({"result":{"type":"object","value":{"nativeValue":native_value,"insertText":!native_value}}});
                            } else {
                                assert!(exact);
                                assert!(source.contains("return this.isConnected"));
                                response["result"] =
                                    json!({"result":{"type":"boolean","value":true}});
                            }
                        }
                        "Input.insertText" => {
                            insertions += 1;
                            assert_eq!(request["sessionId"], "page");
                            assert_eq!(request["params"]["text"], "replacement");
                            if fail_insert {
                                response["error"] =
                                    json!({"code":-32000,"message":"Response lost"});
                            }
                        }
                        method => panic!("Unexpected fill command: {method}"),
                    }
                    ws.send(Message::Text(response.to_string())).await.unwrap();
                }
                insertions
            });
            let client = CdpClient::connect(&url).await.unwrap();
            let mut refs = RefMap::new();
            if exact {
                refs.add_exact_backend_node("e1".into(), 42);
            } else {
                refs.add("e1".into(), Some(42), "textbox", "Name", None);
            }
            let result = fill(
                &client,
                "page",
                &refs,
                "@e1",
                "replacement",
                &HashMap::new(),
            )
            .await;
            if fail_insert {
                let error = result.unwrap_err();
                assert!(error.contains("after input may have committed"));
                assert!(!error.starts_with(super::super::element::STALE_REF_PREFIX));
            } else {
                assert!(result.is_ok());
            }
            assert_eq!(server.await.unwrap(), usize::from(!native_value));
        }
    }

    #[tokio::test]
    async fn exact_click_preserves_modifiers_on_move_press_and_release() {
        use futures_util::{SinkExt, StreamExt};
        use serde_json::json;
        use tokio_tungstenite::tungstenite::Message;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(socket).await.unwrap();
            for event in ["mouseMoved", "mousePressed", "mouseReleased"] {
                let Some(Ok(Message::Text(text))) = ws.next().await else {
                    panic!("Missing pointer event")
                };
                let request: Value = serde_json::from_str(&text).unwrap();
                assert_eq!(request["method"], "Input.dispatchMouseEvent");
                assert_eq!(request["params"]["modifiers"], 10);
                assert_eq!(request["params"]["type"], event);
                ws.send(Message::Text(
                    json!({"id":request["id"],"sessionId":request["sessionId"],"result":{}})
                        .to_string(),
                ))
                .await
                .unwrap();
            }
        });
        let client = CdpClient::connect(&url).await.unwrap();
        dispatch_click(&client, "page", &["page"], 3.5, 7.25, "left", 1, 10)
            .await
            .unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn noncheckable_targets_never_dispatch_a_click() {
        use futures_util::{SinkExt, StreamExt};
        use serde_json::json;
        use tokio_tungstenite::tungstenite::Message;
        for remove_check in [false, true] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("ws://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                let mut ws = tokio_tungstenite::accept_async(socket).await.unwrap();
                while let Ok(Some(Ok(Message::Text(text)))) =
                    tokio::time::timeout(std::time::Duration::from_millis(100), ws.next()).await
                {
                    let request: Value = serde_json::from_str(&text).unwrap();
                    let response = match request["method"].as_str().unwrap() {
                        "DOM.resolveNode" => json!({"object":{"type":"object","objectId":"node"}}),
                        "Runtime.callFunctionOn" => {
                            let source = request["params"]["functionDeclaration"].as_str().unwrap();
                            if source.contains("return this.isConnected") {
                                json!({"result":{"type":"boolean","value":true}})
                            } else {
                                json!({"result":{"type":"object","subtype":"null","value":null}})
                            }
                        }
                        method => panic!("Uncheckable target dispatched {method}"),
                    };
                    ws.send(Message::Text(json!({"id":request["id"],"sessionId":request["sessionId"],"result":response}).to_string())).await.unwrap();
                }
            });
            let client = CdpClient::connect(&url).await.unwrap();
            let mut refs = RefMap::new();
            refs.add_with_frame(
                "e1".into(),
                Some(42),
                "button",
                "Business action",
                None,
                None,
            );
            let result = if remove_check {
                uncheck(&client, "page", &refs, "@e1", &HashMap::new()).await
            } else {
                check(&client, "page", &refs, "@e1", &HashMap::new()).await
            };
            assert!(result.is_err());
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn checkbox_delayed_state_and_replacement_never_dispatch_again() {
        use futures_util::{SinkExt, StreamExt};
        use serde_json::json;
        use tokio_tungstenite::tungstenite::Message;
        for detached in [false, true] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("ws://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                let mut ws = tokio_tungstenite::accept_async(socket).await.unwrap();
                let mut reads = 0;
                while let Ok(Some(Ok(Message::Text(text)))) =
                    tokio::time::timeout(std::time::Duration::from_millis(100), ws.next()).await
                {
                    let request: Value = serde_json::from_str(&text).unwrap();
                    let result = match request["method"].as_str().unwrap() {
                        "DOM.resolveNode" => {
                            json!({"object":{"type":"object","objectId":"checked-node"}})
                        }
                        "Runtime.callFunctionOn" => {
                            let function =
                                request["params"]["functionDeclaration"].as_str().unwrap();
                            assert!(
                                !function.contains(".click("),
                                "A delayed state must never trigger another click"
                            );
                            if function.contains("isConnected") {
                                json!({"result":{"type":"boolean","value":!detached}})
                            } else {
                                reads += 1;
                                json!({"result":{"type":"boolean","value":reads >= 3}})
                            }
                        }
                        "Runtime.releaseObject" => {
                            assert_eq!(request["params"]["objectId"], "checked-node");
                            json!({})
                        }
                        other => panic!("Post-click verification must be read-only, got {other}"),
                    };
                    let response = json!({"id":request["id"],"sessionId":request["sessionId"],"result":result});
                    ws.send(Message::Text(response.to_string())).await.unwrap();
                }
                reads
            });
            let client = CdpClient::connect(&url).await.unwrap();
            let mut map = RefMap::new();
            map.add_exact_with_frame("e1".into(), 42, "checkbox", "Agree", None, None);
            let result =
                wait_for_checkbox_after_input(&client, "page", &map, "@e1", true, &HashMap::new())
                    .await;
            if detached {
                let error = result.unwrap_err();
                assert!(!error.starts_with(super::super::element::STALE_REF_PREFIX));
                assert!(error.contains("after input may have committed"));
            } else {
                assert!(result.is_ok());
            }
            let reads = server.await.unwrap();
            assert_eq!(reads, if detached { 0 } else { 3 });
        }
    }

    use super::*;

    #[tokio::test]
    async fn text_and_keyboard_operations_share_dispatch_and_unicode_insertion() {
        use futures_util::{SinkExt, StreamExt};
        use serde_json::json;
        use tokio_tungstenite::tungstenite::Message;
        for keyboard_events in [false, true] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("ws://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                let mut ws = tokio_tungstenite::accept_async(socket).await.unwrap();
                let mut commands = Vec::new();
                while let Some(Ok(message)) = ws.next().await {
                    match message {
                        Message::Text(text) => {
                            let command: Value = serde_json::from_str(&text).unwrap();
                            assert_eq!(command["sessionId"], "owned-page");
                            ws.send(Message::Text(
                                json!({"id":command["id"],"result":{}}).to_string(),
                            ))
                            .await
                            .unwrap();
                            commands.push(command);
                        }
                        Message::Close(_) => break,
                        _ => {}
                    }
                }
                commands
            });
            let client = CdpClient::connect(&url).await.unwrap();
            let text = "--sessionA@! \n\t汉🙂";
            if keyboard_events {
                type_keys_into_active_context(&client, "owned-page", text, None)
                    .await
                    .unwrap();
            } else {
                type_text_into_active_context(&client, "owned-page", text, None)
                    .await
                    .unwrap();
            }
            client.close().await;
            let commands = tokio::time::timeout(std::time::Duration::from_secs(3), server)
                .await
                .unwrap()
                .unwrap();
            let mut commands = commands.iter();
            for ch in text.chars() {
                let (key, code, key_code) = typing_key_info(ch);
                if matches!(ch, '\n' | '\r' | '\t') || (keyboard_events && key_code != 0) {
                    let down = commands.next().unwrap();
                    let up = commands.next().unwrap();
                    for (command, event) in [(down, "keyDown"), (up, "keyUp")] {
                        assert_eq!(command["method"], "Input.dispatchKeyEvent");
                        assert_eq!(command["params"]["type"], event);
                        assert_eq!(command["params"]["key"], key);
                        assert_eq!(command["params"]["code"], code);
                        assert_eq!(command["params"]["windowsVirtualKeyCode"], key_code);
                    }
                    assert_eq!(down["params"]["text"], json!(key_text(&key)));
                    assert!(up["params"]["text"].is_null());
                } else {
                    let command = commands.next().unwrap();
                    assert_eq!(command["method"], "Input.insertText");
                    assert_eq!(command["params"]["text"], ch.to_string());
                }
            }
            assert!(commands.next().is_none());
        }
        for (ch, code, key_code) in [
            ('!', "Digit1", 49),
            ('@', "Digit2", 50),
            (')', "Digit0", 48),
        ] {
            assert_eq!(
                typing_key_info(ch),
                (ch.to_string(), code.to_string(), key_code)
            );
        }
    }

    #[tokio::test]
    async fn keyboard_type_stops_after_a_partial_key_pair_without_retry() {
        use futures_util::{SinkExt, StreamExt};
        use serde_json::json;
        use tokio_tungstenite::tungstenite::Message;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(socket).await.unwrap();
            let mut count = 0;
            while let Some(Ok(message)) = ws.next().await {
                match message {
                    Message::Text(text) => {
                        count += 1;
                        assert!(
                            count <= 2,
                            "Typing retried or continued after an uncertain key pair"
                        );
                        let command: Value = serde_json::from_str(&text).unwrap();
                        assert_eq!(command["method"], "Input.dispatchKeyEvent");
                        assert_eq!(command["params"]["key"], "a");
                        let response = if count == 1 {
                            json!({"id":command["id"],"result":{}})
                        } else {
                            json!({"id":command["id"],"error":{"code":-32000,"message":"synthetic keyup failure"}})
                        };
                        ws.send(Message::Text(response.to_string())).await.unwrap();
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
            count
        });
        let client = CdpClient::connect(&url).await.unwrap();
        let error = type_keys_into_active_context(&client, "owned-page", "abc", None)
            .await
            .unwrap_err();
        assert!(!error.starts_with("e2e_"));
        client.close().await;
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(3), server)
                .await
                .unwrap()
                .unwrap(),
            2
        );
    }

    /// Verify that `char_to_key_info` returns the correct (key, code,
    /// windowsVirtualKeyCode) triple for every character in Playwright's
    /// USKeyboardLayout.  The expected values below are taken verbatim from
    /// playwright-core/lib/server/usKeyboardLayout.js so that any drift from
    /// Playwright's behaviour is caught immediately.
    #[test]
    fn test_char_to_key_info_matches_playwright_layout() {
        // (character, expected_code, expected_vk_code)
        let cases: &[(char, &str, i32)] = &[
            // Letters – VK code must equal the uppercase ASCII value.
            ('a', "KeyA", 65),
            ('z', "KeyZ", 90),
            ('A', "KeyA", 65),
            // Digits
            ('0', "Digit0", 48),
            ('9', "Digit9", 57),
            // Punctuation – these are the values from Playwright's layout.
            // The bug that prompted this test sent '.' as VK 46 (= VK_DELETE).
            ('.', "Period", 190),
            (',', "Comma", 188),
            ('/', "Slash", 191),
            (';', "Semicolon", 186),
            ('\'', "Quote", 222),
            ('[', "BracketLeft", 219),
            (']', "BracketRight", 221),
            ('\\', "Backslash", 220),
            ('`', "Backquote", 192),
            ('-', "Minus", 189),
            ('=', "Equal", 187),
            // Shifted variants produced by the same physical keys.
            ('>', "Period", 190),
            ('<', "Comma", 188),
            ('?', "Slash", 191),
            (':', "Semicolon", 186),
            ('"', "Quote", 222),
            ('{', "BracketLeft", 219),
            ('}', "BracketRight", 221),
            ('|', "Backslash", 220),
            ('~', "Backquote", 192),
            ('_', "Minus", 189),
            ('+', "Equal", 187),
            // Whitespace / control
            (' ', "Space", 32),
            ('\n', "Enter", 13),
            ('\t', "Tab", 9),
        ];

        for &(ch, expected_code, expected_vk) in cases {
            let (key, code, vk) = char_to_key_info(ch);
            assert_eq!(
                code, expected_code,
                "char {:?}: expected code {:?}, got {:?}",
                ch, expected_code, code
            );
            assert_eq!(
                vk, expected_vk,
                "char {:?}: expected VK {}, got {} (ASCII would be {})",
                ch, expected_vk, vk, ch as i32
            );
            // key should be the character itself (except control chars).
            if !ch.is_control() {
                assert_eq!(key, ch.to_string(), "char {:?}: key mismatch", ch);
            }
        }
    }

    /// Regression test: period must NEVER map to VK 46 (VK_DELETE).
    #[test]
    fn test_period_is_not_vk_delete() {
        let (_, _, vk) = char_to_key_info('.');
        assert_ne!(
            vk, 46,
            "Period must not use VK code 46 (VK_DELETE); expected 190 (VK_OEM_PERIOD)"
        );
        assert_eq!(vk, 190);
    }

    /// Characters outside the US keyboard layout should return (key, "", 0)
    /// so that `type_text` falls back to `Input.insertText`.
    #[test]
    fn test_unmapped_chars_return_zero_keycode() {
        for ch in ['@', '#', '$', '%', '^', '&', '*', '(', ')', '€', '£', '你'] {
            let (key, code, vk) = char_to_key_info(ch);
            assert_eq!(
                code, "",
                "char {:?}: unmapped char should have empty code, got {:?}",
                ch, code
            );
            assert_eq!(
                vk, 0,
                "char {:?}: unmapped char should have VK 0, got {}",
                ch, vk
            );
            assert_eq!(key, ch.to_string());
        }
    }

    #[test]
    fn test_key_text_returns_correct_text_for_special_keys() {
        assert_eq!(key_text("Enter"), Some("\r".to_string()));
        assert_eq!(key_text("Tab"), Some("\t".to_string()));
        assert_eq!(key_text(" "), Some(" ".to_string()));
        // Single printable characters carry themselves.
        assert_eq!(key_text("a"), Some("a".to_string()));
        assert_eq!(key_text("Z"), Some("Z".to_string()));
        // Non-printable named keys return None.
        assert_eq!(key_text("Escape"), None);
        assert_eq!(key_text("ArrowUp"), None);
        assert_eq!(key_text("Backspace"), None);
        assert_eq!(key_text("Delete"), None);
    }
}
